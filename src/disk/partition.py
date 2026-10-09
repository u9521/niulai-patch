"""The MBR partition table, and each partition as a usable device.

Why this layer exists
---------------------
The boot partition is 14,660,608 bytes and holds 14,503,860 bytes of files,
leaving 79,872 free.  Replacing the kernel with anything larger than the
shipped 12,362,752-byte image therefore needs the partition to grow, which
means editing the MBR.

That is not a small edit.  The layout is::

    sda1        2,048 ..    18,175
    sda2       18,176 ..    34,303
    sda3       34,304 ..    62,937     <- 14 MiB ext2, the boot partition
    extended   62,938 ..              <- container, holds the logical volumes
      sda5     62,939 ..    79,066
      sda6     79,068 .. 3,501,939    <- 1.6 GiB ext4, the Android system
    (unpartitioned) 3,501,940 .. 4,811,269   <- 670 MB, but NOT adjacent to sda3

There is no free space on either side of ``sda3``: ``sda2`` ends one sector
before it and the extended partition begins one sector after.  The 670 MB of
unpartitioned space at the end of the disk cannot be used, because a partition
must be contiguous.  So growing ``sda3`` **necessarily** moves the extended
partition start, and therefore ``sda5`` and ``sda6`` -- 1.7 GB of data.

The one thing that makes this tractable
---------------------------------------
A move is not a rewrite.  ext4 block numbers are relative to the start of the
partition and the superblock records no absolute sector, so shifting a
filesystem's start sector by *N* requires changing **nothing inside it**: the
bytes move wholesale.  The logical volumes also keep the same *relative* offsets
inside their EBRs, so only two things actually change:

* the MBR's extended-partition entry (``start_lba`` and ``size``);
* the physical location of each EBR, which moves with its partition.

Why partitions are devices, not records
---------------------------------------
A partition *is* a window onto the disk, so it is one here.  Before, three
separate modules each hand-rolled the same eight-line adapter that added the
partition's byte offset to every call, and none of them checked that the result
stayed inside the partition -- so a wrong offset wrote into whatever partition
came next, silently.  :class:`Partition` does the arithmetic once and refuses
anything outside its own extent.

Partitions are also looked up by *content* rather than by sector.  The MBR
labels the boot partition and the Android system partition with the same type
byte, and the sector numbers stop being true the moment a growth plan moves
them, so :meth:`PartitionTable.boot` and :meth:`PartitionTable.system` read the
disk instead of trusting a constant.

Why the MBR's CHS fields are not updated
----------------------------------------
Every entry in this table has saturated CHS (``FE FF FF``), which is what a
modern tool writes when the geometry exceeds what CHS can express.  This image
reports ``C/H/S = 0/0/0``.  Writing real CHS values would be *worse* than
leaving them: GRUB and the Linux kernel both use LBA when the values are
saturated, and inventing a geometry risks disagreement between them. So the
saturated bytes are preserved verbatim.

Safety model
------------
:meth:`PartitionTable.plan_growth` computes a full plan and validates it
*before* anything is written, and :meth:`PartitionTable.apply_plan` refuses a
plan that fails any check.  The move itself is done back-to-front so that no
source region is overwritten before it is read, and the partition table is
written last.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from itertools import pairwise

from .device import DeviceError, SectorDevice, WriteStats
from .filetype import FileSystemKind, detect_partition

#: The MBR format is defined in 512-byte units regardless of what a container
#: reports as its sector size, so the table's own arithmetic uses this literal.
MBR_SECTOR_SIZE = 512
MBR_SIGNATURE_OFFSET = 510
PARTITION_TABLE_OFFSET = 446
PARTITION_ENTRY_SIZE = 16
EXTENDED_TYPES = (0x05, 0x0F, 0x85)

#: Saturated CHS, as written by every modern tool for a large disk.
SATURATED_CHS = (0xFE, 0xFF, 0xFF)


class PartitionError(DeviceError):
    """Raised when a partition table cannot be parsed or safely edited.

    A subclass of :class:`DeviceError` so that "this disk could not be used"
    is one thing to catch, whether the problem was the container, the table, or
    a partition's bounds.
    """


class Partition(SectorDevice):
    """One entry in the MBR primary table or an EBR, as a usable device.

    A partition *is* a window onto the disk, so it is presented as a device
    rather than as a record that callers have to turn into one.  Before this,
    three modules each hand-rolled the same eight-line "add the base offset to
    every call" adapter, and none of them checked that the result stayed inside
    the partition -- so a wrong base wrote into the next partition along.

    Reads and writes are in *partition-relative* sectors, so the arithmetic
    that has to be right lives here and nowhere else.
    """

    def __init__(
        self,
        *,
        number: int,
        boot_flag: int,
        type: int,
        start_lba: int,
        sectors: int,
        chs_start: bytes = b"",
        chs_end: bytes = b"",
        ebr_lba: int | None = None,
        parent: SectorDevice | None = None,
        table: PartitionTable | None = None,
    ) -> None:
        self.number = number
        self.boot_flag = boot_flag
        self.type = type
        self.start_lba = start_lba
        self.sectors = sectors
        self.chs_start = chs_start
        self.chs_end = chs_end
        #: EBR sector this entry was read from, or None for a primary entry.
        self.ebr_lba = ebr_lba
        #: The disk this partition lives on.  Excluded from equality and repr:
        #: it is context, not identity.
        self.parent = parent
        self.table = table

    # -- identity ----------------------------------------------------------
    @property
    def index(self) -> int:
        """The Linux partition number (sda3 -> 3).  Alias for :attr:`number`."""
        return self.number

    @property
    def name(self) -> str:
        return f"sda{self.number}"

    def __eq__(self, other) -> bool:
        if not isinstance(other, Partition):
            return NotImplemented
        return (
            self.number,
            self.type,
            self.start_lba,
            self.sectors,
            self.ebr_lba,
        ) == (
            other.number,
            other.type,
            other.start_lba,
            other.sectors,
            other.ebr_lba,
        )

    def __hash__(self) -> int:
        return hash((self.number, self.type, self.start_lba, self.sectors))

    def __repr__(self) -> str:
        return (
            f"<Partition sda{self.number} type {self.type:#04x} "
            f"lba {self.start_lba:,}+{self.sectors:,}>"
        )

    # -- geometry ----------------------------------------------------------
    @property
    def end_lba(self) -> int:
        return self.start_lba + self.sectors - 1

    @property
    def is_extended(self) -> bool:
        return self.type in EXTENDED_TYPES

    @property
    def size_bytes(self) -> int:
        return self.sectors * MBR_SECTOR_SIZE

    # -- device interface --------------------------------------------------
    # Intentional override: the base holds `sector_size` as a plain
    # attribute so a test double can assign one, while this wraps another
    # device and must delegate rather than store its own copy.
    @property
    def sector_size(self) -> int:  # type: ignore[reportIncompatibleVariableOverride]
        # The partition inherits the disk's sector size; the MBR's own unit is
        # 512 bytes regardless, which is why start_lba/sectors stay in 512-byte
        # units even if a container ever reports something else.
        return self.parent.sector_size if self.parent is not None else 512

    @property
    def size(self) -> int:
        return self.sectors * self.sector_size

    @property
    def sector_count(self) -> int:
        return self.sectors

    def describe(self) -> str:
        return f"partition sda{self.number} at LBA {self.start_lba:,} ({self.size_bytes:,} bytes)"

    def _absolute(self, lba: int) -> int:
        """Disk-relative sector for a partition-relative one."""
        return self.start_lba + lba

    def read_sectors(self, lba: int, count: int) -> bytes:
        self.check_sectors(lba, count, what=f"read from sda{self.number}")
        if self.parent is None:
            raise PartitionError(
                f"sda{self.number} has no disk attached; it was built without "
                f"one and cannot be read"
            )
        return self.parent.read_sectors(self._absolute(lba), count)

    def write_sectors(self, lba: int, count: int, data: bytes) -> None:
        self.check_sectors(lba, count, what=f"write to sda{self.number}")
        if self.parent is None:
            raise PartitionError(
                f"sda{self.number} has no disk attached; it was built without "
                f"one and cannot be written"
            )
        self.parent.write_sectors(self._absolute(lba), count, data)

    def write_blocks(self, writes) -> WriteStats:
        """Rebase batched writes onto the disk and forward them in one call.

        This must not degrade into a per-range ``write_sectors`` loop: on the
        9p mount this runs against a write costs ~17 ms whatever its size, so
        passing ranges through one at a time is the 228-second path.  The whole
        point of the batching interface is that it survives the layer change.
        """
        if self.parent is None:
            raise PartitionError(f"sda{self.number} has no disk attached")
        rebased = []
        for offset, payload in writes:
            if not payload:
                continue
            self.check_range(offset, len(payload), what=f"write to sda{self.number}")
            rebased.append((self.start_lba * self.sector_size + offset, payload))
        return self.parent.write_blocks(rebased)

    def filesystem_type(self) -> str:
        """Name what this partition holds, by reading it."""
        return detect_partition(self)

    # -- serialisation -----------------------------------------------------
    def serialize(self, *, start_lba: int | None = None) -> bytes:
        """Encode this entry, optionally relocated to a new start sector."""
        out = bytearray(PARTITION_ENTRY_SIZE)
        out[0] = self.boot_flag
        out[1:4] = self.chs_start
        out[4] = self.type
        out[5:8] = self.chs_end
        struct.pack_into(
            "<II",
            out,
            8,
            start_lba if start_lba is not None else self.start_lba,
            self.sectors,
        )
        return bytes(out)


@dataclass
class Move:
    """One region of the disk that has to be relocated."""

    name: str
    old_start: int
    sectors: int
    new_start: int

    @property
    def delta(self) -> int:
        return self.new_start - self.old_start

    def describe(self) -> str:
        return (
            f"{self.name:6} {self.old_start:>10,} -> {self.new_start:<10,} "
            f"({self.sectors * MBR_SECTOR_SIZE:>13,} bytes, "
            f"{'+' if self.delta >= 0 else ''}{self.delta:,} sectors)"
        )


@dataclass
class GrowthPlan:
    """What growing a partition would involve. Computed, then validated."""

    grow_partition: int
    grow_by_sectors: int
    new_size_sectors: int
    moves: list[Move] = field(default_factory=list)
    #: EBR sectors that must be rewritten at new locations.
    ebr_moves: list[Move] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.errors

    @property
    def total_bytes_moved(self) -> int:
        return sum(m.sectors * MBR_SECTOR_SIZE for m in self.moves)

    def summary(self) -> str:
        lines = [
            f"grow sda{self.grow_partition} by {self.grow_by_sectors:,} sectors "
            f"({self.grow_by_sectors * MBR_SECTOR_SIZE:,} bytes)"
        ]
        for move in self.moves:
            lines.append("  move " + move.describe())
        for move in self.ebr_moves:
            lines.append("  EBR  " + move.describe())
        if self.moves:
            lines.append(
                f"  {self.total_bytes_moved:,} bytes ({self.total_bytes_moved / 1e9:.2f} GB) "
                f"must be relocated"
            )
        lines.extend("  note: " + n for n in self.notes)
        lines.extend("  ERROR: " + e for e in self.errors)
        return "\n".join(lines)


class PartitionTable:
    """The MBR partition table of a disk, with its EBR chain.

    Operates on a :class:`~disk.device.SectorDevice` -- a VDI, a raw
    image, or anything else that can hand back sectors.
    """

    def __init__(
        self,
        device: SectorDevice,
        *,
        total_sectors: int | None = None,
        cache_partitions: bool = True,
    ) -> None:
        """Parse the table on ``device``.

        ``total_sectors`` defaults to the device's own length, which is the
        right answer for a whole disk; it is still accepted explicitly so a
        test can describe a disk smaller than the file holding it.
        """
        self.dev = device
        if total_sectors is None:
            total_sectors = device.size // MBR_SECTOR_SIZE
        self.total_sectors = total_sectors
        self._cache = cache_partitions
        self._partitions: dict[int, Partition] | None = None
        mbr = self._read_mbr()
        if len(mbr) < MBR_SECTOR_SIZE:
            raise PartitionError(
                f"could not read the MBR: got {len(mbr):,} of {MBR_SECTOR_SIZE} bytes"
            )
        if mbr[MBR_SIGNATURE_OFFSET : MBR_SIGNATURE_OFFSET + 2] != b"\x55\xaa":
            raise PartitionError(
                "no MBR signature (55 AA) at offset 510; this is not an MBR-partitioned disk"
            )
        self.mbr = bytearray(mbr)
        self.primaries = self._parse_primaries()
        self.logicals, self.ebrs = self._parse_logicals()

    def _read_mbr(self) -> bytes:
        """The first 512 bytes of the disk, by whichever path it supports."""
        if isinstance(self.dev, SectorDevice):
            return self.dev.read_sectors(0, 1)
        return self.dev.read_at(0, MBR_SECTOR_SIZE)

    def _read_sector(self, lba: int) -> bytes:
        if isinstance(self.dev, SectorDevice):
            return self.dev.read_sectors(lba, 1)
        return self.dev.read_at(lba * MBR_SECTOR_SIZE, MBR_SECTOR_SIZE)

    def _write_sector(self, lba: int, data: bytes) -> None:
        if isinstance(self.dev, SectorDevice):
            self.dev.write_sectors(lba, 1, data)
        else:
            self.dev.write_at(lba * MBR_SECTOR_SIZE, data)

    def invalidate(self) -> None:
        """Forget the cached partition devices.

        Called after a table change, because the cached ``Partition`` objects
        still describe the old geometry -- a partition whose start moved but
        whose cached ``start_lba`` did not is exactly the stale-address bug this
        layer exists to prevent.
        """
        self._partitions = None

    # -- parsing -----------------------------------------------------------
    def _parse_primaries(self) -> list[Partition]:
        out: list[Partition] = []
        for i in range(4):
            base = PARTITION_TABLE_OFFSET + i * PARTITION_ENTRY_SIZE
            entry = self.mbr[base : base + PARTITION_ENTRY_SIZE]
            ptype = entry[4]
            start, sectors = struct.unpack_from("<II", entry, 8)
            if ptype == 0 or sectors == 0:
                continue
            out.append(
                Partition(
                    number=i + 1,
                    boot_flag=entry[0],
                    type=ptype,
                    start_lba=start,
                    sectors=sectors,
                    chs_start=bytes(entry[1:4]),
                    chs_end=bytes(entry[5:8]),
                    parent=self.dev,
                    table=self,
                )
            )
        return out

    def _parse_logicals(self) -> tuple[list[Partition], list[Partition]]:
        """Walk the EBR chain, returning logical partitions and EBR locations.

        The walk is bounded and validates each link, because a damaged or
        hostile chain would otherwise loop forever or read off the end of the
        disk.  Both cases are real: this image's chain, followed naively,
        reaches an EBR with no ``55 AA`` signature.

        The second return value is the list of EBR *sectors* -- one per logical
        volume, each holding that volume's entry plus a link to the next.  Every
        one of them moves when the extended partition starts later, so the plan
        needs their addresses, not just the entries inside them.
        """
        logicals: list[Partition] = []
        ebr_locations: list[Partition] = []

        extended = next((p for p in self.primaries if p.is_extended), None)
        if extended is None:
            return logicals, ebr_locations

        current = extended.start_lba
        seen: set[int] = set()
        number = 5
        while current and current not in seen:
            seen.add(current)
            if current + 1 > self.total_sectors:
                break
            sector = self._read_sector(current)
            if sector[MBR_SIGNATURE_OFFSET : MBR_SIGNATURE_OFFSET + 2] != b"\x55\xaa":
                break

            # Record this EBR's own location: it is a sector that must be
            # rewritten elsewhere when the extended region shifts.
            ebr_locations.append(
                Partition(
                    number=0,
                    boot_flag=0,
                    type=0,
                    start_lba=current,
                    sectors=1,
                    ebr_lba=current,
                    parent=self.dev,
                    table=self,
                )
            )

            link = 0
            for slot in (0, 1):
                base = PARTITION_TABLE_OFFSET + slot * PARTITION_ENTRY_SIZE
                entry = sector[base : base + PARTITION_ENTRY_SIZE]
                ptype = entry[4]
                start, sectors = struct.unpack_from("<II", entry, 8)
                if ptype == 0 or sectors == 0:
                    continue
                if slot == 0:
                    logicals.append(
                        Partition(
                            number=number,
                            boot_flag=entry[0],
                            type=ptype,
                            start_lba=current + start,
                            sectors=sectors,
                            chs_start=bytes(entry[1:4]),
                            chs_end=bytes(entry[5:8]),
                            ebr_lba=current,
                            parent=self.dev,
                            table=self,
                        )
                    )
                    number += 1
                else:
                    # A link record: relative offset to the next EBR.
                    link = start
            if not link:
                break
            current = current + link
        return logicals, ebr_locations

    def all_partitions(self) -> list[Partition]:
        return sorted(self.primaries + self.logicals, key=lambda p: p.start_lba)

    def find(self, number: int) -> Partition:
        """The partition with the given Linux number (sda3 -> 3)."""
        for part in self.primaries + self.logicals:
            if part.number == number:
                return part
        raise PartitionError(f"no partition sda{number} in this table")

    def get(self, number: int) -> Partition | None:
        """Like :meth:`find`, but ``None`` instead of raising."""
        try:
            return self.find(number)
        except PartitionError:
            return None

    def by_number(self) -> dict[int, Partition]:
        """Every partition keyed by its Linux number."""
        return {p.number: p for p in self.primaries + self.logicals}

    # -- discovery ---------------------------------------------------------
    def ext_partitions(self) -> list[Partition]:
        """Every partition holding an ext2/ext3/ext4 filesystem, in disk order."""
        return [
            p
            for p in self.all_partitions()
            if not p.is_extended and p.filesystem_type() in FileSystemKind.EXT_ANY
        ]

    def system(self) -> Partition:
        """The partition holding the Android system image.

        Picked as the largest ext4 partition.  This is discovery, not
        validation: the caller still checks the installed launcher's SHA-256
        before writing anything, which is the check that actually protects the
        image.  A wrong answer here therefore produces a clean refusal rather
        than a wrong write.

        The reason it cannot simply be "the ext4 one" is that a future image
        may carry more than one, and "the largest" is the property that makes
        the Android system image the system image.
        """
        candidates = [
            p for p in self.ext_partitions() if p.filesystem_type() == FileSystemKind.EXT4
        ]
        if not candidates:
            raise PartitionError(
                "no ext4 partition found; the Android system image is not on "
                "this disk, or the table has been changed"
            )
        return max(candidates, key=lambda p: p.size)

    def boot(self, *, marker: str = "/kernel") -> Partition:
        """The partition GRUB boots from.

        Identified by *contents*, not by type or by a fixed sector: the MBR
        labels MuMu's 14 MiB boot partition and its 1.6 GiB system partition
        with the same type byte, so the type cannot distinguish them.  The
        partition that holds ``/kernel`` is the one ``(hd0,2)/kernel`` refers
        to, so that is what is looked for.

        Ambiguity is reported rather than resolved by picking the first hit: if
        two partitions both look like the boot partition, something about the
        image is not what this code expects and a guess would be the wrong kind
        of helpful.
        """
        from . import extfs

        found: list[Partition] = []
        for part in self.ext_partitions():
            try:
                fs = extfs.Ext2(part)
            except extfs.ExtError:
                continue
            try:
                fs.lookup(marker)
            except extfs.ExtError:
                continue
            found.append(part)

        if not found:
            raise PartitionError(
                f"no partition holds {marker}; none of the "
                f"{len(self.ext_partitions())} ext partition(s) on this disk "
                f"look like the boot filesystem"
            )
        if len(found) > 1:
            names = ", ".join(p.name for p in found)
            raise PartitionError(
                f"{len(found)} partitions hold {marker} ({names}); refusing to "
                f"guess which one GRUB boots from"
            )
        return found[0]

    # -- device plumbing for the growth path -------------------------------
    def _read_sectors_any(self, lba: int, count: int) -> bytes:
        if isinstance(self.dev, SectorDevice):
            return self.dev.read_sectors(lba, count)
        return self.dev.read_at(lba * MBR_SECTOR_SIZE, count * MBR_SECTOR_SIZE)

    def _write_sectors_any(self, lba: int, count: int, data: bytes) -> None:
        if isinstance(self.dev, SectorDevice):
            self.dev.write_sectors(lba, count, data)
        else:
            self.dev.write_at(lba * MBR_SECTOR_SIZE, data)

    def tail_free_sectors(self) -> int:
        """Unpartitioned sectors after the highest *real* partition.

        The extended container is excluded deliberately.  In this image it
        claims to run to sector 4,294,967,294 -- past the end of a disk that has
        only 4,811,270 -- because that is what a tool writes when it does not
        want to commit to a size.  Counting it would report zero free space and
        hide the 670 MB tail that actually exists.
        """
        real = [p for p in self.all_partitions() if not p.is_extended]
        highest = max((p.end_lba for p in real), default=0)
        return max(0, self.total_sectors - (highest + 1))

    def next_partition_start(self, index: int) -> int:
        """The sector immediately after ``index``, whatever occupies it."""
        part = self.find(index)
        following = [p for p in self.all_partitions() if p.start_lba > part.start_lba]
        if not following:
            return self.total_sectors
        return min(p.start_lba for p in following)

    # -- planning ----------------------------------------------------------
    def plan_growth(self, index: int, extra_sectors: int) -> GrowthPlan:
        """Work out how to make partition ``index`` larger. Read-only.

        Growing is only possible by pushing everything after the partition
        later, so the plan is a list of moves.  Nothing here writes.
        """
        part = self.find(index)
        if extra_sectors <= 0:
            raise PartitionError("extra_sectors must be positive")
        if part.is_extended:
            raise PartitionError(
                "refusing to grow the extended container itself; grow a logical volume instead"
            )

        plan = GrowthPlan(
            grow_partition=index,
            grow_by_sectors=extra_sectors,
            new_size_sectors=part.sectors + extra_sectors,
        )

        boundary = part.end_lba + 1
        movable = [
            p for p in self.all_partitions() if p.start_lba >= boundary and not p.is_extended
        ]
        extended = next((p for p in self.primaries if p.is_extended), None)

        # Anything at or after the boundary has to move.
        for other in movable:
            plan.moves.append(
                Move(
                    name=f"sda{other.index}",
                    old_start=other.start_lba,
                    sectors=other.sectors,
                    new_start=other.start_lba + extra_sectors,
                )
            )
        # The EBR for each logical volume moves with it.
        for ebr in self.ebrs:
            plan.ebr_moves.append(
                Move(
                    name=f"EBR@{ebr.ebr_lba:,}",
                    old_start=ebr.ebr_lba or 0,
                    sectors=1,
                    new_start=(ebr.ebr_lba or 0) + extra_sectors,
                )
            )
        # Sorting back-to-front is what makes the move safe; record the order.
        plan.moves.sort(key=lambda m: m.old_start, reverse=True)

        if extended is not None:
            plan.notes.append(
                f"extended partition sda{extended.index} grows by "
                f"{extra_sectors:,} sectors and its start moves to "
                f"{extended.start_lba + extra_sectors:,}"
            )

        self._validate_growth(part, extra_sectors, plan)
        return plan

    def _validate_growth(self, part: Partition, extra_sectors: int, plan: GrowthPlan) -> None:
        """Populate ``plan.errors`` with anything that makes it unsafe."""
        # Every moved region must stay inside the disk.
        highest = 0
        for move in plan.moves:
            highest = max(highest, move.new_start + move.sectors - 1)
        if highest >= self.total_sectors:
            plan.errors.append(
                f"the move would end at sector {highest:,} but the disk ends at "
                f"{self.total_sectors - 1:,}; the image is too small "
                f"({(highest - self.total_sectors + 1) * MBR_SECTOR_SIZE:,} bytes short). "
                f"The VDI container must grow first."
            )

        # A grown partition must not overlap whatever follows it -- but two
        # details matter.  Partitions *before* the grown one are irrelevant
        # (they are lower on the disk and cannot collide), and the comparison
        # must use the *post-move* positions, because everything after the
        # grown partition is pushed later by exactly the amount it grew.
        new_end = part.end_lba + extra_sectors
        relocated = {m.name: m.new_start for m in plan.moves}
        for other in self.all_partitions():
            if other.index == part.index or other.is_extended:
                continue
            if other.start_lba < part.start_lba:
                continue  # sits earlier on the disk; cannot be reached
            new_start = relocated.get(f"sda{other.index}", other.start_lba)
            if new_start <= new_end:
                plan.errors.append(
                    f"the grown sda{part.index} would reach sector {new_end:,}, "
                    f"overlapping sda{other.index} at {new_start:,}"
                )

        # Moves must not collide with each other.
        spans = sorted((m.new_start, m.new_start + m.sectors, m.name) for m in plan.moves)
        for (_, a_end, a_name), (b_start, _, b_name) in pairwise(spans):
            if b_start < a_end:
                plan.errors.append(f"relocated {a_name} and {b_name} would overlap")

        # The boot partition's filesystem must tolerate a larger partition.
        if part.index == 3:
            plan.notes.append(
                "sda3 is ext2 (rev 0); after the table change the filesystem "
                "must be grown to use the new space (`boot grow` does this)"
            )
        plan.notes.append(
            "the kernel and initrd are read by GRUB as (hd0,2); that refers to "
            "the third partition entry, so the table ORDER must not change"
        )

    # -- applying ----------------------------------------------------------
    def build_mbr_and_ebrs(self, plan: GrowthPlan) -> tuple[bytes, dict[int, bytes]]:
        """Produce the new MBR and EBR sectors for a validated plan.

        Splitting this from the data move makes the plan testable without
        touching 1.7 GB, and lets the caller write the tables last.
        """
        if not plan.ok:
            raise PartitionError(
                "refusing to build a table for an invalid plan:\n" + "\n".join(plan.errors)
            )

        delta = plan.grow_by_sectors
        mbr = bytearray(self.mbr)

        # Grow the target partition in place (its start does not move).
        grown = self.find(plan.grow_partition)
        base = PARTITION_TABLE_OFFSET + (grown.index - 1) * PARTITION_ENTRY_SIZE
        mbr[base : base + PARTITION_ENTRY_SIZE] = grown.serialize()
        struct.pack_into("<I", mbr, base + 12, plan.new_size_sectors)

        # The extended container grows and its start shifts.
        extended = next((p for p in self.primaries if p.is_extended), None)
        if extended is not None:
            ext_base = PARTITION_TABLE_OFFSET + (extended.index - 1) * PARTITION_ENTRY_SIZE
            new_ext_start = extended.start_lba + delta
            new_ext_sectors = extended.sectors - delta
            if new_ext_sectors <= 0:
                raise PartitionError("the extended partition would have no space left")
            struct.pack_into("<II", mbr, ext_base + 8, new_ext_start, new_ext_sectors)

        ebrs: dict[int, bytes] = {}
        for ebr in self.ebrs:
            old = ebr.ebr_lba or 0
            new = old + delta
            if new >= self.total_sectors:
                raise PartitionError(f"EBR would move to sector {new:,}, past the end of the disk")
            sector = bytearray(self._read_sector(old))
            # The link entry's relative offset is unchanged; only the EBR's
            # physical location moves, so the record is copied verbatim.
            ebrs[new] = bytes(sector)

        return bytes(mbr), ebrs

    def apply_plan(self, plan: GrowthPlan, *, progress=None) -> None:
        """Carry out a validated growth plan.

        Ordering is what makes this safe:

        1. validate (again) and build the new tables;
        2. move the data regions **back to front**, so a source is never
           overwritten before it has been read;
        3. write the new EBRs;
        4. write the MBR **last**, because until it is written the disk still
           describes the old layout and a failure leaves the old table valid.
        """
        if not plan.ok:
            raise PartitionError("refusing to apply an invalid plan:\n" + "\n".join(plan.errors))
        mbr, ebrs = self.build_mbr_and_ebrs(plan)

        chunk_sectors = max(1, (1 << 20) // MBR_SECTOR_SIZE)

        for move in plan.moves:
            if move.delta == 0:
                continue
            total = move.sectors
            done = 0
            # Back to front within a region as well, for the same reason.
            remaining = total
            while remaining > 0:
                take = min(chunk_sectors, remaining)
                src = move.old_start + remaining - take
                dst = move.new_start + remaining - take
                data = self._read_sectors_any(src, take)
                if len(data) != take * MBR_SECTOR_SIZE:
                    raise PartitionError(f"short read while moving {move.name} at sector {src:,}")
                self._write_sectors_any(dst, take, data)
                remaining -= take
                done += take
                if progress:
                    progress(move.name, done, total)

        for sector_lba, data in ebrs.items():
            self._write_sector(sector_lba, data)

        # Last: the MBR. Until this lands, the on-disk table still matches the
        # un-moved layout, so an interruption leaves a consistent old disk.
        self._write_sector(0, mbr)
        # Every cached Partition describes the old geometry from here on.
        self.invalidate()

    # -- verification ------------------------------------------------------
    def verify_after_growth(self, plan: GrowthPlan) -> list[str]:
        """Re-read the table and confirm the post-conditions hold.

        Returns a list of problems; empty means the table is what was intended.
        """
        problems: list[str] = []
        fresh = PartitionTable(self.dev, total_sectors=self.total_sectors)
        try:
            grown = fresh.find(plan.grow_partition)
        except PartitionError as exc:
            return [f"the grown partition is missing afterwards: {exc}"]
        if grown.sectors != plan.new_size_sectors:
            problems.append(
                f"sda{plan.grow_partition} is {grown.sectors:,} sectors, "
                f"expected {plan.new_size_sectors:,}"
            )
        for move in plan.moves:
            name = move.name
            try:
                index = int(name.removeprefix("sda"))
                part = fresh.find(index)
            except PartitionError, ValueError:
                problems.append(f"{name} is missing from the new table")
                continue
            if part.start_lba != move.new_start:
                problems.append(f"{name} starts at {part.start_lba:,}, expected {move.new_start:,}")
            if part.sectors != move.sectors:
                problems.append(f"{name} is {part.sectors:,} sectors, expected {move.sectors:,}")
        # Signature must still be intact.
        mbr = self._read_mbr()
        if mbr[MBR_SIGNATURE_OFFSET : MBR_SIGNATURE_OFFSET + 2] != b"\x55\xaa":
            problems.append("the MBR signature was lost")
        return problems
