"""Read and write VirtualBox VDI images without VirtualBox.

Why this exists
---------------
MuMu's guest disk lives in ``nx_device/15.0/vms/<product>/system.vdi``: an MBR
partition table followed by ext2/ext4 filesystems holding the Android system
image and the kernel.  Replacing the launcher APK or the kernel means editing
inside those filesystems, and the image is shared by every instance of the
emulator (the ``.nemu`` config declares it ``Readonly``), so the edit has to be
made offline and correctly.

``vbox-img.exe`` ships with MuMu and can convert VDI to RAW and back, which
would let us use any raw-image tool.  That round trip is *lossy in an important
way*: it rewrites the whole 1.8 GB and reassigns block UUIDs every time.  Doing
the edit in place is both far faster and preserves the identity of the image.

Header layout
-------------
This is the part that has to be exactly right, so it is derived from
VirtualBox's own structs rather than from memory.

In ``src/VBox/Storage/VDICore.h`` both structs are declared ``#pragma pack(1)``,
so the layout is **tightly packed, not naturally aligned**::

    VDIPREHEADER     char szFileInfo[64]; u32 u32Signature; u32 u32Version;
                     -> 72 bytes
    VDIHEADER1PLUS   u32 cbHeader; u32 u32Type; u32 fFlags;
                     char szComment[256]; u32 offBlocks; u32 offData;
                     ... LegacyGeometry ... u64 cbDisk; u32 cbBlock; ...
                     -> 400 bytes, ending at file offset 472

Because it is packed, the 64-bit ``cbDisk`` sits at the *unaligned* offset
0x170 and everything after it follows immediately.  Assuming natural alignment
would push ``cbDisk`` to 0x178 and shift every following field by eight bytes.
An earlier version of this file had ``u32Type``/``fFlags``/``szComment`` four
bytes early for the same reason.

======  ==========================================  ====================
Offset  Field                                       Value in MuMu's image
======  ==========================================  ====================
0x000   ``char szFileInfo[64]``                     ``<<< Oracle VM ...``
0x040   ``u32 u32Signature``                        0xbeda107f
0x044   ``u32 u32Version``                          0x00010001
0x048   ``u32 cbHeader`` (= sizeof VDIHEADER1PLUS)  400
0x04c   ``u32 u32Type``                             1 (dynamic)
0x050   ``u32 fFlags``                              0
0x054   ``char szComment[256]``                     "Converted image ..."
0x154   ``u32 offBlocks`` (BAT byte offset)         0x100000
0x158   ``u32 offData`` (first block's offset)      0x200000
0x168   ``u32 cbSector``                            512
0x170   ``u64 cbDisk`` (virtual size)               2463370240
0x178   ``u32 cbBlock``                             0x100000
0x17c   ``u32 cbBlockExtra``                        0
0x180   ``u32 cBlocks``                             2350
0x184   ``u32 cBlocksAllocated``                    1789
0x188   ``uuid uCreation``
0x198   ``uuid uModification``
======  ==========================================  ====================

Two traps in that table, both of which this file fell into before the offsets
were measured instead of assumed:

* ``u32Signature`` is a **magic constant**, not a checksum.
  ``vdiValidatePreHeader`` compares it for exact equality against
  ``VDI_IMAGE_SIGNATURE``; accepting a computed CRC-32 of the header text would
  let through a header VirtualBox rejects, which is the opposite of what a
  validator is for.
* ``u32Version`` encodes ``(major << 16) | minor`` and
  ``VDI_GET_VERSION_MAJOR`` reads the **high 16 bits**.  Reading the high 8
  bits instead rejects ``0x00010001``, the value every real image uses.

Block addressing
----------------
Data blocks are 1 MiB (``cbBlock``).  Logical block ``i`` lives at

    file_offset = offData + BAT[i] * cbBlock

``BAT[i] == 0xFFFFFFFF`` means "never written" and ``0xFFFFFFFE`` means "zero
block"; both read back as zeros.  VirtualBox's ``IS_VDI_IMAGE_BLOCK_ALLOCATED``
draws the line at ``~1``, so both count as unallocated -- treating 0xFFFFFFFE as
ordinary storage would expose uninitialised data.  ``BAT[0]`` maps to file
block 0 and holds the MBR (verified: the ``55 AA`` signature at offset 510).

Reading
-------
Reading is cached too, and that is not an optimisation either.  The container's
unit is 1 MiB, but the ext2 layer above addresses it one *filesystem* block at a
time -- 1 KiB on the boot partition.  The 12,362,752-byte kernel is 12,073
filesystem blocks living inside only ~12 distinct 1 MiB VDI blocks, so without a
cache every one of those 12,073 calls re-reads a whole container block and the
same 12 MB comes off the file a thousand times over: **12.7 GB of I/O and 40 s
per kernel read** through the Windows mount.  Cached, it is 20 MB and 0.12 s.

Clean blocks are held as ``bytes`` and invalidated when their block is written;
a block staged for writing is served from :attr:`_dirty` rather than the file,
so a read can never be handed a pre-write version.

Writing
-------
:class:`VdiDevice` opens read-only by default.  Writes are staged in a small
dirty-page cache keyed by *logical VDI block* -- the unit the BAT actually maps
-- and reach the file when a block fills up, when the cache evicts it, or at
:meth:`VdiDevice.flush`.

Every cached buffer is seeded by reading the block it covers.  That is
correctness, not an optimisation: a filesystem block rarely starts at a VDI
block boundary, so a buffer that started as zeros would erase whatever else
shares that 1 MiB when it was written back.  On the real image exactly that
destroyed an unrelated inode's extent tree.

The BAT is written *after* the data blocks it describes, so an interruption
cannot leave a block reachable that was never written.
"""

from __future__ import annotations

import contextlib
import os
import struct
import uuid as uuid_mod
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from .device import DeviceError, SectorDevice, WriteStats

VDI_SIGNATURE = b"<<< Oracle VM VirtualBox Disk Image >>>"
HEADER_SIZE = 512
#: ``sizeof(VDIHEADER1PLUS)``; the header struct ends at file offset 472 inside
#: the 512-byte header area.  ``cbHeader`` must be at least this.
HEADER_STRUCT_SIZE = 400
BLOCK_FREE = 0xFFFFFFFF
#: VirtualBox's other "not allocated" marker: reads back as zeroes.  Treating
#: this as an ordinary slot would expose uninitialised data.
BLOCK_ZERO = 0xFFFFFFFE


def is_allocated(mapping: int) -> bool:
    """Whether a BAT entry names real storage.

    VirtualBox's ``IS_VDI_IMAGE_BLOCK_ALLOCATED`` tests ``bp < ~1``, so both
    0xFFFFFFFF (free) and 0xFFFFFFFE (zero block) count as unallocated.
    """
    return mapping < BLOCK_ZERO


# Field offsets, named so the numbers appear exactly once.
#
# These are computed from VirtualBox's own structs (VDICore.h), which are
# declared `#pragma pack(1)`, so the layout is tightly packed, NOT aligned:
#
#     VDIPREHEADER   szFileInfo[64] + u32Signature + u32Version        = 72
#     VDIHEADER1PLUS cbHeader, u32Type, fFlags, szComment[256], ...
#
# The 64-bit cbDisk therefore sits at an unaligned offset (0x170).  An earlier
# version of this file put u32Type/fFlags/szComment four bytes early, which
# shifted the comment by one field; those were unused, so nothing broke, but
# they are corrected here and pinned by tests.
OFF_MAGIC = 0x40  # u32Signature: the constant 0xbeda107f, not a checksum
OFF_VERSION = 0x44  # u32Version
OFF_CB_HEADER = 0x48  # u32 cbHeader, sizeof(VDIHEADER1PLUS) = 400
OFF_TYPE = 0x4C  # u32 u32Type (1 normal, 2 fixed, 4 diff)
OFF_FLAGS = 0x50  # u32 fFlags
OFF_COMMENT = 0x54  # char[256]
OFF_BLOCKS = 0x154  # u32, byte offset of the block allocation table
OFF_DATA = 0x158  # u32, byte offset where block 0's data begins
OFF_CB_SECTOR = 0x168  # u32, sector size inside LegacyGeometry
OFF_DISK_SIZE = 0x170  # u64 cbDisk, virtual size in bytes
OFF_CB_BLOCK = 0x178  # u32, block size in bytes (1 MiB here)
OFF_CB_BLOCK_EXTRA = 0x17C  # u32, per-block service data (0 here)
OFF_CBLOCKS = 0x180  # u32, total logical blocks
OFF_CBLOCKS_ALLOC = 0x184  # u32, blocks actually allocated
OFF_CREATION_UUID = 0x188
OFF_MODIFICATION_UUID = 0x198
OFF_LINKAGE_UUID = 0x1A8
OFF_PARENT_MODIFY_UUID = 0x1B8

# VirtualBox's VDI type codes.
TYPE_DYNAMIC = 0x00000001
TYPE_STATIC = 0x00000002
TYPE_UNDO = 0x00000003
TYPE_DIFF = 0x00000004

#: What VirtualBox writes in ``u32Signature``, and the only value it accepts.
#: ``vdiValidatePreHeader`` compares for exact equality, so this is a magic
#: number rather than a checksum over the header text.
VDI_IMAGE_SIGNATURE = 0xBEDA107F

#: How many 1 MiB blocks may sit dirty in memory.  A 43 MiB APK touches about
#: 43 of them, so this holds a whole file's write without evicting; the cap
#: exists so a pathological access pattern cannot grow the cache without limit.
DEFAULT_CACHE_BLOCKS = 64


class VdiError(DeviceError):
    """Raised when an image is not a VDI we understand, or cannot be edited.

    A subclass of :class:`DeviceError` so a caller that only cares that "this
    device could not be used" can catch one thing.
    """


@dataclass
class VdiHeader:
    """The parsed 512-byte VDI header."""

    version: int
    vdi_type: int
    flags: int
    comment: str
    disk_size: int
    off_blocks: int
    off_data: int
    cb_block: int
    c_blocks: int
    c_blocks_allocated: int
    sector_size: int
    creation_uuid: bytes
    modification_uuid: bytes
    raw: bytes

    @classmethod
    def parse(cls, raw: bytes) -> VdiHeader:
        if len(raw) < HEADER_SIZE:
            raise VdiError(f"header is only {len(raw)} bytes; a VDI header is {HEADER_SIZE}")
        # The signature field is 64 bytes and NUL-padded; the text itself is
        # followed by a newline, so compare on the prefix.
        if not raw.startswith(VDI_SIGNATURE):
            found = raw[:36]
            raise VdiError(
                f"not a VDI image: expected signature {VDI_SIGNATURE!r} at offset 0, "
                f"found {found!r}"
            )

        # The signature is checked exactly as VirtualBox checks it: the
        # u32Signature field must equal VDI_IMAGE_SIGNATURE.  This is a magic
        # constant, not a checksum over the text (an earlier version of this
        # parser treated it as a CRC and accepted a computed value too, which
        # would have let a header VirtualBox rejects pass silently).
        stored_signature = struct.unpack_from("<I", raw, OFF_MAGIC)[0]
        if stored_signature != VDI_IMAGE_SIGNATURE:
            raise VdiError(
                f"not a VDI image: the signature field at {OFF_MAGIC:#x} is "
                f"{stored_signature:#010x}, expected {VDI_IMAGE_SIGNATURE:#010x}. "
                f"VirtualBox compares this for equality and so does this parser; "
                f"refusing to touch the file."
            )

        version = struct.unpack_from("<I", raw, OFF_VERSION)[0]
        # VirtualBox encodes this as (major << 16) | minor and accepts any
        # minor of major 1 -- VDI_GET_VERSION_MAJOR takes the high *16* bits.
        # Reading it as the high 8 bits rejects 0x00010001, the value every
        # real image uses, so the width here is not cosmetic.
        major = version >> 16
        if major != 1 and version != 0x00000002:
            raise VdiError(
                f"unsupported VDI version {version:#010x} at {OFF_VERSION:#x}; "
                f"VirtualBox accepts major version 1 or the legacy 2. A wrong "
                f"offset here would corrupt the image, so it refuses to continue."
            )

        cb_header = struct.unpack_from("<I", raw, OFF_CB_HEADER)[0]
        if major == 1 and cb_header < HEADER_STRUCT_SIZE:
            raise VdiError(
                f"cbHeader is {cb_header:,} at {OFF_CB_HEADER:#x}, but a "
                f"VDIHEADER1PLUS is {HEADER_STRUCT_SIZE} bytes. VirtualBox "
                f"rejects this header; so does this parser."
            )

        comment = raw[OFF_COMMENT : OFF_COMMENT + 256].rstrip(b"\x00")
        try:
            comment_text = comment.decode("utf-8")
        except UnicodeDecodeError:
            comment_text = comment.decode("latin-1")

        disk_size = struct.unpack_from("<Q", raw, OFF_DISK_SIZE)[0]
        off_blocks = struct.unpack_from("<I", raw, OFF_BLOCKS)[0]
        off_data = struct.unpack_from("<I", raw, OFF_DATA)[0]
        cb_block = struct.unpack_from("<I", raw, OFF_CB_BLOCK)[0]
        c_blocks = struct.unpack_from("<I", raw, OFF_CBLOCKS)[0]
        c_alloc = struct.unpack_from("<I", raw, OFF_CBLOCKS_ALLOC)[0]

        if cb_block == 0:
            raise VdiError(f"cbBlock is zero at {OFF_CB_BLOCK:#x}; header is not a VDI")
        if off_blocks % 512 != 0 or off_data % 512 != 0:
            raise VdiError(
                f"BAT offset {off_blocks:#x} / data offset {off_data:#x} are not "
                f"sector-aligned; refusing to trust this header"
            )
        if off_blocks != 0 and off_data != 0 and off_blocks >= off_data:
            # The BAT must precede the data area; if not, the offsets are being
            # read from the wrong place (exactly the bug the table guards).
            raise VdiError(
                f"offBlocks {off_blocks:#x} >= offData {off_data:#x}; these "
                f"cannot both be right for this format"
            )
        if c_blocks == 0:
            raise VdiError("cBlocks is zero; refusing to edit an empty image")
        if c_alloc > c_blocks:
            raise VdiError(f"cBlocksAllocated {c_alloc} exceeds cBlocks {c_blocks}")

        return cls(
            version=version,
            vdi_type=struct.unpack_from("<I", raw, OFF_TYPE)[0],
            flags=struct.unpack_from("<I", raw, OFF_FLAGS)[0],
            comment=comment_text,
            disk_size=disk_size,
            off_blocks=off_blocks,
            off_data=off_data,
            cb_block=cb_block,
            c_blocks=c_blocks,
            c_blocks_allocated=c_alloc,
            sector_size=struct.unpack_from("<I", raw, OFF_CB_SECTOR)[0],
            creation_uuid=raw[OFF_CREATION_UUID : OFF_CREATION_UUID + 16],
            modification_uuid=raw[OFF_MODIFICATION_UUID : OFF_MODIFICATION_UUID + 16],
            raw=raw,
        )

    @property
    def magic_ok(self) -> bool:
        """Whether the signature field holds VirtualBox's magic constant.

        This is an equality check against ``VDI_IMAGE_SIGNATURE``, matching
        ``vdiValidatePreHeader``.  It is not a checksum: there is no integrity
        value covering the header text, so a header damaged in some *other*
        field passes this test.  It catches truncation and foreign files, which
        is what it is for.
        """
        return struct.unpack_from("<I", self.raw, OFF_MAGIC)[0] == VDI_IMAGE_SIGNATURE

    def with_updates(
        self,
        *,
        disk_size: int | None = None,
        c_blocks: int | None = None,
        c_blocks_allocated: int | None = None,
    ) -> bytes:
        """Return a new 512-byte header with the given fields replaced.

        Only the fields listed are touched, so everything else -- the comment,
        the geometry, the creation UUID -- survives verbatim.
        """
        out = bytearray(self.raw)
        if disk_size is not None:
            struct.pack_into("<Q", out, OFF_DISK_SIZE, disk_size)
        if c_blocks is not None:
            struct.pack_into("<I", out, OFF_CBLOCKS, c_blocks)
        if c_blocks_allocated is not None:
            struct.pack_into("<I", out, OFF_CBLOCKS_ALLOC, c_blocks_allocated)
        # A modification UUID of all zeros is invalid, so start from the old one
        # when replacing it.
        new_uuid = uuid_mod.uuid4().bytes
        struct.pack_into("16s", out, OFF_MODIFICATION_UUID, new_uuid)
        return bytes(out)


class VdiDevice(SectorDevice):
    """A VDI image as a sector device.

    This is the only class in the project that knows the VDI container exists.
    Everything above it addresses a flat run of sectors; the 1 MiB blocks and
    the block allocation table are an implementation detail here.

    The file object is kept open because callers walk many blocks; use the
    instance as a context manager or call :meth:`close`.
    """

    error_class = VdiError

    def __init__(
        self,
        path: Path,
        *,
        writable: bool = False,
        cache_blocks: int = DEFAULT_CACHE_BLOCKS,
    ) -> None:
        self.path = Path(path)
        if not self.path.is_file():
            raise VdiError(f"no such image: {self.path}")
        self.writable = writable
        self._cache_limit = max(1, cache_blocks)
        # Not a `with`: the handle lives as long as the device, and `close()` /
        # `__exit__` is what releases it.
        self._fh = open(self.path, "r+b" if writable else "rb")  # noqa: SIM115
        try:
            raw = self._fh.read(HEADER_SIZE)
            self.header = VdiHeader.parse(raw)
            self._bat: list[int] = self._read_bat()
        except BaseException:
            self._fh.close()
            raise
        #: Dirty blocks, keyed by *logical VDI block index*.  Keying on the
        #: container's own unit is what makes one flush per 1 MiB possible.
        self._dirty: dict[int, bytearray] = {}
        #: Insertion order of dirty blocks, so eviction is predictable rather
        #: than dependent on dict internals.
        self._order: list[int] = []
        self._writes = WriteStats()
        #: Lazily refreshed length of the image file; see :meth:`_file_size`.
        self._size_hint: int | None = None
        #: Clean blocks, most-recently-used last.  See :meth:`_read_block` for
        #: why this is not an optimisation but a correctness-of-cost fix: the
        #: ext2 layer above asks for one 1 KiB block at a time, so without this
        #: a 12 MB file reads 12 GB.
        self._clean: dict[int, bytes] = {}
        self._clean_order: list[int] = []
        self._read_calls = 0
        self._read_bytes = 0

    # -- lifecycle ---------------------------------------------------------
    def close(self) -> None:
        if self._fh.closed:
            return
        if self.writable and self._dirty:
            self.flush()
        self._fh.close()

    def __enter__(self) -> VdiDevice:
        return self

    # `Literal[False]` rather than `bool`: this never suppresses the
    # exception, and saying so is what lets a type checker see that values
    # assigned inside the `with` block are bound afterwards.
    def __exit__(self, *exc) -> Literal[False]:
        self.close()
        return False

    def _require_writable(self) -> None:
        if not self.writable:
            raise VdiError(f"{self.path.name} was opened read-only; reopen with writable=True")

    def describe(self) -> str:
        return (
            f"{self.path.name} (VDI, "
            f"{'read-write' if self.writable else 'read-only'}, "
            f"{self.header.disk_size:,} bytes)"
        )

    # -- geometry ----------------------------------------------------------
    @property
    def size(self) -> int:
        return self.header.disk_size

    # Intentional override: the base holds `sector_size` as a plain
    # attribute so a test double can assign one, while this wraps another
    # device and must delegate rather than store its own copy.
    @property
    def sector_size(self) -> int:  # type: ignore[reportIncompatibleVariableOverride]
        # From the header, not assumed: the format records it, and a header
        # that says something other than 512 should not be silently treated as
        # 512.  VirtualBox only writes 512 today, so this is a guard.
        return self.header.sector_size or 512

    # -- BAT ---------------------------------------------------------------
    def _read_bat(self) -> list[int]:
        h = self.header
        self._fh.seek(h.off_blocks)
        raw = self._fh.read(h.c_blocks * 4)
        if len(raw) != h.c_blocks * 4:
            raise VdiError(
                f"block allocation table is truncated: wanted "
                f"{h.c_blocks * 4:,} bytes at {h.off_blocks:#x}, got {len(raw):,}"
            )
        return list(struct.unpack(f"<{h.c_blocks}I", raw))

    def _write_bat(self) -> None:
        h = self.header
        self._fh.seek(h.off_blocks)
        self._fh.write(struct.pack(f"<{h.c_blocks}I", *self._bat))

    @property
    def bat(self) -> tuple[int, ...]:
        return tuple(self._bat)

    def block_offset(self, index: int) -> int:
        """File offset of logical block ``index``, or raise if unmapped."""
        self._check_block(index)
        mapping = self._bat[index]
        if not is_allocated(mapping):
            raise VdiError(f"logical block {index} is not allocated")
        return self.header.off_data + mapping * self.header.cb_block

    def _check_block(self, index: int) -> None:
        if not 0 <= index < self.header.c_blocks:
            raise VdiError(
                f"logical block {index} is out of range (cBlocks={self.header.c_blocks})"
            )

    # -- raw container block access ----------------------------------------
    # Private on purpose: above this layer the container does not exist, and a
    # caller that addresses 1 MiB VDI blocks has already leaked it.
    def _read_block(self, index: int) -> bytes:
        """Read logical block ``index``; an unallocated block reads as zeros.

        A block whose storage lies past the end of the file also reads as
        zeros.  That is not a corruption being hidden: a VDI file is only as
        long as the blocks that have actually been written, so a freshly
        allocated block legitimately has nothing behind it yet.  Treating that
        as a short read would make the first write to any new block fail, which
        is precisely the case a growing filesystem needs.

        **Clean blocks are cached, and that is load-bearing.**  The container's
        unit is 1 MiB, but the ext2 layer above asks for one filesystem block at
        a time -- 1 KiB on the boot partition.  Without a cache, reading the
        12,362,752-byte kernel walks 12,073 filesystem blocks, each of which
        lands in one of only **12** distinct 1 MiB VDI blocks, so the same 12 MB
        is read from the file 1,000 times over: 12.7 GB of I/O for a 12 MB
        result.  Measured through the Windows 9p mount that is 40 s per kernel
        read, which is exactly how long the boot tests used to take.

        The cache holds whole blocks as ``bytes``, so a caller that mutates a
        returned block cannot corrupt another caller's view -- a dirty block is
        a ``bytearray`` in :attr:`_dirty` and is never handed out here.
        """
        self._check_block(index)

        cached = self._clean.get(index)
        if cached is not None:
            return cached
        # A block staged for writing is the truth, not what is on disk.
        dirty = self._dirty.get(index)
        if dirty is not None:
            return bytes(dirty)

        cb = self.header.cb_block
        mapping = self._bat[index]
        if not is_allocated(mapping):
            # BLOCK_FREE and BLOCK_ZERO both read as zeros.  VirtualBox draws
            # the line at VDI_IMAGE_BLOCK_UNALLOCATED rather than testing for
            # one sentinel, so the same predicate is used here.
            data = b"\x00" * cb
        else:
            offset = self.header.off_data + mapping * cb
            if offset >= self._file_size():
                data = b"\x00" * cb
            else:
                self._fh.seek(offset)
                data = self._fh.read(cb)
                if len(data) < cb:
                    # The file ends part-way through this block; the rest was
                    # never written, so it is zero.
                    data += b"\x00" * (cb - len(data))

        self._read_calls += 1
        self._read_bytes += cb
        self._cache_clean(index, data)
        return data

    def _cache_clean(self, index: int, data: bytes) -> None:
        """Remember a block's contents, evicting the least recently used.

        Insertion order is the LRU order: a hit re-appends, so the front of
        :attr:`_clean_order` is the coldest entry.
        """
        if index in self._clean:
            with contextlib.suppress(ValueError):  # pragma: no cover
                self._clean_order.remove(index)
        elif len(self._clean_order) >= self._cache_limit:
            victim = self._clean_order.pop(0)
            self._clean.pop(victim, None)
        self._clean[index] = data
        self._clean_order.append(index)

    def _file_size(self) -> int:
        """Current length of the image file, refreshed from the descriptor.

        Cached because the block reader consults it on every access, and
        invalidated by :meth:`_write_block` when it extends the file.
        """
        if self._size_hint is None:
            self._size_hint = os.fstat(self._fh.fileno()).st_size
        return self._size_hint

    def _ensure_allocated(self, index: int) -> None:
        """Give logical block ``index`` storage if it has none.

        Storage is appended after the highest file block in use, and the
        mapping is written for ``index`` itself.

        An earlier version hunted for the first free BAT *slot*, assigned the
        new file block there, and then re-pointed ``index`` at
        ``max(used)``.  When a free slot existed below ``index`` -- which
        happens as soon as a block is ever released -- that produced
        ``max(used) == 0`` and mapped the block onto file block 0, the MBR.
        Allocating for the block that was asked for removes the whole class of
        mistake: there is no second index to get wrong.
        """
        if self._bat[index] != BLOCK_FREE:
            return
        self._require_writable()
        # File blocks are handed out densely from zero, so the next one is one
        # past the highest in use.  The only way this can fail is exhausting
        # the two sentinel values that mean "no storage"; the file itself is
        # extended as needed, which is what makes appending safe.
        used = [m for m in self._bat if is_allocated(m)]
        next_block = (max(used) + 1) if used else 0
        if next_block >= BLOCK_ZERO:
            raise VdiError(
                f"no block number left for logical block {index}: the highest "
                f"file block in use is {max(used):,}, and "
                f"{BLOCK_ZERO:#x} onwards means 'no storage'."
            )
        # New blocks are appended after the highest block in use.
        self._bat[index] = next_block
        self.header.c_blocks_allocated += 1

    # -- dirty page cache --------------------------------------------------
    def _load_for_update(self, index: int) -> bytearray:
        """The current contents of block ``index``, as a mutable buffer.

        Seeded from what is already there.  An unallocated block reads as
        zeros; an allocated one is read back so a partial write cannot disturb
        the bytes it does not cover.  This read-merge-write is what keeps an
        APK's blocks from erasing the extent tree sharing their 1 MiB VDI
        block -- on the real image, exactly that happened once.
        """
        cached = self._dirty.get(index)
        if cached is not None:
            return cached
        if len(self._order) >= self._cache_limit:
            self._evict_one()
        buffer = bytearray(self._read_block(index))
        self._dirty[index] = buffer
        self._order.append(index)
        return buffer

    def _evict_one(self) -> None:
        """Flush the oldest dirty block to make room."""
        while self._order:
            victim = self._order.pop(0)
            buffer = self._dirty.pop(victim, None)
            if buffer is not None:
                self._write_block(victim, buffer)
                return

    def _write_block(self, index: int, data: bytes | bytearray) -> None:
        """One positioned write of a whole container block.

        Writing past the end of the file extends it, which is how a newly
        allocated block acquires its storage: the BAT names a block number, and
        the file is grown to cover it on first write rather than preallocated.
        """
        mapping = self._bat[index]
        if not is_allocated(mapping):
            raise VdiError(f"logical block {index} has no storage; refusing to write it")
        offset = self.header.off_data + mapping * self.header.cb_block
        self._fh.seek(offset)
        self._fh.write(data)
        if offset + len(data) > self._file_size():
            self._size_hint = offset + len(data)
        # The cached clean copy is now stale.  Dropping it means a later read
        # goes back to the file (or to the dirty buffer, which is checked
        # first), so no reader can be served a pre-write version.
        self._clean.pop(index, None)
        with contextlib.suppress(ValueError):
            self._clean_order.remove(index)

    # -- diagnostics -------------------------------------------------------
    @property
    def read_stats(self) -> WriteStats:
        """Physical reads issued, in the same shape as :attr:`write_stats`.

        Exposed so a test can assert that reading a file costs one container
        block per *distinct* block rather than one per filesystem block.  That
        ratio is the whole point of the clean cache, and a silent regression
        would only show up as the suite getting slower.
        """
        return WriteStats(
            calls=self._read_calls,
            physical_bytes=self._read_bytes,
            blocks=self._read_calls,
        )

    def _commit(self, stats: WriteStats) -> WriteStats:
        """Make data durable, then the header and BAT that describe it."""
        if not stats.calls:
            return stats
        self._fh.flush()
        os.fsync(self._fh.fileno())
        self._flush_header_and_bat()
        self._writes += stats
        return stats

    def flush(self) -> WriteStats:
        """Write every dirty block, then the table that describes them.

        Order matters: data blocks first, BAT last.  A crash between the two
        leaves blocks allocated but unwritten, which reads as zeros -- rather
        than a BAT entry pointing at a block that was never written, which
        would read as whatever was there before.
        """
        if not self.writable:
            return WriteStats()
        stats = WriteStats()
        for index in list(self._order):
            buffer = self._dirty.pop(index, None)
            if buffer is None:
                continue
            self._write_block(index, buffer)
            stats += WriteStats(calls=1, physical_bytes=len(buffer), blocks=1)
        self._order.clear()
        return self._commit(stats)

    # -- sector access -----------------------------------------------------
    def read_sectors(self, lba: int, count: int) -> bytes:
        """Read ``count`` sectors from ``lba``, through the dirty cache."""
        self.check_sectors(lba, count, what="read")
        if count == 0:
            return b""
        ss = self.sector_size
        cb = self.header.cb_block
        out = bytearray()
        pos = lba * ss
        remaining = count * ss
        while remaining > 0:
            index = pos // cb
            within = pos % cb
            chunk = min(remaining, cb - within)
            block = self._dirty.get(index)
            if block is None:
                block = self._read_block(index)
            out += block[within : within + chunk]
            pos += chunk
            remaining -= chunk
        return bytes(out)

    def write_sectors(self, lba: int, count: int, data: bytes) -> None:
        """Stage ``count`` sectors at ``lba`` into the dirty cache."""
        self._require_writable()
        self.check_sectors(lba, count, what="write")
        if count == 0:
            return
        expected = count * self.sector_size
        if len(data) != expected:
            raise VdiError(
                f"write_sectors({lba}, {count}) needs {expected:,} bytes but got {len(data):,}"
            )
        self._stage(lba * self.sector_size, data)

    def _stage(self, offset: int, data: bytes) -> WriteStats:
        """Put ``data`` at byte ``offset`` into the dirty cache."""
        cb = self.header.cb_block
        spans = list(self._split_by_block(offset, memoryview(data)))
        # Allocate before staging: a block must have storage by the time the
        # cache flushes it, and doing it up front means a full BAT is reported
        # before any buffer has been dirtied.
        for position, _chunk in spans:
            self._ensure_allocated(position // cb)
        for position, chunk in spans:
            index = position // cb
            within = position % cb
            self._load_for_update(index)[within : within + len(chunk)] = chunk
        return WriteStats(bytes=len(data), blocks=len({p // cb for p, _ in spans}))

    def _split_by_block(self, pos: int, view: memoryview):
        """Yield ``(absolute offset, chunk)`` pairs, one per container block."""
        cb = self.header.cb_block
        while view:
            within = pos % cb
            chunk = min(len(view), cb - within)
            yield pos, view[:chunk]
            view = view[chunk:]
            pos += chunk

    # -- batched writes ----------------------------------------------------
    def write_blocks(self, writes: Sequence[tuple[int, bytes]]) -> WriteStats:
        """Stage many byte ranges, then flush whole container blocks once.

        ``writes`` is a sequence of ``(virtual byte offset, data)``, typically
        the 4 KiB blocks of a file being rewritten.  Every range lands in the
        same dirty-page cache the sector path uses, so a contiguous run costs
        **one** positioned write per MiB instead of one per 4 KiB.

        Why this matters: on the Windows 9p mount this project runs against, the
        cost of a write is the round trip, not the bytes.  Measured on the real
        image, 200 separate 4 KiB writes took 3.4 s (17 ms each) while a single
        800 KiB write of the same data took 0.03 s.  Writing a 43 MB file block
        by block therefore took 228 s; staging turns 10,550 calls into about 42.
        """
        self._require_writable()
        if not writes:
            return WriteStats()

        touched: set[int] = set()
        total_bytes = 0
        for offset, payload in writes:
            if not payload:
                continue
            self.check_range(offset, len(payload), what="batched write")
            staged = self._stage(offset, payload)
            total_bytes += staged.bytes
            cb = self.header.cb_block
            for position, _chunk in self._split_by_block(offset, memoryview(payload)):
                touched.add(position // cb)

        # Flush each touched block exactly once.  A block the cache evicted
        # while staging was written then and is simply absent here.
        stats = WriteStats(bytes=total_bytes)
        for index in sorted(touched):
            buffer = self._dirty.pop(index, None)
            if buffer is None:
                continue
            self._write_block(index, buffer)
            stats += WriteStats(calls=1, physical_bytes=len(buffer), blocks=1)
            with contextlib.suppress(ValueError):
                self._order.remove(index)

        # The table is flushed after the data it describes, so an interruption
        # cannot leave a block reachable that was never written.
        return self._commit(stats)

    # -- growing -----------------------------------------------------------
    def set_disk_size(self, size: int) -> None:
        """Grow ``cbDisk``/``cBlocks`` so more logical blocks exist.

        Shrinking is refused: it would orphan data and silently truncate the
        filesystem inside.
        """
        self._require_writable()
        if size < self.header.disk_size:
            raise VdiError(
                f"refusing to shrink the image from {self.header.disk_size:,} to {size:,} bytes"
            )
        new_blocks = (size + self.header.cb_block - 1) // self.header.cb_block
        if new_blocks == self.header.c_blocks:
            self.header.disk_size = size
            self._flush_header_and_bat()
            return

        # The BAT has to grow in place, which means the data area must move --
        # not something we can do safely in one pass.  Grow only within the
        # already-reserved BAT capacity.
        bat_bytes = self.header.c_blocks * 4
        gap = self.header.off_data - (self.header.off_blocks + bat_bytes)
        needed = (new_blocks - self.header.c_blocks) * 4
        if needed > gap:
            raise VdiError(
                f"cannot grow from {self.header.c_blocks} to {new_blocks} blocks: "
                f"the BAT would need {needed:,} more bytes but only {gap:,} are "
                f"reserved before the data area at {self.header.off_data:#x}. "
                f"Resizing the BAT requires moving the data area, which is not "
                f"supported in place."
            )
        self._bat.extend([BLOCK_FREE] * (new_blocks - self.header.c_blocks))
        self.header.c_blocks = new_blocks
        self.header.disk_size = size
        self._flush_header_and_bat()

    def _flush_header_and_bat(self) -> None:
        """Rewrite the header and the BAT, and make both durable."""
        if not self.writable:
            return
        self._fh.seek(0)
        self._fh.write(
            self.header.with_updates(
                disk_size=self.header.disk_size,
                c_blocks=self.header.c_blocks,
                c_blocks_allocated=self.header.c_blocks_allocated,
            )
        )
        # Keep the in-memory copy consistent with what is on disk, so a later
        # with_updates() does not resurrect a stale field.
        self._fh.seek(0)
        self.header.raw = self._fh.read(HEADER_SIZE)
        self._write_bat()
        self._fh.flush()
        os.fsync(self._fh.fileno())
