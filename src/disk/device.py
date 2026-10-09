"""The device interface every layer of the disk stack implements.

Why an interface at all
-----------------------
The code this replaces addressed the disk by opening a ``Vdi`` and hand-rolling
a tiny class that added a byte offset to every call -- three near-identical
copies of it lived in ``kernel``, ``lawnchair`` and the tests.  None of them
checked that the result stayed inside the partition it was supposed to be
describing, so a wrong base offset wrote into whichever partition happened to
follow, silently.

Two things are therefore part of the interface rather than conventions:

**Bounds are checked at the layer that knows them.**  A :class:`SectorDevice`
knows how many sectors it covers and refuses anything outside.  A partition
covering 28,634 sectors cannot be talked into writing sector 30,000.

**Batching is declared, not negotiated.**  On the Windows 9p mount this project
runs against, one write costs ~17 ms whether it carries 4 KiB or 1 MiB, so
writing a 43 MiB file one filesystem block at a time took 228 s.  The old code
reached the fast path through ``getattr(device, "write_blocks", None)``, which
meant a device that lost the method would quietly go back to being 50x slower
with nothing to say so.  :meth:`Device.write_blocks` is part of the base class,
so it is always there and can always be counted.

The unit of transfer is part of each layer
------------------------------------------
``read_sectors``/``write_sectors`` are the primitives at the container and
partition layers; ``read_at``/``write_at`` are derived from them so a caller
cannot reach past the sector path.  The filesystem layer above speaks in byte
ranges because that is what ext2/ext4 block numbers are.
"""

from __future__ import annotations

import hashlib
import os
from abc import ABC, abstractmethod
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

#: Copy granularity for :meth:`Device.extract_to` / :meth:`Device.write_from`.
#: Large enough that the per-call cost disappears, small enough that a 14 MiB
#: partition lift-out does not need a 14 MiB buffer per layer.
DEFAULT_IO_CHUNK = 4 * 1024 * 1024


def ceil_to(value: int, unit: int) -> int:
    """Round ``value`` up to the next multiple of ``unit``.

    Lives here because two callers that must agree use it: the launcher swap
    (:mod:`lawnchair`) and the boot-file swap (:mod:`boot.image`).  Both compute
    "how many blocks does this replacement need that the current one did not
    have" from it, and two copies of a rounding rule is one copy too many.
    """
    if unit <= 0:
        raise ValueError(f"unit must be positive, got {unit}")
    return -(-value // unit) * unit


class DeviceError(Exception):
    """A read or write fell outside the region, or was otherwise invalid."""


@dataclass(frozen=True)
class WriteStats:
    """What a batch of writes actually cost.

    Replaces the ``dict[str, int]`` this used to return.  Two call sites were
    already returning dicts with no keys in common (``{"calls", "blocks",
    "bytes"}`` against ``{"allocated", "freed", "net"}``), so a mistyped key was
    a ``KeyError`` several layers away from the mistake.  Here it is an
    ``AttributeError`` at the point of use.
    """

    #: Positioned writes issued to the underlying file.
    calls: int = 0
    #: Bytes the caller asked to write.
    bytes: int = 0
    #: Bytes actually pushed to storage.  Higher than :attr:`bytes` when a
    #: partial block write forces a read-merge-write of the whole block, which
    #: is the cost this class exists to make visible.
    physical_bytes: int = 0
    #: Storage blocks touched (1 MiB VDI blocks, typically).
    blocks: int = 0

    def __add__(self, other: WriteStats) -> WriteStats:
        if not isinstance(other, WriteStats):
            return NotImplemented
        return WriteStats(
            calls=self.calls + other.calls,
            bytes=self.bytes + other.bytes,
            physical_bytes=self.physical_bytes + other.physical_bytes,
            blocks=self.blocks + other.blocks,
        )

    def __bool__(self) -> bool:
        return bool(self.calls or self.bytes or self.blocks)

    def describe(self) -> str:
        detail = f"{self.calls:,} calls, {self.bytes:,} bytes requested"
        if self.physical_bytes:
            detail += f", {self.physical_bytes:,} bytes written"
        return detail + f", {self.blocks:,} blocks"


class Device(ABC):
    """A byte-addressable region with declared batched writes.

    The only thing a filesystem layer needs is this: read a range, write a
    range, and be able to write many ranges without paying per range.
    """

    #: Raised for a range that does not fit.  A concrete layer overrides this
    #: with its own error type, so a caller can catch ``VdiError`` for a VDI
    #: and still have ``DeviceError`` catch every layer at once.
    error_class: type[DeviceError] = DeviceError

    @property
    @abstractmethod
    def size(self) -> int:
        """The region's length in bytes."""

    @abstractmethod
    def read_at(self, offset: int, length: int) -> bytes:
        """Read ``length`` bytes at ``offset``."""

    @abstractmethod
    def write_at(self, offset: int, data: bytes) -> None:
        """Write ``data`` at ``offset``."""

    # -- bounds ------------------------------------------------------------
    def check_range(self, offset: int, length: int, *, what: str = "access") -> None:
        """Refuse a range that does not lie inside this device.

        Called by every implementation before it does I/O.  The message names
        the region so a wrong base offset is reported as "outside partition
        sda6" rather than as a short read somewhere further down.
        """
        if offset < 0:
            raise self.error_class(f"negative offset {offset:,} for {what}")
        if length < 0:
            raise self.error_class(f"negative length {length:,} for {what}")
        end = offset + length
        if end > self.size:
            raise self.error_class(
                f"{what} at {offset:,}..{end:,} is past the end of {self.describe()}"
            )

    def describe(self) -> str:
        return f"{type(self).__name__} of {self.size:,} bytes"

    # -- batched I/O -------------------------------------------------------
    def write_blocks(self, writes: Sequence[tuple[int, bytes]]) -> WriteStats:
        """Write many ``(offset, data)`` ranges.

        The base implementation is one positioned write per range, which is
        correct everywhere.  Layers where a write is expensive override this to
        coalesce; the point of declaring it here is that the fast path cannot
        silently disappear.
        """
        total = WriteStats()
        for offset, payload in writes:
            if not payload:
                continue
            self.write_at(offset, payload)
            total += WriteStats(calls=1, bytes=len(payload))
        return total

    # -- whole-device copy -------------------------------------------------
    def extract_to(self, dest: Path, *, chunk: int = DEFAULT_IO_CHUNK) -> str:
        """Copy the whole device to ``dest`` and return its SHA-256.

        Lifts a partition out to a plain file, for a tool that needs a seekable
        image and cannot cope with a VDI's block indirection.  The hash is
        returned rather than left to the caller because every caller wants it:
        it is how the copy is shown to be the partition that was asked for.
        """
        dest = Path(dest)
        digest = hashlib.sha256()
        done = 0
        with open(dest, "wb") as fh:
            while done < self.size:
                want = min(chunk, self.size - done)
                data = self.read_at(done, want)
                if len(data) != want:
                    raise self.error_class(
                        f"short read at {done:,}: got {len(data):,} of {want:,} bytes"
                    )
                fh.write(data)
                digest.update(data)
                done += want
            fh.flush()
            os.fsync(fh.fileno())
        return digest.hexdigest()

    def write_from(self, src: Path, *, chunk: int = DEFAULT_IO_CHUNK) -> int:
        """Write the contents of ``src`` over the start of this device.

        Returns the number of bytes written.  Refuses a source that does not
        fit rather than truncating it: a partition that is too small for the
        file is a planning mistake, not something to discover halfway through.
        """
        src = Path(src)
        total = src.stat().st_size
        if total > self.size:
            raise self.error_class(
                f"{src.name} is {total:,} bytes but {self.describe()} is only "
                f"{self.size:,} bytes; refusing to truncate it"
            )
        done = 0
        with open(src, "rb") as fh:
            while block := fh.read(chunk):
                self.write_at(done, block)
                done += len(block)
        return done


class SectorDevice(Device):
    """A device addressed in sectors, with byte access derived from them.

    ``read_at``/``write_at`` are implemented here in terms of the sector
    primitives, so a subclass only has to get the sector path right -- there is
    no second, unchecked way to reach the storage.  An unaligned write becomes
    a read-modify-write of the sectors it covers, which is the same thing the
    old code did at 1 MiB granularity and is exact at 512 bytes.
    """

    #: Bytes per sector.  Read from the container header where there is one
    #: (a VDI records it at ``OFF_CB_SECTOR``); 512 is the MBR's own unit.
    sector_size: int = 512

    @property
    def sector_count(self) -> int:
        return self.size // self.sector_size

    @abstractmethod
    def read_sectors(self, lba: int, count: int) -> bytes:
        """Read ``count`` sectors starting at logical sector ``lba``."""

    @abstractmethod
    def write_sectors(self, lba: int, count: int, data: bytes) -> None:
        """Write ``count`` sectors of ``data`` starting at sector ``lba``."""

    # -- bounds ------------------------------------------------------------
    def check_sectors(self, lba: int, count: int, *, what: str = "access") -> None:
        """Refuse a sector range that does not lie inside this device.

        This is the guard the hand-rolled offset adapters did not have.  A
        partition is a window onto a disk, and a window that will not refuse to
        look past its own edge is how a base-offset bug becomes silent damage
        to the next partition along.
        """
        if lba < 0:
            raise self.error_class(f"negative sector {lba:,} for {what}")
        if count < 0:
            raise self.error_class(f"negative sector count {count:,} for {what}")
        end = lba + count
        if end > self.sector_count:
            raise self.error_class(
                f"{what} of sectors {lba:,}..{end:,} is past the end of {self.describe()}"
            )

    # -- byte access derived from sectors ----------------------------------
    def read_at(self, offset: int, length: int) -> bytes:
        if length == 0:
            return b""
        self.check_range(offset, length, what="read")
        ss = self.sector_size
        first = offset // ss
        last = (offset + length - 1) // ss
        raw = self.read_sectors(first, last - first + 1)
        start = offset - first * ss
        return raw[start : start + length]

    def write_at(self, offset: int, data: bytes) -> None:
        if not data:
            return
        self.check_range(offset, len(data), what="write")
        ss = self.sector_size
        first = offset // ss
        last = (offset + len(data) - 1) // ss
        count = last - first + 1
        start = offset - first * ss
        end = start + len(data)
        if start == 0 and end == count * ss:
            # Sector-aligned and a whole number of sectors: no need to read
            # anything back.  This is the common case -- an ext2/ext4 block
            # write is always block-aligned, and 4 KiB is eight 512-byte
            # sectors.
            self.write_sectors(first, count, bytes(data))
            return
        buffer = bytearray(self.read_sectors(first, count))
        buffer[start:end] = data
        self.write_sectors(first, count, bytes(buffer))


class ByteDevice(SectorDevice):
    """A plain host file as a device: a raw image, or a test double.

    A file is trivially sector-addressable, so this is a sector device whose
    sectors happen to be contiguous -- which means a raw image and a VDI look
    the same to everything above this module.

    Also what the filesystem tests bind to, which is what keeps them
    independent of the VDI layer.
    """

    def __init__(self, path: Path, *, writable: bool = False, extendable: bool = True) -> None:
        self.path = Path(path)
        if not self.path.is_file():
            raise DeviceError(f"no such file: {self.path}")
        self.writable = writable
        #: Whether a write past the end grows the file.  True for a raw disk
        #: image, which is just a file and grows the way one does; False for a
        #: device whose extent is fixed by something else (a partition, or a
        #: container header), where a write past the end is a bug rather than
        #: an extension.
        self.extendable = extendable
        # Not a `with`: the handle lives as long as the device, and `close()` /
        # `__exit__` is what releases it.
        self._fh = open(self.path, "r+b" if writable else "rb")  # noqa: SIM115
        self._fh.seek(0, os.SEEK_END)
        self._size = self._fh.tell()

    #: Files are byte-addressable, so 512 is a convention rather than a
    #: constraint; it matches what a raw disk image is normally described in.
    sector_size = 512

    @property
    def size(self) -> int:
        return self._size

    def describe(self) -> str:
        mode = "read-write" if self.writable else "read-only"
        return f"{self.path.name} ({mode}, {self._size:,} bytes)"

    def read_sectors(self, lba: int, count: int) -> bytes:
        self.check_sectors(lba, count, what="read")
        offset = lba * self.sector_size
        length = count * self.sector_size
        self._fh.seek(offset)
        data = self._fh.read(length)
        if len(data) < length:
            # A file shorter than the device it claims to be: pad with zeros,
            # which is what an unallocated region reads as everywhere else.
            data += b"\x00" * (length - len(data))
        return data

    def write_sectors(self, lba: int, count: int, data: bytes) -> None:
        self._require_writable()
        if lba < 0 or count < 0:
            raise self.error_class(f"negative sector range {lba:,}+{count:,}")
        if not self.extendable:
            self.check_sectors(lba, count, what="write")
        if not data:
            return
        self._fh.seek(lba * self.sector_size)
        self._fh.write(data)
        end = lba * self.sector_size + len(data)
        if end > self._size:
            self._size = end

    def read_at(self, offset: int, length: int) -> bytes:
        """Direct byte read, without going through the sector path."""
        if length == 0:
            return b""
        self.check_range(offset, length, what="read")
        self._fh.seek(offset)
        data = self._fh.read(length)
        if len(data) < length:
            data += b"\x00" * (length - len(data))
        return data

    def write_at(self, offset: int, data: bytes) -> None:
        if not data:
            return
        self._require_writable()
        if self.extendable:
            if offset < 0:
                raise self.error_class(f"negative offset {offset:,} for write")
        else:
            self.check_range(offset, len(data), what="write")
        self._fh.seek(offset)
        self._fh.write(data)
        if offset + len(data) > self._size:
            self._size = offset + len(data)

    def _require_writable(self) -> None:
        if not self.writable:
            raise DeviceError(f"{self.path.name} was opened read-only; reopen with writable=True")

    def flush(self) -> None:
        if self.writable:
            self._fh.flush()
            os.fsync(self._fh.fileno())

    def close(self) -> None:
        if not self._fh.closed:
            self._fh.close()

    def __enter__(self) -> ByteDevice:
        return self

    # `Literal[False]` rather than `bool`: this never suppresses the
    # exception, and saying so is what lets a type checker see that values
    # assigned inside the `with` block are bound afterwards.
    def __exit__(self, *exc) -> Literal[False]:
        self.close()
        return False
