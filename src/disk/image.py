"""Opening a disk image, whichever container it turns out to be.

Why this exists
---------------
Everything above this module wants the same thing: a whole disk it can read
sectors from, plus a partition table.  What it does *not* want to know is
whether those sectors come out of a VirtualBox VDI, a raw ``.img``, or
something else again -- that question has exactly one answer per file and one
place where it should be asked.

This is also where the refusal lives.  A file that is not a container this code
understands is reported, not silently treated as raw: a VDI read as a raw image
would produce a plausible-looking disk whose first 512 bytes are a header, and
every subsequent read would be off by the header size.  Guessing here is how
you write to the wrong place.
"""

from __future__ import annotations

from pathlib import Path
from typing import Literal

from .device import ByteDevice, DeviceError, SectorDevice, WriteStats
from .partition import PartitionTable
from .vdi import VdiDevice, VdiError

#: The container formats this module can open, by name.
FORMAT_VDI = "vdi"
FORMAT_RAW = "raw"


class ImageError(DeviceError):
    """Raised when a file cannot be opened as a disk image."""


class Disk(SectorDevice):
    """A whole disk: sectors, plus the partition table on them.

    The partition table is parsed on demand and cached, because building it
    reads the MBR and probes partitions, and a caller that asks twice should not
    pay twice.
    """

    #: Which container this disk was read from.
    format: str = FORMAT_RAW

    def __init__(self, device: SectorDevice) -> None:
        self.dev = device
        self._table: PartitionTable | None = None

    # -- the underlying device ---------------------------------------------
    # Intentional override: the base holds `sector_size` as a plain
    # attribute so a test double can assign one, while this wraps another
    # device and must delegate rather than store its own copy.
    @property
    def sector_size(self) -> int:  # type: ignore[reportIncompatibleVariableOverride]
        return self.dev.sector_size

    @property
    def size(self) -> int:
        return self.dev.size

    def read_sectors(self, lba: int, count: int) -> bytes:
        return self.dev.read_sectors(lba, count)

    def write_sectors(self, lba: int, count: int, data: bytes) -> None:
        return self.dev.write_sectors(lba, count, data)

    def write_blocks(self, writes) -> WriteStats:
        """Forward batched writes to the container unchanged.

        This override is what keeps batching alive across the whole stack: the
        base implementation would issue one write per range, which on the 9p
        mount this runs against is the 228-second path.
        """
        return self.dev.write_blocks(writes)

    def flush(self) -> WriteStats:
        """Make staged writes durable, if the container stages any."""
        flush = getattr(self.dev, "flush", None)
        if flush is None:
            return WriteStats()
        return flush()

    def describe(self) -> str:
        return f"{self.dev.describe()} [{self.format}]"

    # -- partitions --------------------------------------------------------
    def partitions(self, *, refresh: bool = False) -> PartitionTable:
        """The MBR partition table on this disk, parsed once and cached."""
        if self._table is None or refresh:
            self._table = PartitionTable(self, total_sectors=self.sector_count)
        return self._table

    def partition(self, number: int):
        """The partition with the given Linux number (sda3 -> 3)."""
        return self.partitions().find(number)

    # -- lifecycle ---------------------------------------------------------
    def close(self) -> None:
        close = getattr(self.dev, "close", None)
        if close is not None:
            close()

    def __enter__(self) -> Disk:
        return self

    # `Literal[False]` rather than `bool`: this never suppresses the
    # exception, and saying so is what lets a type checker see that values
    # assigned inside the `with` block are bound afterwards.
    def __exit__(self, *exc) -> Literal[False]:
        self.close()
        return False


class VdiDisk(Disk):
    """A VirtualBox VDI opened as a disk.

    A container that cannot be parsed raises :class:`ImageError` here, even
    though the underlying parser raises ``VdiError``: callers of this module
    asked to open *an image*, and should not have to know which container it
    turned out to be in order to catch the failure.
    """

    format = FORMAT_VDI

    def __enter__(self) -> VdiDisk:
        """Narrowed so callers can reach the container-specific ``.vdi``."""
        return self

    def __init__(self, path: Path, *, writable: bool = False) -> None:
        path = Path(path)
        try:
            self.vdi = VdiDevice(path, writable=writable)
        except VdiError as exc:
            raise ImageError(f"cannot open {path.name} as a VDI: {exc}") from exc
        try:
            super().__init__(self.vdi)
        except BaseException:
            self.vdi.close()
            raise
        self.path = path


class RawDisk(Disk):
    """A raw disk image opened as a disk.

    MuMu ships ``.vdi`` files, so this exists for the other direction: a disk
    dumped out with ``vbox-img convert`` or ``dd``, which is what someone
    comparing against a known-good image will have.
    """

    format = FORMAT_RAW

    def __init__(self, path: Path, *, writable: bool = False) -> None:
        self.file = ByteDevice(path, writable=writable)
        super().__init__(self.file)
        self.path = Path(path)


def _looks_like_vdi(path: Path) -> bool:
    """Whether the first bytes name the VirtualBox container."""
    from .vdi import VDI_SIGNATURE

    try:
        with open(path, "rb") as fh:
            return fh.read(len(VDI_SIGNATURE)) == VDI_SIGNATURE
    except OSError:
        return False


def open_image(
    path: Path,
    *,
    writable: bool = False,
    format: str | None = None,
) -> Disk:
    """Open a disk image, working out its container from its contents.

    ``format`` forces a container (``"vdi"`` or ``"raw"``) and skips detection;
    that is for a caller that knows better, not a fallback.  A file whose
    container cannot be identified is *refused* rather than assumed to be raw,
    because a VDI read as raw produces a disk that looks plausible and is
    entirely wrong.
    """
    path = Path(path)
    if not path.is_file():
        raise ImageError(f"no such image: {path}")

    if format == FORMAT_VDI:
        return VdiDisk(path, writable=writable)
    if format == FORMAT_RAW:
        return RawDisk(path, writable=writable)
    if format is not None:
        raise ImageError(
            f"unknown image format {format!r}; expected {FORMAT_VDI!r} or {FORMAT_RAW!r}"
        )

    if _looks_like_vdi(path):
        # The signature says VDI, so a header that will not parse is an error
        # rather than a reason to fall back to raw: treating those bytes as a
        # flat disk would be wrong in a way that is hard to see.
        return VdiDisk(path, writable=writable)

    # A raw image is whatever is left.  It is only accepted when the caller
    # asked for it or when it has a partition table, so a random file is
    # reported rather than mounted.
    try:
        disk = RawDisk(path, writable=writable)
    except DeviceError as exc:
        raise ImageError(f"cannot open {path}: {exc}") from exc
    try:
        disk.partitions()
    except DeviceError as exc:
        disk.close()
        raise ImageError(
            f"{path.name} is not a VDI and has no MBR partition table ({exc}); "
            f"pass format='raw' to open it as a flat disk anyway"
        ) from exc
    return disk


def vdi_header_fields(path: Path) -> dict[str, str]:
    """The VDI header fields worth cross-checking against ``vbox-img``.

    Returned as strings because that is how the bundled tool reports them, and
    the comparison is textual.  Lives here rather than in the CLI so that the
    layer which knows about containers is also the layer that describes one.
    """
    with VdiDisk(path) as disk:
        h = disk.vdi.header
        return {
            "Size": str(h.disk_size),
            "CBlocks": str(h.c_blocks),
            "CBlocksAllocated": str(h.c_blocks_allocated),
            "offBlocks": str(h.off_blocks),
            "offData": str(h.off_data),
        }


__all__ = [
    "FORMAT_RAW",
    "FORMAT_VDI",
    "Disk",
    "ImageError",
    "RawDisk",
    "VdiDisk",
    "open_image",
    "vdi_header_fields",
]
