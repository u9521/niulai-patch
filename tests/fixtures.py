"""Shared fixtures for the disk tests.

Kept in one module so the VDI, partition, image and filesystem tests all build
their synthetic images the same way.  Everything here is hand-built rather than
shelled out to ``mkfs`` or ``VBoxManage``: the suite has to run on a machine
with no ext2 tools and no VirtualBox, and a fixture whose layout we control is
one whose bytes we can assert against.
"""

from __future__ import annotations

import struct
from pathlib import Path

from disk import vdi
from disk.device import ByteDevice, SectorDevice


# --------------------------------------------------------------------------- #
# Synthetic VDIs
# --------------------------------------------------------------------------- #
def build_vdi_bytes(
    data_blocks: list[bytes],
    *,
    block_size: int = 1024,
    bat: list[int] | None = None,
    sector_size: int = 512,
    header_patch: dict[int, bytes] | None = None,
) -> bytes:
    """Wrap raw blocks in a synthetic dynamic VDI, matching the real layout.

    ``data_blocks`` are the file's storage blocks, in file order.  ``bat`` maps
    logical blocks to file blocks; it defaults to the identity mapping for all
    of them.  Pass ``vdi.BLOCK_FREE`` for a logical block that has no storage,
    which is how the unallocated-reads-as-zeros path is exercised.

    The layout mirrors a real image: a 512-byte header, a gap, the BAT at
    0x100000, a gap, then the data at 0x200000.  The offsets matter because the
    header's own validation checks that the BAT precedes the data area.
    """
    if bat is None:
        bat = list(range(len(data_blocks)))
    n_logical = len(bat)
    allocated = sum(1 for m in bat if vdi.is_allocated(m))
    highest = max((m for m in bat if vdi.is_allocated(m)), default=-1)

    header = bytearray(512)
    sig = vdi.VDI_SIGNATURE + b"\n"
    header[0 : len(sig)] = sig
    struct.pack_into("<I", header, vdi.OFF_MAGIC, vdi.VDI_IMAGE_SIGNATURE)
    struct.pack_into("<I", header, vdi.OFF_VERSION, 0x00010001)
    struct.pack_into("<I", header, vdi.OFF_CB_HEADER, vdi.HEADER_STRUCT_SIZE)
    struct.pack_into("<I", header, vdi.OFF_TYPE, vdi.TYPE_DYNAMIC)
    struct.pack_into("<I", header, vdi.OFF_FLAGS, 0)
    struct.pack_into("<I", header, vdi.OFF_BLOCKS, 0x100000)
    struct.pack_into("<I", header, vdi.OFF_DATA, 0x200000)
    struct.pack_into("<I", header, vdi.OFF_CB_SECTOR, sector_size)
    struct.pack_into("<Q", header, vdi.OFF_DISK_SIZE, n_logical * block_size)
    struct.pack_into("<I", header, vdi.OFF_CB_BLOCK, block_size)
    struct.pack_into("<I", header, vdi.OFF_CBLOCKS, n_logical)
    struct.pack_into("<I", header, vdi.OFF_CBLOCKS_ALLOC, allocated)
    for offset, data in (header_patch or {}).items():
        header[offset : offset + len(data)] = data

    out = bytearray()
    out += bytes(header)
    out += b"\x00" * (0x100000 - len(out))
    out += struct.pack(f"<{n_logical}I", *bat)
    out += b"\x00" * (0x100000 - len(out) % 0x100000)
    out += b"\x00" * (0x200000 - len(out))
    # Physical blocks are written for everything the BAT could name, and for
    # every block supplied -- a test that allocates a new block needs the file
    # to be long enough to hold it.
    for index in range(max(highest + 1, len(data_blocks))):
        payload = b""
        if index < len(data_blocks):
            payload = data_blocks[index]
        out += payload.ljust(block_size, b"\x00")
    return bytes(out)


def write_vdi(path: Path, data_blocks: list[bytes], **kwargs) -> Path:
    """``build_vdi_bytes`` written to ``path``."""
    path.write_bytes(build_vdi_bytes(data_blocks, **kwargs))
    return path


def mbr_bytes(entries: list[tuple[int, int, int]], *, boot: int = 0) -> bytes:
    """A 512-byte MBR holding up to four primary entries.

    ``entries`` are ``(type, start_lba, sectors)``; type 0 leaves the slot
    empty.  CHS fields are written saturated (``FE FF FF``), which is what every
    modern tool writes for a disk larger than CHS can express, and what the
    partition code expects to preserve verbatim.
    """
    mbr = bytearray(512)
    for slot, (ptype, start, sectors) in enumerate(entries[:4]):
        if not ptype:
            continue
        entry = bytearray(16)
        if slot == boot:
            entry[0] = 0x80
        entry[1:4] = b"\xfe\xff\xff"
        entry[4] = ptype
        entry[5:8] = b"\xfe\xff\xff"
        struct.pack_into("<II", entry, 8, start, sectors)
        mbr[446 + slot * 16 : 462 + slot * 16] = bytes(entry)
    mbr[510:512] = b"\x55\xaa"
    return bytes(mbr)


def ebr_bytes(
    *,
    logical: tuple[int, int] | None = None,
    link: int = 0,
    link_sectors: int = 0,
) -> bytes:
    """A 512-byte extended boot record.

    Slot 0 describes the logical volume at ``logical`` (start is relative to
    this EBR); slot 1 links to the next EBR ``link`` sectors further on.
    """
    sector = bytearray(512)
    if logical is not None:
        ptype, start, sectors = logical
        entry = bytearray(16)
        entry[1:4] = b"\xfe\xff\xff"
        entry[4] = ptype
        entry[5:8] = b"\xfe\xff\xff"
        struct.pack_into("<II", entry, 8, start, sectors)
        sector[446:462] = bytes(entry)
    if link:
        entry = bytearray(16)
        entry[1:4] = b"\xfe\xff\xff"
        entry[4] = 0x05
        entry[5:8] = b"\xfe\xff\xff"
        struct.pack_into("<II", entry, 8, link, link_sectors or 1)
        sector[462:478] = bytes(entry)
    sector[510:512] = b"\x55\xaa"
    return bytes(sector)


class FakeDisk(SectorDevice):
    """An in-memory sector device.

    The partition and image tests need a disk they can write to and inspect
    byte by byte without a file, and a plain bytearray is faster and clearer
    than a temp file for that.
    """

    def __init__(self, size: int, *, sector_size: int = 512) -> None:
        self.data = bytearray(size)
        self.sector_size = sector_size
        #: Every ``write_sectors`` call, so a test can assert on batching.
        self.write_calls: list[tuple[int, int]] = []

    def read_sectors(self, lba: int, count: int) -> bytes:
        start = lba * self.sector_size
        return bytes(self.data[start : start + count * self.sector_size])

    def write_sectors(self, lba: int, count: int, data: bytes) -> None:
        start = lba * self.sector_size
        self.data[start : start + len(data)] = data
        self.write_calls.append((lba, count))

    @property
    def size(self) -> int:
        return len(self.data)


__all__ = [
    "ByteDevice",
    "FakeDisk",
    "build_vdi_bytes",
    "ebr_bytes",
    "mbr_bytes",
    "vdi",
    "write_vdi",
]
