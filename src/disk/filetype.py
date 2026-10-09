"""Identify what a partition holds by looking at it.

Why this is separate from the partition table
---------------------------------------------
The MBR records a *hint* about a partition's contents in its type byte, and
hints are not reliable: MuMu's own image labels both the 14 MiB boot partition
and the 1.6 GiB Android system partition ``0x83`` ("Linux"), so the type byte
cannot tell them apart.  Anything that needs to know which partition is which
has to read the partition.

That matters because the alternative -- hard-coding the sector numbers -- is
what this project did before, and those numbers stop being true the moment a
growth plan moves the partitions.  A number that is right today and silently
wrong after a resize is worse than a lookup that refuses when it is unsure.
"""

from __future__ import annotations

import struct

from .device import DeviceError

#: How much of a partition to read when probing.  Enough for an ext2/ext4
#: superblock (which starts at byte 1024 and is 1024 bytes) plus the signatures
#: of the other formats, and small enough to be free.
PROBE_BYTES = 4096

EXT2_MAGIC = 0xEF53
EXT2_SUPERBLOCK_OFFSET = 1024
#: ``s_feature_incompat`` / ``s_feature_ro_compat``, relative to the superblock.
SB_FEATURE_INCOMPAT = 0x60
SB_FEATURE_RO_COMPAT = 0x64
INCOMPAT_EXTENTS = 0x0040
INCOMPAT_64BIT = 0x0080
RO_COMPAT_HAS_JOURNAL = 0x0004


class FileSystemKind:
    """The formats this module can name."""

    EXT2 = "ext2"
    EXT3 = "ext3"
    EXT4 = "ext4"
    FAT = "vfat"
    EXFAT = "exfat"
    NTFS = "ntfs"
    SWAP = "linux-swap"
    UNKNOWN = "unknown"

    #: Everything that is an ext filesystem, for callers that just want to know
    #: whether ``extfs.Ext2`` can mount it.
    EXT_ANY = (EXT2, EXT3, EXT4)


def _at(data: bytes, offset: int, length: int) -> bytes:
    return data[offset : offset + length]


def detect(data: bytes) -> str:
    """Name the filesystem in a probe read, or ``"unknown"``.

    Reads only what it needs and returns ``"unknown"`` rather than raising for
    an unrecognised blob: this is a question, not a validation.  Callers that
    need certainty check the answer.
    """
    if len(data) >= EXT2_SUPERBLOCK_OFFSET + 2:
        magic = struct.unpack_from("<H", data, EXT2_SUPERBLOCK_OFFSET + 0x38)[0]
        if magic == EXT2_MAGIC:
            return _ext_flavour(data)

    if len(data) >= 512 + 2 and data[510:512] == b"\x55\xaa":
        # FAT12/16/32 put the "FAT" marker in the boot sector at 0x36 (FAT16)
        # or 0x52 (FAT32).
        if _at(data, 0x36, 3) == b"FAT":
            return FileSystemKind.FAT
        if _at(data, 0x52, 3) == b"FAT":
            return FileSystemKind.FAT
        if _at(data, 0x03, 8) == b"EXFAT   ":
            return FileSystemKind.EXFAT
        if _at(data, 0x03, 8) == b"NTFS    ":
            return FileSystemKind.NTFS

    if _at(data, 0xFF6, 10) == b"SWAPSPACE2":
        return FileSystemKind.SWAP
    # A 4096-byte-block swap area puts the same signature one page in.
    if len(data) >= 0x1000 and _at(data, 0xFF6, 10) == b"SWAPSPACE2":
        return FileSystemKind.SWAP

    return FileSystemKind.UNKNOWN


def _ext_flavour(data: bytes) -> str:
    """Distinguish ext2/ext3/ext4 from the feature words.

    The magic is shared, so the features are what identify the revision:
    a journal means ext3 or better, extents or 64-bit block numbers mean ext4.
    The distinction is worth making because the three revisions need different
    growth handling, and the boot partition is deliberately plain ext2.
    """
    if len(data) < EXT2_SUPERBLOCK_OFFSET + 0x68:
        return FileSystemKind.EXT2
    incompat = struct.unpack_from("<I", data, EXT2_SUPERBLOCK_OFFSET + SB_FEATURE_INCOMPAT)[0]
    ro_compat = struct.unpack_from("<I", data, EXT2_SUPERBLOCK_OFFSET + SB_FEATURE_RO_COMPAT)[0]
    if incompat & (INCOMPAT_EXTENTS | INCOMPAT_64BIT):
        return FileSystemKind.EXT4
    if ro_compat & RO_COMPAT_HAS_JOURNAL:
        return FileSystemKind.EXT3
    return FileSystemKind.EXT2


def detect_partition(partition) -> str:
    """Probe a partition device and name its filesystem.

    A partition shorter than the probe window is read in full rather than
    rejected: a tiny partition is still a partition, it just cannot be ext.
    """
    want = min(PROBE_BYTES, partition.size)
    try:
        data = partition.read_at(0, want)
    except DeviceError:
        return FileSystemKind.UNKNOWN
    return detect(data)
