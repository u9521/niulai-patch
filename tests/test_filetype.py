"""Tests for filesystem detection.

The MBR's type byte is a hint, and MuMu's image shows why it is not enough:
the 14 MiB boot partition and the 1.6 GiB Android system partition are both
labelled ``0x83``.  Anything that needs to tell them apart has to read them, so
the detection here is what makes content-based partition lookup possible.
"""

from __future__ import annotations

import struct

from disk import filetype


def ext_probe(*, incompat: int = 0, ro_compat: int = 0, magic: int = 0xEF53) -> bytes:
    data = bytearray(4096)
    struct.pack_into("<H", data, 1024 + 0x38, magic)
    struct.pack_into("<I", data, 1024 + 0x60, incompat)
    struct.pack_into("<I", data, 1024 + 0x64, ro_compat)
    return bytes(data)


def test_detects_ext2_from_the_superblock_magic():
    assert filetype.detect(ext_probe()) == filetype.FileSystemKind.EXT2


def test_distinguishes_ext2_ext3_and_ext4_by_features():
    """The magic is shared, so the feature words identify the revision.

    The boot partition is deliberately plain ext2; reporting it as ext4 would
    change how it is grown.
    """
    assert filetype.detect(ext_probe()) == filetype.FileSystemKind.EXT2
    assert (
        filetype.detect(ext_probe(ro_compat=filetype.RO_COMPAT_HAS_JOURNAL))
        == filetype.FileSystemKind.EXT3
    )
    assert (
        filetype.detect(ext_probe(incompat=filetype.INCOMPAT_EXTENTS))
        == filetype.FileSystemKind.EXT4
    )
    assert (
        filetype.detect(ext_probe(incompat=filetype.INCOMPAT_64BIT)) == filetype.FileSystemKind.EXT4
    )


def test_a_wrong_magic_is_not_ext():
    assert filetype.detect(ext_probe(magic=0x1234)) == filetype.FileSystemKind.UNKNOWN


def test_detects_fat_exfat_and_ntfs():
    fat16 = bytearray(4096)
    fat16[510:512] = b"\x55\xaa"
    fat16[0x36:0x39] = b"FAT"
    assert filetype.detect(bytes(fat16)) == filetype.FileSystemKind.FAT

    fat32 = bytearray(4096)
    fat32[510:512] = b"\x55\xaa"
    fat32[0x52:0x55] = b"FAT"
    assert filetype.detect(bytes(fat32)) == filetype.FileSystemKind.FAT

    exfat = bytearray(4096)
    exfat[510:512] = b"\x55\xaa"
    exfat[3:11] = b"EXFAT   "
    assert filetype.detect(bytes(exfat)) == filetype.FileSystemKind.EXFAT

    ntfs = bytearray(4096)
    ntfs[510:512] = b"\x55\xaa"
    ntfs[3:11] = b"NTFS    "
    assert filetype.detect(bytes(ntfs)) == filetype.FileSystemKind.NTFS


def test_detects_swap():
    swap = bytearray(4096)
    swap[0xFF6:0x1000] = b"SWAPSPACE2"
    assert filetype.detect(bytes(swap)) == filetype.FileSystemKind.SWAP


def test_unknown_for_zeros_and_for_a_short_probe():
    """A question, not a validation: an unrecognised blob is just unknown."""
    assert filetype.detect(b"\x00" * 4096) == filetype.FileSystemKind.UNKNOWN
    assert filetype.detect(b"") == filetype.FileSystemKind.UNKNOWN
    assert filetype.detect(b"short") == filetype.FileSystemKind.UNKNOWN


def test_ext_any_covers_the_three_variants():
    assert filetype.FileSystemKind.EXT2 in filetype.FileSystemKind.EXT_ANY
    assert filetype.FileSystemKind.EXT3 in filetype.FileSystemKind.EXT_ANY
    assert filetype.FileSystemKind.EXT4 in filetype.FileSystemKind.EXT_ANY
    assert filetype.FileSystemKind.FAT not in filetype.FileSystemKind.EXT_ANY


def test_detects_a_partition_by_reading_it():
    """``detect_partition`` probes a device rather than trusting its type."""
    from fixtures import FakeDisk

    dev = FakeDisk(64 * 512)
    dev.write_sectors(0, 1, ext_probe()[:512])
    # The superblock lives at byte 1024, which is sector 2.
    dev.write_sectors(2, 1, ext_probe()[1024:1536])
    from disk.partition import Partition

    part = Partition(number=1, boot_flag=0, type=0x83, start_lba=0, sectors=64, parent=dev)
    assert filetype.detect_partition(part) == filetype.FileSystemKind.EXT2


def test_detect_partition_reports_unknown_for_an_unreadable_partition():
    """A partition with no disk is unknown, not an exception."""
    from disk.partition import Partition

    part = Partition(number=1, boot_flag=0, type=0x83, start_lba=0, sectors=64)
    assert filetype.detect_partition(part) == filetype.FileSystemKind.UNKNOWN
