"""Tests for opening a disk image and the whole-stack round trip.

The decision this module makes is *which container* a file is, and getting it
wrong is not a visible failure: a VDI read as a raw disk yields a disk whose
first sector is a header, so every partition offset is wrong by the size of that
header.  The tests therefore concentrate on the refusal as much as the success.
"""

from __future__ import annotations

import struct

import pytest

from disk import image, vdi
from disk.device import DeviceError, WriteStats
from fixtures import build_vdi_bytes, mbr_bytes, write_vdi


# --------------------------------------------------------------------------- #
# Container detection
# --------------------------------------------------------------------------- #
def test_opens_a_vdi_by_its_contents(tmp_path):
    p = write_vdi(tmp_path / "a.vdi", [b"\x00" * 1024])
    with image.open_image(p) as disk:
        assert isinstance(disk, image.VdiDisk)
        assert disk.format == image.FORMAT_VDI
        assert disk.size == 1024


def test_opens_a_raw_image_that_has_a_partition_table(tmp_path):
    p = tmp_path / "b.img"
    raw = bytearray(1 << 20)
    raw[0:512] = mbr_bytes([(0x83, 8, 64)])
    p.write_bytes(bytes(raw))
    with image.open_image(p) as disk:
        assert isinstance(disk, image.RawDisk)
        assert disk.format == image.FORMAT_RAW
        assert disk.partition(1).start_lba == 8


def test_refuses_a_file_that_is_neither(tmp_path):
    """A random file is reported, not mounted as a flat disk.

    Guessing "raw" here is how a wrong edit starts: the caller would get a disk
    that reads successfully and is off by whatever the real container's header
    is.
    """
    p = tmp_path / "junk.bin"
    p.write_bytes(b"this is not a disk image at all" * 100)
    with pytest.raises(image.ImageError) as exc:
        image.open_image(p)
    assert "not a VDI" in str(exc.value)
    assert "format='raw'" in str(exc.value)


def test_a_vdi_with_a_broken_header_is_refused_not_downgraded(tmp_path):
    """The signature says VDI, so a bad header is an error, not a raw disk."""
    raw = bytearray(build_vdi_bytes([b"\x00" * 1024]))
    # Corrupt a field the parser validates.
    struct.pack_into("<I", raw, vdi.OFF_VERSION, 0x00090000)
    p = tmp_path / "c.vdi"
    p.write_bytes(bytes(raw))
    with pytest.raises(image.ImageError) as exc:
        image.open_image(p)
    # The message names the container, so the failure is not mistaken for a
    # file that simply is not an image at all.
    assert "as a VDI" in str(exc.value)
    assert "unsupported VDI version" in str(exc.value)


def test_format_can_be_forced(tmp_path):
    """A caller that knows the container can skip detection."""
    p = write_vdi(tmp_path / "d.vdi", [b"\x00" * 1024])
    with image.open_image(p, format=image.FORMAT_VDI) as disk:
        assert disk.format == image.FORMAT_VDI
    # Forcing raw on a VDI is allowed and does exactly what it says: the
    # header becomes sector 0.
    with image.open_image(p, format=image.FORMAT_RAW) as disk:
        assert disk.format == image.FORMAT_RAW
        assert disk.read_sectors(0, 1).startswith(vdi.VDI_SIGNATURE)


def test_an_unknown_format_is_rejected(tmp_path):
    p = write_vdi(tmp_path / "e.vdi", [b"\x00" * 1024])
    with pytest.raises(image.ImageError) as exc:
        image.open_image(p, format="qcow2")
    assert "unknown image format" in str(exc.value)


def test_a_missing_file_is_reported(tmp_path):
    with pytest.raises(image.ImageError) as exc:
        image.open_image(tmp_path / "nope.vdi")
    assert "no such image" in str(exc.value)


# --------------------------------------------------------------------------- #
# The disk as a device
# --------------------------------------------------------------------------- #
def test_disk_forwards_sector_access_to_the_container(tmp_path):
    p = write_vdi(tmp_path / "f.vdi", [b"ABCD" * 256])
    with image.open_image(p) as disk:
        assert disk.read_sectors(0, 1)[:4] == b"ABCD"
        assert disk.read_at(2, 4) == b"CDAB"


def test_disk_write_blocks_keeps_batching(tmp_path):
    """The whole-stack property: batching must not be lost at this layer.

    If ``Disk`` used the base implementation, every range would become its own
    positioned write and the 43 MiB launcher write would take minutes again.
    """
    p = write_vdi(tmp_path / "g.vdi", [b"\x00" * 0x100000], block_size=0x100000)
    with image.open_image(p, writable=True) as disk:
        assert isinstance(disk, image.VdiDisk)
        calls: list[int] = []
        real = disk.vdi._fh.write

        def counting(data):
            calls.append(len(data))
            return real(data)

        disk.vdi._fh.write = counting
        stats = disk.write_blocks([(i * 4096, b"Q" * 4096) for i in range(16)])
    assert isinstance(stats, WriteStats)
    assert stats.calls == 1, "batching was lost at the Disk layer"
    assert len(calls) <= 4, calls


def test_disk_partitions_are_cached(tmp_path):
    p = tmp_path / "h.img"
    raw = bytearray(1 << 20)
    raw[0:512] = mbr_bytes([(0x83, 8, 64)])
    p.write_bytes(bytes(raw))
    with image.open_image(p) as disk:
        first = disk.partitions()
        assert disk.partitions() is first
        assert disk.partitions(refresh=True) is not first


def test_disk_close_is_safe_to_call_twice(tmp_path):
    p = write_vdi(tmp_path / "i.vdi", [b"\x00" * 1024])
    disk = image.open_image(p)
    disk.close()
    disk.close()


# --------------------------------------------------------------------------- #
# End to end: an ext2 filesystem inside a partition inside a VDI
# --------------------------------------------------------------------------- #
def test_an_ext2_filesystem_round_trips_through_the_whole_stack(tmp_path):
    """Read a file out of an ext2 image inside a VDI through every layer.

    This is the test that would catch a rebasing mistake anywhere in the stack:
    the filesystem is written at a known partition offset, so a wrong base in
    the VDI, image or partition layer produces a superblock that does not parse
    rather than a wrong answer.
    """
    from test_disk import build_ext2_bytes

    fs = build_ext2_bytes(
        block_size=1024,
        nblocks=4096,
        files={"a.txt": b"A" * 400, "kernel": b"K" * 1234},
    )
    assert len(fs) == 4096 * 1024

    part_lba = 8
    # One VDI container block of 1 MiB is too small for 4 MiB of filesystem, so
    # use 1 MiB blocks and enough of them.
    n_blocks = (part_lba * 512 + len(fs) + 0x100000 - 1) // 0x100000
    blocks = [b"\x00" * 0x100000 for _ in range(n_blocks)]
    mbr = mbr_bytes([(0x83, part_lba, len(fs) // 512)])
    blocks[0] = mbr + b"\x00" * (0x100000 - 512)
    p = write_vdi(tmp_path / "full.vdi", blocks, block_size=0x100000)

    # Lay the filesystem down through the partition device.
    with image.open_image(p, writable=True) as disk:
        part = disk.partition(1)
        part.write_at(0, fs)
        disk.flush()

    # Read it back through the same stack.
    with image.open_image(p) as disk:
        from disk import extfs

        part = disk.partition(1)
        assert part.filesystem_type() == "ext2"
        mounted = extfs.Ext2(part)
        assert mounted.read_path("/a.txt") == b"A" * 400
        assert mounted.read_path("/kernel") == b"K" * 1234
        assert {e.name for e in mounted.list_dir(mounted.read_inode(2))} >= {
            "a.txt",
            "kernel",
        }


def test_a_partition_inside_a_vdi_refuses_to_overrun_itself(tmp_path):
    """Bounds hold across the whole stack, not just at the fake-disk level.

    The partition's own extent is what limits it, so a read one sector past its
    end must fail even though the VDI is far larger than the partition -- the
    container having room is not permission to use it.
    """
    blocks = [b"\x00" * 0x100000 for _ in range(2)]
    blocks[0] = mbr_bytes([(0x83, 8, 64)]) + b"\x00" * (0x100000 - 512)
    p = write_vdi(tmp_path / "j.vdi", blocks, block_size=0x100000)

    with image.open_image(p, writable=True) as disk:
        part = disk.partition(1)
        assert part.sectors == 64
        # Well inside the 2 MiB container, well past the 32 KiB partition.
        with pytest.raises(DeviceError) as exc:
            part.read_sectors(64, 1)
        assert "past the end" in str(exc.value)
        # The last sector of the partition is still readable.
        assert len(part.read_sectors(63, 1)) == 512
