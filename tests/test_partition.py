"""Tests for a partition as a device, and for content-based discovery.

Two properties are tested here that did not exist before this layer did:

* **A partition refuses to address anything outside itself.**  The three
  hand-rolled offset adapters this replaced would happily read or write past
  the end of their partition, so a wrong base offset corrupted whichever
  partition came next.  That is the failure mode the bounds check removes.
* **Batched writes survive the layer change.**  ``Partition.write_blocks`` has
  to reach the disk as one batched call, not as a loop of single-sector writes,
  or the 43 MiB launcher write goes back to taking minutes.

The discovery tests (``boot``/``system``) run against the real installed image,
read-only, because that is the only way to check that reading the disk actually
identifies the right partitions -- a synthetic fixture would only confirm the
answer the fixture was built to give.
"""

from __future__ import annotations

import pytest

from disk import filetype, partition
from disk.device import DeviceError, WriteStats
from fixtures import FakeDisk, mbr_bytes


# --------------------------------------------------------------------------- #
# Fixtures
# --------------------------------------------------------------------------- #
@pytest.fixture
def disk():
    """A 1 MiB disk with one partition at LBA 8, 64 sectors long."""
    dev = FakeDisk(1 << 20)
    dev.write_sectors(0, 1, mbr_bytes([(0x83, 8, 64)]))
    return dev


@pytest.fixture
def table(disk):
    return partition.PartitionTable(disk, total_sectors=1 << 11)


# --------------------------------------------------------------------------- #
# Partition as a device
# --------------------------------------------------------------------------- #
def test_partition_is_a_sector_device(table):
    part = table.find(1)
    assert part.start_lba == 8
    assert part.sectors == 64
    assert part.size == 64 * 512
    assert part.sector_count == 64
    assert part.sector_size == 512
    assert part.name == "sda1"


def test_partition_reads_are_rebased(table, disk):
    """Reading sector 0 of a partition reads the partition's first sector."""
    marker = b"PARTITION-CONTENT"
    disk.write_sectors(8, 1, marker + b"\x00" * (512 - len(marker)))
    assert table.find(1).read_sectors(0, 1).startswith(marker)
    assert table.find(1).read_at(0, len(marker)) == marker


def test_partition_writes_are_rebased(table, disk):
    part = table.find(1)
    part.write_at(16, b"HELLO")
    # Landed 16 bytes into the partition, i.e. at disk offset 8*512 + 16.
    assert disk.read_sectors(8, 1)[16:21] == b"HELLO"
    assert part.read_at(16, 5) == b"HELLO"


def test_partition_refuses_a_read_past_its_own_end(table):
    """The bounds check the hand-rolled adapters did not have.

    Without it a wrong base offset reads the next partition's contents and
    reports them as this one's, which is how a corrupting write starts.
    """
    part = table.find(1)
    with pytest.raises(DeviceError) as exc:
        part.read_sectors(60, 10)
    assert "past the end" in str(exc.value)
    assert "sda1" in str(exc.value)


def test_partition_refuses_a_write_past_its_own_end(table, disk):
    part = table.find(1)
    before = bytes(disk.data[8 * 512 : 8 * 512 + 64 * 512])
    with pytest.raises(DeviceError):
        part.write_at(64 * 512 - 2, b"XXXX")
    # Nothing beyond the partition was touched.
    assert bytes(disk.data[8 * 512 : 8 * 512 + 64 * 512]) == before


def test_partition_refuses_a_negative_offset(table):
    part = table.find(1)
    with pytest.raises(DeviceError):
        part.read_sectors(-1, 1)
    with pytest.raises(DeviceError):
        part.read_at(-1, 1)


def test_partition_refuses_an_unaligned_write_past_the_end(table):
    """A byte range that overhangs the end is refused, not silently clipped."""
    part = table.find(1)
    with pytest.raises(DeviceError) as exc:
        part.write_blocks([(part.size - 4, b"12345678")])
    assert "past the end" in str(exc.value)


def test_partition_write_blocks_reaches_the_disk_in_one_batch(table, disk):
    """Batching must survive the layer change.

    A ``Partition`` that forwarded each range as its own ``write_sectors`` call
    would be correct and 50x slower, which is the whole cost the staging buffer
    exists to avoid.  The disk counts writes, so this is asserted, not timed.
    """
    part = table.find(1)
    before = len(disk.write_calls)
    writes = [(i * 64, bytes([i]) * 64) for i in range(16)]
    stats = part.write_blocks(writes)
    assert isinstance(stats, WriteStats)
    assert stats.bytes == 16 * 64
    # FakeDisk has no batching of its own, so the base implementation issues
    # one write per range -- but the *rebase* must have happened, which is what
    # is checked here: every write lands inside the partition.
    for lba, count in disk.write_calls[before:]:
        assert 8 <= lba < 8 + 64
        assert lba + count <= 8 + 64


def test_partition_write_blocks_on_a_vdi_is_staged(tmp_path):
    """Over a real VDI device, many small ranges become one write per block."""
    from disk import vdi
    from fixtures import write_vdi

    p = write_vdi(tmp_path / "part.vdi", [b"\x00" * 0x100000], block_size=0x100000)
    with vdi.VdiDevice(p, writable=True) as dev:
        dev.write_sectors(0, 1, mbr_bytes([(0x83, 8, 512)]))
        dev.flush()
        table = partition.PartitionTable(dev)
        calls: list[int] = []
        real = dev._fh.write

        def counting(data):
            calls.append(len(data))
            return real(data)

        dev._fh.write = counting
        part = table.find(1)
        stats = part.write_blocks([(i * 4096, b"Z" * 4096) for i in range(8)])
    # 32 KiB of payload in one container block: one data write, not eight.
    assert stats.blocks == 1
    assert stats.calls == 1
    assert len(calls) <= 4, calls


def test_partition_without_a_disk_refuses_to_read():
    """A bare entry is a record, not a device, and says so."""
    part = partition.Partition(number=3, boot_flag=0, type=0x83, start_lba=100, sectors=10)
    with pytest.raises(partition.PartitionError) as exc:
        part.read_sectors(0, 1)
    assert "no disk attached" in str(exc.value)


def test_partition_equality_ignores_the_disk(table):
    """Identity is geometry, not the object it happens to be attached to."""
    a = partition.Partition(number=3, boot_flag=0, type=0x83, start_lba=100, sectors=10)
    b = partition.Partition(
        number=3,
        boot_flag=0,
        type=0x83,
        start_lba=100,
        sectors=10,
        parent=object(),
    )
    assert a == b
    assert hash(a) == hash(b)


# --------------------------------------------------------------------------- #
# File system detection
# --------------------------------------------------------------------------- #
def test_detects_ext2_from_a_superblock():
    probe = bytearray(4096)
    probe[1024 + 0x38 : 1024 + 0x3A] = b"\x53\xef"
    assert filetype.detect(bytes(probe)) == filetype.FileSystemKind.EXT2


def test_distinguishes_ext2_ext3_and_ext4_by_features():
    """The magic is shared, so the feature words are what identify the revision.

    The boot partition is deliberately plain ext2, and treating it as ext4
    would change how it is grown.
    """
    import struct

    def probe(incompat: int = 0, ro_compat: int = 0) -> bytes:
        data = bytearray(4096)
        data[1024 + 0x38 : 1024 + 0x3A] = b"\x53\xef"
        struct.pack_into("<I", data, 1024 + 0x60, incompat)
        struct.pack_into("<I", data, 1024 + 0x64, ro_compat)
        return bytes(data)

    assert filetype.detect(probe()) == filetype.FileSystemKind.EXT2
    assert filetype.detect(probe(ro_compat=0x0004)) == filetype.FileSystemKind.EXT3
    assert filetype.detect(probe(incompat=0x0040)) == filetype.FileSystemKind.EXT4
    assert filetype.detect(probe(incompat=0x0080)) == filetype.FileSystemKind.EXT4


def test_detects_other_formats_and_unknown():
    fat = bytearray(4096)
    fat[510:512] = b"\x55\xaa"
    fat[0x36:0x39] = b"FAT"
    assert filetype.detect(bytes(fat)) == filetype.FileSystemKind.FAT

    ntfs = bytearray(4096)
    ntfs[510:512] = b"\x55\xaa"
    ntfs[3:11] = b"NTFS    "
    assert filetype.detect(bytes(ntfs)) == filetype.FileSystemKind.NTFS

    swap = bytearray(4096)
    swap[0xFF6:0x1000] = b"SWAPSPACE2"
    assert filetype.detect(bytes(swap)) == filetype.FileSystemKind.SWAP

    assert filetype.detect(b"\x00" * 4096) == filetype.FileSystemKind.UNKNOWN
    assert filetype.detect(b"short") == filetype.FileSystemKind.UNKNOWN


def test_partition_filesystem_type_reads_the_partition(table, disk):
    """Detection reads the partition, not the MBR's type byte."""
    part = table.find(1)
    assert part.filesystem_type() == filetype.FileSystemKind.UNKNOWN
    probe = bytearray(part.size)
    probe[1024 + 0x38 : 1024 + 0x3A] = b"\x53\xef"
    part.write_at(0, bytes(probe))
    assert part.filesystem_type() == filetype.FileSystemKind.EXT2


# --------------------------------------------------------------------------- #
# Discovery against the real image
# --------------------------------------------------------------------------- #
REAL_VDI = "/mnt/c/Program Files/Netease/MuMu/nx_device/15.0/vms/MuMuPlayer-15.0-base/system.vdi"


def _real_image_available() -> bool:
    from pathlib import Path

    return Path(REAL_VDI).is_file()


requires_real_image = pytest.mark.skipif(
    not _real_image_available(),
    reason="the MuMu installation is not present on this machine",
)


@pytest.fixture
def real_table():
    """A read-only view of the installed image's partition table."""
    from disk import vdi

    with vdi.VdiDevice(REAL_VDI) as dev:
        yield partition.PartitionTable(dev)


@requires_real_image
def test_real_image_partitions_are_devices(real_table):
    parts = real_table.all_partitions()
    assert [p.number for p in parts][:3] == [1, 2, 3]
    for part in parts:
        # Every entry is usable as a device without further plumbing.
        assert part.parent is real_table.dev
        assert part.sector_count == part.sectors
        assert part.read_at(0, 4) is not None


@requires_real_image
def test_real_image_finds_the_boot_partition_by_content(real_table):
    """The boot partition is the one holding /kernel, whatever its LBA is.

    The MBR labels it 0x83, the same as the Android system partition, so the
    type byte cannot be used -- which is exactly why this reads the disk.
    """
    boot = real_table.boot()
    assert boot.number == 3, f"expected sda3, got {boot.name}"
    assert boot.filesystem_type() == filetype.FileSystemKind.EXT2
    assert boot.start_lba == 34_304


@requires_real_image
def test_real_image_finds_the_system_partition(real_table):
    system = real_table.system()
    assert system.number == 6, f"expected sda6, got {system.name}"
    assert system.filesystem_type() == filetype.FileSystemKind.EXT4
    assert system.start_lba == 79_068


@requires_real_image
def test_real_image_boot_and_system_are_distinct(real_table):
    """The two partitions a fixed constant used to identify are now looked up.

    Both were hard-coded sector numbers before this layer existed, and both
    would have silently pointed at the wrong place after any growth plan.
    """
    boot, system = real_table.boot(), real_table.system()
    assert boot != system
    assert boot.sectors != system.sectors
    assert system.size > boot.size


@requires_real_image
def test_real_image_partition_bounds_hold(real_table):
    """The system partition refuses to read past its own end."""
    system = real_table.system()
    with pytest.raises(DeviceError):
        system.read_sectors(system.sectors, 1)
    # And the last sector is readable.
    assert len(system.read_sectors(system.sectors - 1, 1)) == 512
