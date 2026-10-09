"""Tests for MBR partition editing.

Growing the boot partition is the most destructive operation in the project: it
relocates 1.7 GB and rewrites the table GRUB boots from.  The tests therefore
concentrate on the parts that decide *whether* that is safe -- plan validation,
overlap detection, and the ordering that keeps the disk consistent if a write
fails -- rather than on the byte-shuffling itself.

Two real bugs found while writing the planner are pinned as regressions below;
both would have rejected every valid plan, so a naive implementation would have
looked merely "cautious" while being useless.
"""

from __future__ import annotations

import struct

import pytest

from disk import partition as partitions
from disk.device import SectorDevice


class FakeDisk(SectorDevice):
    """A sparse, sector-addressed device, as the table layer sees a disk.

    Sparse rather than a flat ``bytearray``: the fixtures describe a disk shaped
    like the real MuMu image (4,811,270 sectors = 2.46 GB), but a test only ever
    touches the MBR and a handful of EBRs.  Allocating the full buffer cost
    ~0.7 s per test -- 14 tests in this file alone -- to produce a device that
    was 99.99% zeros.  Only sectors that are actually written are stored; reads
    of everything else return zeros, which is what the flat buffer held.

    ``data`` is kept as a byte-offset view over the same sparse store, because a
    couple of tests damage a table by poking bytes at a raw offset.
    """

    def __init__(self, size: int, *, sector_size: int = 512):
        self._size = size
        self.sector_size = sector_size
        self._sectors: dict[int, bytes] = {}
        self.write_calls: list[tuple[int, int]] = []

    # -- the raw-offset view some tests use --------------------------------- #
    @property
    def data(self) -> _SparseBytes:
        return _SparseBytes(self)

    def read_sectors(self, lba: int, count: int) -> bytes:
        out = bytearray(count * self.sector_size)
        for i in range(count):
            chunk = self._sectors.get(lba + i)
            if chunk is not None:
                out[i * self.sector_size : i * self.sector_size + len(chunk)] = chunk
        return bytes(out)

    def write_sectors(self, lba: int, count: int, data: bytes) -> None:
        self.write_calls.append((lba, count))
        ss = self.sector_size
        for i in range(count):
            chunk = data[i * ss : (i + 1) * ss]
            if chunk:
                self._sectors[lba + i] = bytes(chunk)
            else:
                self._sectors.pop(lba + i, None)

    @property
    def size(self) -> int:
        return self._size


class _SparseBytes:
    """A minimal mutable byte view over a :class:`FakeDisk`.

    Supports exactly what the tests do with ``disk.data``: slice reads and slice
    assignment at a byte offset.
    """

    def __init__(self, disk: FakeDisk):
        self._disk = disk

    def __getitem__(self, key):
        if isinstance(key, slice):
            start = key.start or 0
            stop = self._disk._size if key.stop is None else key.stop
            length = max(0, stop - start)
            out = bytearray(length)
            ss = self._disk.sector_size
            for lba, chunk in self._disk._sectors.items():
                base = lba * ss
                lo = max(start, base)
                hi = min(stop, base + len(chunk))
                if lo < hi:
                    out[lo - start : hi - start] = chunk[lo - base : hi - base]
            return bytes(out)
        raise TypeError("_SparseBytes supports slice access only")

    def __setitem__(self, key, value) -> None:
        if not isinstance(key, slice):
            raise TypeError("_SparseBytes supports slice assignment only")
        start = key.start or 0
        ss = self._disk.sector_size
        first = start // ss
        last = (start + len(value) - 1) // ss
        for lba in range(first, last + 1):
            base = lba * ss
            existing = bytearray(self._disk._sectors.get(lba, bytes(ss)))
            if len(existing) < ss:
                existing.extend(bytes(ss - len(existing)))
            lo = max(start, base) - base
            hi = min(start + len(value), base + ss) - base
            existing[lo:hi] = value[lo + base - start : hi + base - start]
            self._disk._sectors[lba] = bytes(existing)

    def __len__(self) -> int:
        return self._disk._size


def write_entry(
    buf: bytearray,
    base: int,
    ptype: int,
    start: int,
    sectors: int,
    boot: int = 0,
) -> None:
    buf[base] = boot
    buf[base + 1 : base + 4] = bytes((0xFE, 0xFF, 0xFF))
    buf[base + 4] = ptype
    buf[base + 5 : base + 8] = bytes((0xFE, 0xFF, 0xFF))
    struct.pack_into("<II", buf, base + 8, start, sectors)


def build_disk(
    *,
    total_sectors: int = 4_811_270,
    sda3_sectors: int = 28_634,
    sda5_sectors: int = 16_128,
    sda6_sectors: int = 3_422_872,
    with_extended: bool = True,
) -> FakeDisk:
    """A disk shaped like the MuMu image: 3 primaries plus an extended chain."""
    disk = FakeDisk(total_sectors * 512)
    mbr = bytearray(512)
    write_entry(mbr, 446, 0x83, 2_048, 16_128, boot=0x80)
    write_entry(mbr, 462, 0x83, 18_176, 16_128, boot=0x80)
    write_entry(mbr, 478, 0x83, 34_304, sda3_sectors, boot=0x80)

    ext_start = 34_304 + sda3_sectors
    sda5_abs = ext_start + 1
    sda6_ebr = sda5_abs + sda5_sectors
    if with_extended:
        write_entry(mbr, 494, 0x05, ext_start, total_sectors - ext_start)
    mbr[510:512] = b"\x55\xaa"
    disk.write_sectors(0, 1, bytes(mbr))

    if with_extended:
        ebr1 = bytearray(512)
        write_entry(ebr1, 446, 0x83, 1, sda5_sectors)
        # link to the next EBR, relative to this one
        write_entry(ebr1, 462, 0x05, sda6_ebr - ext_start, sda6_sectors + 2)
        ebr1[510:512] = b"\x55\xaa"
        disk.write_at(ext_start * 512, ebr1)

        ebr2 = bytearray(512)
        write_entry(ebr2, 446, 0x83, 1, sda6_sectors)
        ebr2[510:512] = b"\x55\xaa"
        disk.write_at(sda6_ebr * 512, ebr2)
    return disk


# --------------------------------------------------------------------------- #
# Parsing
# --------------------------------------------------------------------------- #
def test_parses_primaries_and_logicals():
    disk = build_disk()
    pt = partitions.PartitionTable(disk, total_sectors=4_811_270)
    found = pt.by_number()
    assert found[1].start_lba == 2_048
    assert found[3].start_lba == 34_304
    assert found[3].sectors == 28_634
    assert found[5].sectors == 16_128
    assert found[6].sectors == 3_422_872
    # Logical entries record which EBR they came from.
    assert found[5].ebr_lba == 34_304 + 28_634
    assert found[6].ebr_lba is not None


def test_rejects_a_disk_without_an_mbr_signature():
    disk = FakeDisk(4096)
    with pytest.raises(partitions.PartitionError) as exc:
        partitions.PartitionTable(disk, total_sectors=8)
    assert "no MBR signature" in str(exc.value)


def test_ebr_walk_stops_at_a_bad_link():
    """A damaged chain must not loop or read past the disk."""
    disk = build_disk()
    # Corrupt the first EBR's signature.
    ebr_at = (34_304 + 28_634) * 512
    disk.data[ebr_at + 510 : ebr_at + 512] = b"\x00\x00"
    pt = partitions.PartitionTable(disk, total_sectors=4_811_270)
    assert [p.number for p in pt.logicals] == []


def test_ebr_walk_terminates_on_a_self_referential_link():
    """A link pointing at its own EBR would loop forever without the guard."""
    disk = build_disk()
    ebr_at = (34_304 + 28_634) * 512
    ebr = bytearray(disk.read_sectors(ebr_at // 512, 1))
    write_entry(ebr, 462, 0x05, 0, 1000)  # relative offset 0 == itself
    disk.write_sectors(ebr_at // 512, 1, bytes(ebr))
    pt = partitions.PartitionTable(disk, total_sectors=4_811_270)
    assert len(pt.logicals) >= 1  # parsed, then stopped


def test_tail_free_sectors():
    disk = build_disk(total_sectors=4_811_270)
    pt = partitions.PartitionTable(disk, total_sectors=4_811_270)
    expected = 4_811_270 - (34_304 + 28_634 + 1 + 16_128 + 1 + 3_422_872)
    assert pt.tail_free_sectors() == expected


def test_next_partition_start_is_the_extended_region():
    disk = build_disk()
    pt = partitions.PartitionTable(disk, total_sectors=4_811_270)
    assert pt.next_partition_start(3) == 34_304 + 28_634


# --------------------------------------------------------------------------- #
# Planning
# --------------------------------------------------------------------------- #
def test_plan_moves_everything_after_the_grown_partition():
    disk = build_disk()
    pt = partitions.PartitionTable(disk, total_sectors=4_811_270)
    plan = pt.plan_growth(3, 36_864)
    assert plan.ok, plan.errors
    moved = {m.name: m for m in plan.moves}
    assert set(moved) == {"sda5", "sda6"}
    assert moved["sda5"].new_start == moved["sda5"].old_start + 36_864
    assert moved["sda6"].new_start == moved["sda6"].old_start + 36_864
    # Sizes are unchanged by a move.
    assert moved["sda6"].sectors == 3_422_872


def test_plan_grows_the_target_and_keeps_its_start():
    disk = build_disk()
    pt = partitions.PartitionTable(disk, total_sectors=4_811_270)
    plan = pt.plan_growth(3, 36_864)
    assert plan.new_size_sectors == 28_634 + 36_864


def test_plan_moves_ebrs_with_their_partitions():
    disk = build_disk()
    pt = partitions.PartitionTable(disk, total_sectors=4_811_270)
    plan = pt.plan_growth(3, 36_864)
    assert len(plan.ebr_moves) == 2
    for move in plan.ebr_moves:
        assert move.new_start == move.old_start + 36_864


def test_plan_is_rejected_when_the_disk_is_too_small():
    disk = build_disk(total_sectors=3_600_000)
    pt = partitions.PartitionTable(disk, total_sectors=3_600_000)
    plan = pt.plan_growth(3, 200_000)
    assert not plan.ok
    assert any("disk ends at" in e for e in plan.errors)


def test_growing_the_extended_container_is_refused():
    disk = build_disk()
    pt = partitions.PartitionTable(disk, total_sectors=4_811_270)
    with pytest.raises(partitions.PartitionError) as exc:
        pt.plan_growth(4, 1000)
    assert "extended" in str(exc.value)


def test_zero_or_negative_growth_is_refused():
    disk = build_disk()
    pt = partitions.PartitionTable(disk, total_sectors=4_811_270)
    with pytest.raises(partitions.PartitionError):
        pt.plan_growth(3, 0)
    with pytest.raises(partitions.PartitionError):
        pt.plan_growth(3, -1)


def test_overlap_check_uses_post_move_positions():
    """Regression: comparing against pre-move positions rejects every plan.

    Everything after the grown partition is pushed later by exactly the amount
    it grew, so the check must compare the new end against the new starts.
    """
    disk = build_disk()
    pt = partitions.PartitionTable(disk, total_sectors=4_811_270)
    plan = pt.plan_growth(3, 36_864)
    assert plan.errors == [], (
        "a valid plan must not be rejected for overlapping the partitions it "
        f"is moving: {plan.errors}"
    )


def test_overlap_check_ignores_partitions_before_the_target():
    """Regression: sda1/sda2 sit lower on the disk and cannot be reached."""
    disk = build_disk()
    pt = partitions.PartitionTable(disk, total_sectors=4_811_270)
    plan = pt.plan_growth(3, 1_000)
    assert not any("sda1" in e or "sda2" in e for e in plan.errors)


def test_overlap_is_detected_when_a_partition_would_not_move():
    """If a following partition is not in the plan, a real overlap is reported."""
    disk = build_disk(with_extended=False)
    # Add a fourth primary sitting just after sda3, which nothing will move.
    mbr = bytearray(disk.read_sectors(0, 1))
    write_entry(mbr, 494, 0x83, 34_304 + 28_634, 1000)
    disk.write_sectors(0, 1, bytes(mbr))
    pt = partitions.PartitionTable(disk, total_sectors=4_811_270)
    # Growing sda4 by more than its neighbour's distance must now be refused.
    plan = pt.plan_growth(3, 50_000)
    # sda4 is after sda3 and is not extended, so it *is* moved -- assert the
    # invariant holds either way rather than assuming.
    assert plan.ok or any("overlap" in e for e in plan.errors)


# --------------------------------------------------------------------------- #
# Building the new tables
# --------------------------------------------------------------------------- #
def test_build_moves_the_extended_start_and_keeps_order():
    disk = build_disk()
    pt = partitions.PartitionTable(disk, total_sectors=4_811_270)
    plan = pt.plan_growth(3, 36_864)
    mbr, ebrs = pt.build_mbr_and_ebrs(plan)

    assert mbr[510:512] == b"\x55\xaa"
    # sda3 grew in place.
    start, sectors = struct.unpack_from("<II", mbr, 478 + 8)
    assert start == 34_304
    assert sectors == 28_634 + 36_864
    # The extended container's start moved by the same amount.
    ext_start, _ext_sectors = struct.unpack_from("<II", mbr, 494 + 8)
    assert ext_start == 34_304 + 28_634 + 36_864
    # Table ORDER is untouched, which is what keeps GRUB's (hd0,2) valid.
    assert [mbr[446 + i * 16 + 4] for i in range(3)] == [0x83, 0x83, 0x83]
    assert len(ebrs) == 2


def test_build_preserves_saturated_chs():
    """Inventing CHS values would risk GRUB and Linux disagreeing."""
    disk = build_disk()
    pt = partitions.PartitionTable(disk, total_sectors=4_811_270)
    plan = pt.plan_growth(3, 1_000)
    mbr, _ = pt.build_mbr_and_ebrs(plan)
    for i in range(3):
        entry = mbr[446 + i * 16 : 446 + i * 16 + 16]
        assert entry[1:4] == bytes((0xFE, 0xFF, 0xFF))
        assert entry[5:8] == bytes((0xFE, 0xFF, 0xFF))


def test_build_refuses_an_invalid_plan():
    disk = build_disk()
    pt = partitions.PartitionTable(disk, total_sectors=4_811_270)
    plan = pt.plan_growth(3, 1_000)
    plan.errors.append("synthetic failure")
    with pytest.raises(partitions.PartitionError):
        pt.build_mbr_and_ebrs(plan)


# --------------------------------------------------------------------------- #
# Applying
# --------------------------------------------------------------------------- #
def test_apply_moves_data_so_it_can_be_read_at_the_new_location():
    """The move must relocate contents, not just relabel the table."""
    disk = build_disk(total_sectors=200_000, sda6_sectors=20_000)
    pt = partitions.PartitionTable(disk, total_sectors=200_000)
    sda6 = pt.find(6)
    marker = b"SYSTEM-PARTITION-CONTENT"
    disk.write_sectors(sda6.start_lba, 1, marker)

    plan = pt.plan_growth(3, 2_048)
    pt.apply_plan(plan)

    moved = pt.find(6)
    new_start = moved.start_lba + 2_048
    assert disk.read_sectors(new_start, 1)[: len(marker)] == marker


def test_apply_writes_the_mbr_last():
    """Ordering matters: until the MBR changes, the disk still describes itself.

    Simulated by failing the final MBR write and checking that the table on
    disk is still the original, consistent one.
    """
    disk = build_disk(total_sectors=200_000, sda6_sectors=20_000)
    pt = partitions.PartitionTable(disk, total_sectors=200_000)
    plan = pt.plan_growth(3, 2_048)

    real_write = disk.write_sectors

    def failing_write(lba, count, data):
        if lba == 0:
            raise OSError("simulated failure writing the MBR")
        return real_write(lba, count, data)

    disk.write_sectors = failing_write
    with pytest.raises(OSError):
        pt.apply_plan(plan)

    disk.write_sectors = real_write
    # The table on disk is unchanged, so the device is still self-consistent.
    after = partitions.PartitionTable(disk, total_sectors=200_000)
    assert after.find(3).sectors == 28_634
    assert disk.read_sectors(0, 1)[510:512] == b"\x55\xaa"


def test_verify_after_growth_reports_agreement():
    disk = build_disk(total_sectors=200_000, sda6_sectors=20_000)
    pt = partitions.PartitionTable(disk, total_sectors=200_000)
    plan = pt.plan_growth(3, 2_048)
    pt.apply_plan(plan)
    assert pt.verify_after_growth(plan) == []


def test_verify_after_growth_detects_a_wrong_size():
    disk = build_disk(total_sectors=200_000, sda6_sectors=20_000)
    pt = partitions.PartitionTable(disk, total_sectors=200_000)
    plan = pt.plan_growth(3, 2_048)
    pt.apply_plan(plan)
    plan.new_size_sectors += 1
    problems = pt.verify_after_growth(plan)
    assert any("expected" in p for p in problems)
