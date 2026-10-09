"""Tests for the VDI layer: header parsing, sector access, the dirty cache.

This is the layer that owns the container format, so the tests are about two
things that cannot be recovered from once wrong:

* the header offsets, which are ``#pragma pack(1)`` and therefore *not* the
  obvious aligned layout.  Getting one wrong writes over a real header field;
* the dirty-page cache, which must merge rather than replace.  A buffer that
  started as zeros instead of being seeded with the block it covers erases
  whatever else shares that 1 MiB -- on the real image that destroyed an
  unrelated inode's extent tree.

Everything here runs against synthetic images built in ``conftest``, so the
suite never touches the installed emulator.  The real image is exercised
read-only in ``test_disk.py``.
"""

from __future__ import annotations

import struct

import pytest

from disk import vdi
from disk.device import DeviceError, WriteStats
from fixtures import build_vdi_bytes, write_vdi


# --------------------------------------------------------------------------- #
# Header
# --------------------------------------------------------------------------- #
def test_vdi_header_offsets_are_read_from_the_packed_layout():
    """Pin every offset against values cross-checked with ``vbox-img info``.

    The header is ``#pragma pack(1)`` in VirtualBox's ``VDICore.h``, so the
    64-bit ``cbDisk`` lands on an *unaligned* offset of 0x170.  Getting this
    wrong shifts every following field, which is why each one is asserted here
    rather than only the few the code happens to use today.

    The signature is a magic constant, not a checksum:
    ``vdiValidatePreHeader`` compares it for equality.
    """
    raw = bytearray(512)
    raw[0 : len(vdi.VDI_SIGNATURE)] = vdi.VDI_SIGNATURE
    struct.pack_into("<I", raw, vdi.OFF_MAGIC, vdi.VDI_IMAGE_SIGNATURE)
    struct.pack_into("<I", raw, vdi.OFF_VERSION, 0x00010001)
    struct.pack_into("<I", raw, vdi.OFF_CB_HEADER, vdi.HEADER_STRUCT_SIZE)
    struct.pack_into("<I", raw, vdi.OFF_TYPE, vdi.TYPE_DYNAMIC)
    struct.pack_into("<I", raw, vdi.OFF_FLAGS, 0)
    raw[vdi.OFF_COMMENT : vdi.OFF_COMMENT + 9] = b"a comment"
    struct.pack_into("<Q", raw, vdi.OFF_DISK_SIZE, 2463370240)
    struct.pack_into("<I", raw, vdi.OFF_BLOCKS, 0x100000)
    struct.pack_into("<I", raw, vdi.OFF_DATA, 0x200000)
    struct.pack_into("<I", raw, vdi.OFF_CB_SECTOR, 512)
    struct.pack_into("<I", raw, vdi.OFF_CB_BLOCK, 0x100000)
    struct.pack_into("<I", raw, vdi.OFF_CBLOCKS, 2350)
    struct.pack_into("<I", raw, vdi.OFF_CBLOCKS_ALLOC, 1789)

    h = vdi.VdiHeader.parse(bytes(raw))
    assert h.magic_ok
    assert h.version == 0x00010001
    assert h.vdi_type == vdi.TYPE_DYNAMIC
    assert h.flags == 0
    assert h.comment == "a comment"
    assert h.disk_size == 2463370240
    assert h.off_blocks == 0x100000
    assert h.off_data == 0x200000
    assert h.cb_block == 0x100000
    assert h.c_blocks == 2350
    assert h.c_blocks_allocated == 1789
    assert h.sector_size == 512


def test_vdi_header_offsets_match_virtualboxes_packed_struct():
    """The offsets themselves, derived from VDICore.h, must not drift.

    VDIPREHEADER is 72 bytes, then VDIHEADER1PLUS is packed:
    cbHeader, u32Type, fFlags, szComment[256], offBlocks, offData, ...
    An earlier version of this parser had u32Type/fFlags/szComment four bytes
    early, which shifted the comment by one field.
    """
    assert vdi.OFF_CB_HEADER == 0x48
    assert vdi.OFF_TYPE == 0x4C
    assert vdi.OFF_FLAGS == 0x50
    assert vdi.OFF_COMMENT == 0x54
    assert vdi.OFF_BLOCKS == 0x154
    assert vdi.OFF_DATA == 0x158
    assert vdi.OFF_DISK_SIZE == 0x170
    assert vdi.OFF_CB_BLOCK == 0x178
    assert vdi.OFF_CBLOCKS == 0x180
    assert vdi.OFF_CBLOCKS_ALLOC == 0x184
    assert vdi.OFF_CREATION_UUID == 0x188
    assert vdi.OFF_MODIFICATION_UUID == 0x198
    # sizeof(VDIHEADER1PLUS) = 400, so the struct ends at 72 + 400 = 472.
    assert vdi.HEADER_STRUCT_SIZE == 400
    assert 72 + vdi.HEADER_STRUCT_SIZE == 472


def test_vdi_rejects_a_computed_crc_in_the_signature_field():
    """VirtualBox compares the signature for equality; so must this parser.

    Accepting a CRC here would let through a header VirtualBox rejects, which
    is the opposite of what a validator is for.
    """
    import zlib

    raw = bytearray(512)
    raw[0 : len(vdi.VDI_SIGNATURE)] = vdi.VDI_SIGNATURE
    struct.pack_into("<I", raw, vdi.OFF_MAGIC, zlib.crc32(bytes(raw[0:64])) & 0xFFFFFFFF)
    struct.pack_into("<I", raw, vdi.OFF_VERSION, 0x00010001)
    struct.pack_into("<I", raw, vdi.OFF_CB_HEADER, vdi.HEADER_STRUCT_SIZE)
    struct.pack_into("<I", raw, vdi.OFF_CB_BLOCK, 0x100000)
    struct.pack_into("<I", raw, vdi.OFF_CBLOCKS, 10)
    with pytest.raises(vdi.VdiError) as exc:
        vdi.VdiHeader.parse(bytes(raw))
    assert "signature field" in str(exc.value)


def test_vdi_rejects_a_short_cbheader():
    """VirtualBox rejects cbHeader < sizeof(VDIHEADER1PLUS)."""
    raw = bytearray(512)
    raw[0 : len(vdi.VDI_SIGNATURE)] = vdi.VDI_SIGNATURE
    struct.pack_into("<I", raw, vdi.OFF_MAGIC, vdi.VDI_IMAGE_SIGNATURE)
    struct.pack_into("<I", raw, vdi.OFF_VERSION, 0x00010001)
    struct.pack_into("<I", raw, vdi.OFF_CB_HEADER, 100)
    struct.pack_into("<I", raw, vdi.OFF_CB_BLOCK, 0x100000)
    struct.pack_into("<I", raw, vdi.OFF_CBLOCKS, 10)
    with pytest.raises(vdi.VdiError) as exc:
        vdi.VdiHeader.parse(bytes(raw))
    assert "cbHeader" in str(exc.value)


def test_vdi_accepts_major_version_1_from_the_high_16_bits():
    """``VDI_GET_VERSION_MAJOR`` reads the high *16* bits, not the high 8.

    Reading the high 8 bits rejects 0x00010001, which is what every real image
    carries -- so this width is load-bearing, not cosmetic.
    """
    raw = bytearray(512)
    raw[0 : len(vdi.VDI_SIGNATURE)] = vdi.VDI_SIGNATURE
    struct.pack_into("<I", raw, vdi.OFF_MAGIC, vdi.VDI_IMAGE_SIGNATURE)
    struct.pack_into("<I", raw, vdi.OFF_VERSION, 0x00010001)
    struct.pack_into("<I", raw, vdi.OFF_CB_HEADER, vdi.HEADER_STRUCT_SIZE)
    struct.pack_into("<I", raw, vdi.OFF_CB_BLOCK, 0x100000)
    struct.pack_into("<I", raw, vdi.OFF_CBLOCKS, 10)
    assert vdi.VdiHeader.parse(bytes(raw)).version == 0x00010001

    # The legacy 2 is accepted; an unknown major is not.
    struct.pack_into("<I", raw, vdi.OFF_VERSION, 0x00000002)
    assert vdi.VdiHeader.parse(bytes(raw)).version == 2
    struct.pack_into("<I", raw, vdi.OFF_VERSION, 0x00030000)
    with pytest.raises(vdi.VdiError):
        vdi.VdiHeader.parse(bytes(raw))


def test_vdi_rejects_a_foreign_signature(tmp_path):
    raw = bytearray(512)
    raw[0:16] = b"not a vdi image!"
    with pytest.raises(vdi.VdiError) as exc:
        vdi.VdiHeader.parse(bytes(raw))
    assert "not a VDI image" in str(exc.value)


def test_vdi_rejects_a_truncated_header(tmp_path):
    with pytest.raises(vdi.VdiError) as exc:
        vdi.VdiHeader.parse(b"\x00" * 100)
    assert "512" in str(exc.value)


# --------------------------------------------------------------------------- #
# Sector access
# --------------------------------------------------------------------------- #
def test_vdi_read_sectors_round_trips(tmp_path):
    blocks = [bytes([i]) * 1024 for i in range(4)]
    p = write_vdi(tmp_path / "a.vdi", blocks)
    with vdi.VdiDevice(p) as v:
        assert v.header.c_blocks == 4
        assert v.header.disk_size == 4096
        assert v.sector_size == 512
        assert v.sector_count == 8
        for i in range(4):
            # Each 1024-byte logical block is two 512-byte sectors.
            assert v.read_sectors(i * 2, 2) == bytes([i]) * 1024


def test_vdi_read_at_agrees_with_read_sectors(tmp_path):
    """Byte access is derived from sector access, so they cannot disagree."""
    blocks = [b"\x00" * 1022 + b"AA", b"BBBB" + b"\x00" * 1020]
    p = write_vdi(tmp_path / "b.vdi", blocks)
    with vdi.VdiDevice(p) as v:
        # 2 bytes at the end of block 0, then 4 from the start of block 1.
        assert v.read_at(1022, 6) == b"AA" + b"BBBB"
        # The same bytes, read through the sector path directly.
        assert v.read_sectors(1, 2)[510:512] == b"AA"
        assert v.read_sectors(2, 1)[:4] == b"BBBB"


def test_vdi_unallocated_block_reads_as_zeros(tmp_path):
    p = write_vdi(tmp_path / "c.vdi", [b"x" * 1024, b"y" * 1024], bat=[0, vdi.BLOCK_FREE])
    with vdi.VdiDevice(p) as v:
        assert v.read_sectors(2, 2) == b"\x00" * 1024


def test_vdi_zero_block_sentinel_reads_as_zeros_and_is_not_allocated(tmp_path):
    """``BLOCK_ZERO`` (0xFFFFFFFE) is unallocated, like ``BLOCK_FREE``.

    VirtualBox's ``IS_VDI_IMAGE_BLOCK_ALLOCATED`` tests ``bp < ~1``, so both
    sentinels are "no storage".  Treating 0xFFFFFFFE as an ordinary block
    number would read uninitialised file contents as if they were data.
    """
    assert not vdi.is_allocated(vdi.BLOCK_FREE)
    assert not vdi.is_allocated(vdi.BLOCK_ZERO)
    assert vdi.is_allocated(0)

    p = write_vdi(
        tmp_path / "c2.vdi", [b"x" * 1024, b"SECRET" + b"\x00" * 1018], bat=[0, vdi.BLOCK_ZERO]
    )
    with vdi.VdiDevice(p) as v:
        assert v.read_sectors(2, 2) == b"\x00" * 1024
        with pytest.raises(vdi.VdiError):
            v.block_offset(1)


def test_vdi_read_only_refuses_writes(tmp_path):
    p = write_vdi(tmp_path / "d.vdi", [b"z" * 1024])
    with vdi.VdiDevice(p) as v:
        with pytest.raises(vdi.VdiError) as exc:
            v.write_sectors(0, 1, b"new")
        assert "read-only" in str(exc.value)


def test_vdi_write_then_read_back(tmp_path):
    p = write_vdi(tmp_path / "e.vdi", [b"a" * 1024, b"b" * 1024])
    with vdi.VdiDevice(p, writable=True) as v:
        v.write_at(0, b"HELLO")
        assert v.read_at(0, 5) == b"HELLO"
        # The rest of the block is preserved (read-modify-write).
        assert v.read_at(5, 3) == b"aaa"


def test_vdi_out_of_range_sector_is_an_error(tmp_path):
    """Out-of-range access raises VdiError, which is also a DeviceError.

    The layer reports its own type -- a caller that only knows about VDI wants
    VdiError -- while still being catchable as the generic device failure.
    """
    p = write_vdi(tmp_path / "f.vdi", [b"a" * 1024])
    with vdi.VdiDevice(p) as v:
        with pytest.raises(vdi.VdiError) as exc:
            v.read_sectors(99, 1)
        assert "past the end" in str(exc.value)
        with pytest.raises(vdi.VdiError):
            v.read_at(4096, 1)
        with pytest.raises(vdi.VdiError):
            v.read_sectors(-1, 1)


def test_vdi_refuses_to_shrink(tmp_path):
    p = write_vdi(tmp_path / "g.vdi", [b"a" * 1024] * 4)
    with vdi.VdiDevice(p, writable=True) as v:
        with pytest.raises(vdi.VdiError) as exc:
            v.set_disk_size(1024)
        assert "shrink" in str(exc.value)


def test_vdi_grows_within_the_reserved_bat_area(tmp_path):
    """Growing the BAT is fine while it still ends before the data area."""
    p = write_vdi(tmp_path / "h.vdi", [b"a" * 1024] * 2)
    with vdi.VdiDevice(p, writable=True) as v:
        before = v.header.c_blocks
        v.set_disk_size(10 * 1024)
        assert v.header.c_blocks == 10
        assert v.header.c_blocks > before
        assert v.header.disk_size == 10 * 1024
        # The original data is still readable where it was.
        assert v.read_at(0, 1) == b"a"
    with vdi.VdiDevice(p) as v:
        assert v.header.c_blocks == 10


def test_vdi_refuses_growth_that_would_overrun_the_data_area(tmp_path):
    """Packing the data area tight against the BAT makes growth impossible.

    The BAT cannot be extended without moving block 0, so this must be refused
    rather than overwriting live data.
    """
    raw = bytearray(build_vdi_bytes([b"a" * 1024] * 2))
    # Move the data area to immediately after a 128-entry BAT (512 bytes,
    # sector-aligned so the header's alignment guard is satisfied).
    struct.pack_into("<I", raw, vdi.OFF_CBLOCKS, 128)
    struct.pack_into("<I", raw, vdi.OFF_CBLOCKS_ALLOC, 2)
    struct.pack_into("<I", raw, vdi.OFF_DATA, 0x100000 + 128 * 4)
    p = tmp_path / "h2.vdi"
    p.write_bytes(bytes(raw))
    with vdi.VdiDevice(p, writable=True) as v:
        assert v.header.off_data == 0x100000 + 512
        with pytest.raises(vdi.VdiError) as exc:
            v.set_disk_size(256 * 1024)
        assert "BAT" in str(exc.value)


def test_vdi_write_bumps_the_modification_uuid(tmp_path):
    """VirtualBox compares this UUID to notice an image changed."""
    p = write_vdi(tmp_path / "i.vdi", [b"a" * 1024])
    with vdi.VdiDevice(p) as v:
        before = v.header.modification_uuid
    with vdi.VdiDevice(p, writable=True) as v:
        v.write_at(0, b"change")
    with vdi.VdiDevice(p) as v:
        assert v.header.modification_uuid != before


# --------------------------------------------------------------------------- #
# Dirty-page cache
# --------------------------------------------------------------------------- #
def test_write_blocks_coalesces_into_one_call_per_container_block(tmp_path):
    """The performance property, asserted by counting calls rather than timing.

    On the Windows 9p mount this runs against, a write costs ~17 ms whatever
    its size, so 200 separate 4 KiB writes took 3.4 s while one 800 KiB write
    took 0.03 s.  Counting positioned writes is the deterministic way to test
    that the staging still happens.
    """
    # 1 MiB container blocks, as a real image uses, so 200 writes fit in one.
    blocks = [b"\x00" * 0x100000]
    p = write_vdi(tmp_path / "j.vdi", blocks, block_size=0x100000)
    with vdi.VdiDevice(p, writable=True) as v:
        calls: list[int] = []
        real = v._fh.write

        def counting(data):
            calls.append(len(data))
            return real(data)

        v._fh.write = counting
        writes = [(i * 512, b"Q" * 512) for i in range(200)]
        stats = v.write_blocks(writes)

    # 200 512-byte writes span 100 KiB, well inside one 1 MiB container block.
    assert stats.bytes == 200 * 512, "bytes should count what was asked for"
    assert stats.blocks == 1
    assert stats.calls == 1
    # One whole 1 MiB block reached the file to carry 100 KiB of payload.
    assert stats.physical_bytes == 0x100000
    # One data write, plus the header and BAT rewrites that make it durable.
    assert len(calls) <= 4, calls


def test_write_blocks_preserves_neighbours_inside_the_container_block(tmp_path):
    """A mid-block write must not erase the bytes before it.

    This is the bug that destroyed an unrelated inode's extent tree on the real
    image: the staging buffer started as zeros, so writing back the whole 1 MiB
    wiped everything that shared the block with the file being written.
    """
    p = write_vdi(tmp_path / "k.vdi", [bytes(range(256)) * 4096], block_size=0x100000)
    with vdi.VdiDevice(p) as v:
        before = v.read_at(0, 0x100000)

    with vdi.VdiDevice(p, writable=True) as v:
        # Start 5000 bytes into the container block, well past the start.
        v.write_blocks([(5000, b"Z" * 100)])

    with vdi.VdiDevice(p) as v:
        after = v.read_at(0, 0x100000)
    assert after[:5000] == before[:5000], "bytes before the write were erased"
    assert after[5000:5100] == b"Z" * 100
    assert after[5100:] == before[5100:], "bytes after the write were erased"


def test_write_blocks_spans_two_container_blocks(tmp_path):
    """A write crossing a container block boundary is split, not truncated."""
    p = write_vdi(tmp_path / "l.vdi", [b"\x00" * 1024] * 6)
    with vdi.VdiDevice(p, writable=True) as v:
        assert v.header.cb_block == 1024  # small blocks keep the fixture cheap
        off = 1024 * 3 - 10
        v.write_blocks([(off, b"X" * 20)])
    with vdi.VdiDevice(p) as v:
        assert v.read_at(off, 20) == b"X" * 20


def test_write_blocks_allocates_storage_for_a_new_block(tmp_path):
    """Writing an unallocated logical block gives it storage, appended last."""
    p = write_vdi(tmp_path / "m.vdi", [b"a" * 1024, b"\x00" * 1024], bat=[0, vdi.BLOCK_FREE])
    with vdi.VdiDevice(p, writable=True) as v:
        assert v.header.c_blocks_allocated == 1
        v.write_blocks([(1024, b"NEWDATA" + b"\x00" * 1017)])
        assert v.header.c_blocks_allocated == 2
        # Appended after the highest block in use, so block 0 is untouched.
        assert v.read_at(0, 1) == b"a"
        assert v.read_at(1024, 7) == b"NEWDATA"
    with vdi.VdiDevice(p) as v:
        assert v.read_at(1024, 7) == b"NEWDATA"


def test_allocation_does_not_alias_a_free_bat_slot(tmp_path):
    """Allocating storage must not make two logical blocks share a file block.

    The real image has free BAT slots at 1..10 sitting *below* allocated ones,
    so this shape is not hypothetical.  The old code claimed the first free
    *slot*, then re-pointed the block being written at ``max(used)``, leaving
    both entries naming the same file block -- so writing one logical block
    silently overwrote the other's data.  Storage is now assigned to the block
    that was actually asked for, and the unrelated slot is left alone.
    """
    # Logical block 0 is free; logical block 1 maps to file block 0.
    p = write_vdi(tmp_path / "m2.vdi", [b"M" * 1024], bat=[vdi.BLOCK_FREE, 0])
    with vdi.VdiDevice(p) as v:
        assert v.read_at(1024, 1) == b"M"

    with vdi.VdiDevice(p, writable=True) as v:
        v.write_blocks([(0, b"NEW" + b"\x00" * 1021)])
        # The new storage is appended after the highest block in use, and the
        # untouched slot keeps its own mapping.
        assert v.bat[0] == 1, f"expected block 1, got {v.bat[0]}"
        assert v.bat[1] == 0, "the free slot was stolen by the new block"
        assert v.bat[0] != v.bat[1], "two logical blocks alias the same storage"

    with vdi.VdiDevice(p) as v:
        assert v.read_at(0, 3) == b"NEW"
        assert v.read_at(1024, 1) == b"M", "the neighbouring block was overwritten"


def test_write_blocks_refuses_a_range_past_the_end(tmp_path):
    p = write_vdi(tmp_path / "n.vdi", [b"a" * 1024])
    with vdi.VdiDevice(p, writable=True) as v:
        with pytest.raises(vdi.VdiError) as exc:
            v.write_blocks([(4096, b"x")])
        assert "past the end" in str(exc.value)


def test_cache_eviction_flushes_rather_than_losing_data(tmp_path):
    """A small cache must not drop writes; it flushes them early."""
    p = write_vdi(tmp_path / "o.vdi", [b"\x00" * 1024] * 40)
    with vdi.VdiDevice(p, writable=True, cache_blocks=2) as v:
        for i in range(40):
            v.write_blocks([(i * 1024, bytes([i]) * 1024)])
    with vdi.VdiDevice(p) as v:
        for i in range(40):
            assert v.read_at(i * 1024, 1) == bytes([i])


def test_flush_is_idempotent_and_reports_nothing_when_clean(tmp_path):
    p = write_vdi(tmp_path / "p.vdi", [b"a" * 1024])
    with vdi.VdiDevice(p, writable=True) as v:
        assert v.flush() == WriteStats()
        v.write_at(0, b"b")
        first = v.flush()
        assert first.calls == 1
        assert v.flush() == WriteStats()


def test_write_stats_accumulate(tmp_path):
    a = WriteStats(calls=1, bytes=100, blocks=1)
    b = WriteStats(calls=2, bytes=200, blocks=2)
    total = a + b
    assert (total.calls, total.bytes, total.blocks) == (3, 300, 3)
    assert bool(total) and not bool(WriteStats())


def test_sector_size_comes_from_the_header(tmp_path):
    """The device reports the header's sector size, not a hard-coded 512."""
    p = write_vdi(tmp_path / "q.vdi", [b"a" * 1024], sector_size=512)
    with vdi.VdiDevice(p) as v:
        assert v.sector_size == 512
    # A header that records something else is honoured rather than assumed.
    raw = bytearray(build_vdi_bytes([b"a" * 1024], sector_size=4096))
    p2 = tmp_path / "q2.vdi"
    p2.write_bytes(bytes(raw))
    with vdi.VdiDevice(p2) as v:
        assert v.sector_size == 4096


def test_a_device_error_is_a_vdi_error(tmp_path):
    """Callers can catch one thing for 'this device could not be used'."""
    assert issubclass(vdi.VdiError, DeviceError)


# --------------------------------------------------------------------------- #
# The clean-block cache
# --------------------------------------------------------------------------- #
def test_reads_within_one_block_cost_one_physical_read(tmp_path):
    """The regression that made the suite slow and inflated I/O by 1000x.

    The container's unit is 1 MiB but callers above address it one 4 KiB
    (or 1 KiB) block at a time.  Without a cache, every one of those calls
    re-reads the whole 1 MiB it lands in -- so reading a 12 MiB file pulled
    12.7 GB off the image and took 40 s through the Windows mount.
    """
    block = b"\x11" * (1 << 20)
    p = write_vdi(tmp_path / "cache.vdi", [block, b"\x22" * (1 << 20)], block_size=1 << 20)
    with vdi.VdiDevice(p) as v:
        # 64 reads of 4 KiB, all inside the first 1 MiB block.
        for i in range(64):
            assert v.read_at(i * 4096, 4096) == b"\x11" * 4096
        assert v.read_stats.calls == 1, (
            f"{v.read_stats.calls} physical reads for one container block"
        )


def test_a_hit_does_not_re_read_and_a_miss_does(tmp_path):
    """Crossing into the next container block is one more read, not a re-read."""
    p = write_vdi(
        tmp_path / "two.vdi",
        [b"\x11" * (1 << 20), b"\x22" * (1 << 20)],
        block_size=1 << 20,
    )
    with vdi.VdiDevice(p) as v:
        v.read_at(0, 16)
        assert v.read_stats.calls == 1
        v.read_at(32, 16)  # same block, cached
        assert v.read_stats.calls == 1
        v.read_at(1 << 20, 16)  # second block
        assert v.read_stats.calls == 2
        v.read_at(0, 16)  # back to the first
        assert v.read_stats.calls == 2


def test_the_clean_cache_is_bounded(tmp_path):
    """A pathological walk must not grow memory without limit."""
    blocks = [bytes([i]) * (1 << 20) for i in range(8)]
    p = write_vdi(tmp_path / "bounded.vdi", blocks, block_size=1 << 20)
    with vdi.VdiDevice(p, cache_blocks=2) as v:
        for i in range(8):
            v.read_at(i * (1 << 20), 16)
        assert len(v._clean) <= 2
        # And eviction is by recency: the last two touched remain.
        assert set(v._clean) == {6, 7}


def test_a_written_block_is_not_served_from_the_stale_clean_copy(tmp_path):
    """The cache must not hide a write -- reads and writes share the file."""
    p = write_vdi(tmp_path / "rw.vdi", [b"\x00" * (1 << 20)], block_size=1 << 20)
    with vdi.VdiDevice(p, writable=True) as v:
        assert v.read_at(0, 4) == b"\x00" * 4
        v.write_at(0, b"ABCD")
        assert v.read_at(0, 4) == b"ABCD"
        v.flush()
        assert v.read_at(0, 4) == b"ABCD"


def test_a_dirty_block_reads_as_the_staged_value(tmp_path):
    """Before a flush, the dirty buffer is the truth rather than the disk."""
    p = write_vdi(tmp_path / "dirty.vdi", [b"\x00" * (1 << 20)], block_size=1 << 20)
    with vdi.VdiDevice(p, writable=True) as v:
        v.write_at(4096, b"staged")
        v._clean.clear()  # force the fallback path to consult dirty
        assert v.read_at(4096, 6) == b"staged"


def test_read_stats_describe_what_was_pulled(tmp_path):
    p = write_vdi(tmp_path / "stats.vdi", [b"\x00" * (1 << 20)], block_size=1 << 20)
    with vdi.VdiDevice(p) as v:
        v.read_at(0, 16)
        stats = v.read_stats
        assert stats.calls == 1
        assert stats.physical_bytes == 1 << 20, "a whole container block per read"
