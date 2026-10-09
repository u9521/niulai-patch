"""Tests for the boot partition: the four files GRUB reads, and how they travel.

Everything here is about a 14 MiB partition holding the kernel, two ramdisks and
a command line, and it is 99.5% full.  That is what makes the module worth
testing carefully: "the replacement is bigger" is the *normal* case, so the
decision between overwriting in place and allocating blocks is the decision that
matters, and getting it wrong produces a filesystem that e2fsck complains about
or a machine that does not boot.

Two properties carry the most weight:

* **Re-packing a ramdisk is a no-op.**  The gzip framing is reproduced byte for
  byte (see :mod:`boot.initrd`), which is asserted against the real image below.
  Without it, every ramdisk edit would silently grow the file by ~70 bytes.
* **Nothing allocates without a measured free-space check.**  The allocating
  writer frees the old blocks first, so what must fit is the *growth*, and the
  tests pin that arithmetic in both directions.

The real-image tests are read-only and skip when MuMu is not installed.
"""

from __future__ import annotations

import gzip
import io
import os
import struct
import zlib
from pathlib import Path

import pytest

from boot import image as boot_image
from boot import initrd as initrd_mod
from boot import kernel
from disk.device import ceil_to


# --------------------------------------------------------------------------- #
# Fixtures
# --------------------------------------------------------------------------- #
def make_bzimage(
    *, release: str = "6.1.90-perf+", size: int = 4096, setup_sects: int = 39
) -> bytes:
    """Build a minimal but structurally valid bzImage."""
    data = bytearray(size)
    data[0x1F1] = setup_sects
    struct.pack_into("<H", data, 0x206, 0x020F)  # boot protocol
    struct.pack_into("<I", data, 0x260, 0x1000000)  # init_size
    data[0x202:0x206] = b"HdrS"
    # The version-string offset is relative to the setup header at 0x200.
    text = release.encode() + b"\x00"
    off = 0x100
    data[0x20E:0x210] = struct.pack("<H", off)
    data[0x200 + off : 0x200 + off + len(text)] = text
    return bytes(data)


def cpio_entry(name: str, data: bytes, ino: int, *, mode: int = 0o100644) -> bytes:
    """One ``newc`` member, with the 4-byte alignment the format requires."""
    header = b"070701" + b"".join(
        f"{v:08x}".encode()
        for v in (
            ino,
            mode,
            0,
            0,
            1,
            0,
            len(data),
            0,
            0,
            0,
            0,
            len(name) + 1,
            0,
        )
    )
    body = header + name.encode() + b"\x00"
    body += b"\x00" * ((-len(body)) % 4)
    body += data
    body += b"\x00" * ((-len(body)) % 4)
    return body


CPIO_TRAILER = (
    b"070701"
    + b"".join(f"{v:08x}".encode() for v in (0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 11, 0))
    + b"TRAILER!!!\x00"
)


def make_cpio(entries: list[tuple[str, bytes]]) -> bytes:
    out = b""
    for index, (name, data) in enumerate(entries, start=1):
        out += cpio_entry(name, data, index)
    return out + CPIO_TRAILER


def _real_vdi() -> Path | None:
    """The installed emulator's system.vdi, or None if MuMu is not installed."""
    roots = [
        os.environ.get("MUMU_INSTALL_DIR"),
        r"C:\Program Files\Netease\MuMu",
        "/mnt/c/Program Files/Netease/MuMu",
    ]
    for root in roots:
        if not root:
            continue
        base = Path(root) / "nx_device" / "15.0" / "vms"
        if not base.is_dir():
            continue
        for candidate in sorted(base.glob("*/system.vdi")):
            if candidate.is_file():
                return candidate
    return None


REAL_VDI = _real_vdi()
requires_real_image = pytest.mark.skipif(REAL_VDI is None, reason="no MuMu installation present")


# --------------------------------------------------------------------------- #
# bzImage parsing
# --------------------------------------------------------------------------- #
def test_bzimage_parses_a_valid_header():
    img = kernel.parse_bzimage(make_bzimage(release="6.1.90-perf+"))
    assert img.release.startswith("6.1.90-perf+")
    assert img.boot_protocol == 0x020F
    assert img.setup_sectors == 39
    assert img.setup_bytes == 40 * 512


def test_bzimage_rejects_a_non_kernel():
    with pytest.raises(kernel.KernelError) as exc:
        kernel.parse_bzimage(b"\x00" * 4096)
    assert "not a bzImage" in str(exc.value)


def test_bzimage_rejects_a_truncated_file():
    with pytest.raises(kernel.KernelError) as exc:
        kernel.parse_bzimage(b"MZ" + b"\x00" * 10)
    assert "too small" in str(exc.value)


def test_bzimage_version_offset_is_relative_to_the_setup_header():
    """A regression guard: reading it as a file offset gives the wrong string."""
    img = kernel.parse_bzimage(make_bzimage(release="6.6.1-test"))
    assert img.release == "6.6.1-test"


def test_bzimage_family_drops_the_localversion():
    """ABI comparisons are on the family, not the full release string."""
    img = kernel.parse_bzimage(make_bzimage(release="6.1.90-perf+"))
    assert img.family == "6.1.90"
    other = kernel.parse_bzimage(make_bzimage(release="6.1.90"))
    assert other.family == img.family
    third = kernel.parse_bzimage(make_bzimage(release="6.6.1-perf+"))
    assert third.family != img.family


# --------------------------------------------------------------------------- #
# gzip framing
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("level,xfl", [(9, 2), (1, 4), (6, 0), (5, 0), (2, 0)])
def test_pack_gzip_sets_the_xfl_byte_the_way_gzip_does(level, xfl):
    """XFL is gzip's own "which extreme" marker; the originals rely on it."""
    blob = initrd_mod.pack_gzip(b"payload" * 100, level=level)
    assert blob[:4] == b"\x1f\x8b\x08\x00"
    assert blob[8] == xfl
    assert blob[9] == 3, "the OS byte is Unix, as in the originals"


def test_pack_gzip_round_trips_through_any_gzip_reader():
    """The framing is ours, but the stream must be ordinary gzip."""
    data = make_cpio([("init", b"#!/bin/sh\n"), ("bin/busybox", b"\x7fELF")])
    blob = initrd_mod.pack_gzip(data, level=9)
    assert gzip.decompress(blob) == data
    assert zlib.decompress(blob, 31) == data


def test_pack_gzip_refuses_an_impossible_level():
    with pytest.raises(initrd_mod.InitrdError):
        initrd_mod.pack_gzip(b"x", level=0)


def test_unpack_gzip_refuses_a_non_gzip_file():
    with pytest.raises(initrd_mod.InitrdError) as exc:
        initrd_mod.unpack_gzip(b"\x07\x07\x01 not gzip at all")
    assert "not gzip" in str(exc.value)


def test_unpack_gzip_refuses_a_truncated_stream():
    blob = initrd_mod.pack_gzip(b"payload" * 1000, level=9)
    with pytest.raises(initrd_mod.InitrdError) as exc:
        initrd_mod.unpack_gzip(blob[: len(blob) // 2])
    assert "truncated" in str(exc.value) or "corrupt" in str(exc.value)


def test_detect_level_recovers_the_level_that_made_the_file():
    data = make_cpio([("init", b"x" * 5000)])
    for level in (1, 6, 9):
        blob = initrd_mod.pack_gzip(data, level=level)
        assert initrd_mod.detect_level(blob) == level


def test_detect_level_returns_none_for_a_foreign_producer():
    """A stream this project cannot reproduce is reported, not guessed at."""
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb", compresslevel=9, mtime=0) as gz:
        gz.write(b"x" * 100)
    assert initrd_mod.detect_level(buf.getvalue()) is None


def test_repack_is_a_round_trip_for_an_unchanged_payload():
    """The property that makes an unchanged ramdisk free to write."""
    data = make_cpio([("init", b"y" * 2000), ("bin/busybox", b"\x7fELF" * 100)])
    original = initrd_mod.pack_gzip(data, level=9)
    assert initrd_mod.repack(original, initrd_mod.unpack_gzip(original)) == original


# --------------------------------------------------------------------------- #
# cpio parsing
# --------------------------------------------------------------------------- #
def test_cpio_entries_reads_names_sizes_and_modes():
    raw = make_cpio([("bin/busybox", b"\x7fELF" * 4), ("init", b"#!/bin/sh\n")])
    entries = initrd_mod.cpio_entries(raw)
    assert [e.name for e in entries] == ["bin/busybox", "init"]
    assert entries[0].size == len(b"\x7fELF" * 4) == 16
    assert entries[0].is_file and not entries[0].is_dir
    assert entries[1].size == len(b"#!/bin/sh\n")


def test_cpio_entries_are_aligned_so_a_second_member_parses():
    """A size that is not a multiple of 4 is the case alignment exists for."""
    raw = make_cpio([("a", b"12345"), ("b", b"x")])
    entries = initrd_mod.cpio_entries(raw)
    assert [e.name for e in entries] == ["a", "b"]
    assert initrd_mod.extract_entry(raw, "a") == b"12345"
    assert initrd_mod.extract_entry(raw, "b") == b"x"


def test_cpio_entries_excludes_the_trailer_by_default():
    raw = make_cpio([("only", b"z")])
    assert [e.name for e in initrd_mod.cpio_entries(raw)] == ["only"]
    assert [e.name for e in initrd_mod.cpio_entries(raw, include_trailer=True)] == [
        "only",
        "TRAILER!!!",
    ]


def test_cpio_entries_refuses_a_bad_magic_rather_than_guessing():
    """Continuing past a bad header yields plausible nonsense names."""
    with pytest.raises(initrd_mod.InitrdError) as exc:
        initrd_mod.cpio_entries(b"070701" + b"Z" * 200)
    assert "malformed" in str(exc.value) or "not a newc" in str(exc.value)


def test_cpio_entries_requires_a_trailer():
    raw = cpio_entry("a", b"x", 1)  # no TRAILER
    with pytest.raises(initrd_mod.InitrdError) as exc:
        initrd_mod.cpio_entries(raw)
    assert "TRAILER" in str(exc.value)


def test_extract_entry_reports_a_missing_name():
    raw = make_cpio([("a", b"x")])
    with pytest.raises(initrd_mod.InitrdError) as exc:
        initrd_mod.extract_entry(raw, "not-here")
    assert "not-here" in str(exc.value)


# --------------------------------------------------------------------------- #
# Ramdisk validation
# --------------------------------------------------------------------------- #
def test_validate_accepts_a_well_formed_ramdisk():
    blob = initrd_mod.pack_gzip(make_cpio([("init", b"#!/bin/sh\n")]))
    assert initrd_mod.validate_initrd(blob) == []


def test_validate_rejects_a_non_gzip_blob():
    problems = initrd_mod.validate_initrd(b"not gzip")
    assert len(problems) == 1 and "gzip" in problems[0]


def test_validate_rejects_a_cpio_without_a_trailer():
    blob = initrd_mod.pack_gzip(cpio_entry("init", b"x", 1))
    problems = initrd_mod.validate_initrd(blob)
    assert problems and "cpio" in problems[0]


def test_validate_refuses_a_member_that_escapes_the_archive_root():
    """init unpacks these as root; ``../`` would write outside the initramfs."""
    for name in ("../evil", "a/../../evil", "/etc/passwd"):
        blob = initrd_mod.pack_gzip(make_cpio([(name, b"x")]))
        problems = initrd_mod.validate_initrd(blob)
        assert problems, f"{name!r} was accepted"


def test_validate_rejects_an_empty_archive():
    blob = initrd_mod.pack_gzip(CPIO_TRAILER)
    problems = initrd_mod.validate_initrd(blob)
    assert problems and "no members" in problems[0]


# --------------------------------------------------------------------------- #
# The real image (read-only)
# --------------------------------------------------------------------------- #
@requires_real_image
class TestRealBootPartition:
    """The most valuable checks here: they use the image that has to boot."""

    def test_inventory_matches_what_was_measured(self):
        inv = boot_image.read_inventory(REAL_VDI)
        assert inv.partition == "sda3"
        assert inv.capacity == 14_660_608
        assert inv.free_bytes == 79_872
        sizes = {i.file.name: i.size for i in inv.files}
        assert sizes == {
            "kernel": 12_362_752,
            "initrd": 2_139_855,
            "ramdisk": 1_159,
            "cmdline": 94,
        }
        assert inv.kernel is not None
        assert inv.kernel.family == "6.1.90"

    def test_cmdline_is_one_line_with_no_trailing_nul(self):
        """Writing a NUL would grow the file and force an allocation."""
        raw = boot_image.read_file(REAL_VDI, "cmdline")
        assert not raw.endswith(b"\x00")
        assert b"\n" not in raw
        assert raw.startswith(b"root=/dev/ram0")

    def test_initrd_repacks_byte_for_byte(self):
        """Our gzip framing equals the producer's -- this is the load-bearing one.

        If this fails, every ramdisk write silently grows the file, which is the
        difference between an in-place edit and an allocated one.
        """
        blob = boot_image.read_file(REAL_VDI, "initrd")
        raw = initrd_mod.unpack_gzip(blob)
        level = initrd_mod.detect_level(blob)
        assert level == 9, f"expected the initrd to be level 9, got {level}"
        assert initrd_mod.pack_gzip(raw, level=level) == blob

    def test_ramdisk_repacks_byte_for_byte(self):
        """The small ramdisk is level 6, not 9 -- the level is per file."""
        blob = boot_image.read_file(REAL_VDI, "ramdisk")
        raw = initrd_mod.unpack_gzip(blob)
        level = initrd_mod.detect_level(blob)
        assert level == 6, f"expected the ramdisk to be level 6, got {level}"
        assert initrd_mod.pack_gzip(raw, level=level) == blob

    def test_initrd_contains_the_android_x86_init(self):
        raw = initrd_mod.unpack_gzip(boot_image.read_file(REAL_VDI, "initrd"))
        names = [e.name for e in initrd_mod.cpio_entries(raw)]
        assert "bin/busybox" in names
        assert "bin/e2fsck" in names
        assert "init" in names

    def test_initrd_has_no_bootconfig_trailer(self):
        """cmdline names ``bootconfig``, but there is no blob to keep in step.

        Asserted because the tempting "improvement" is to start writing one, and
        that would silently change what the kernel parses.
        """
        for name in ("initrd", "ramdisk"):
            raw = initrd_mod.unpack_gzip(boot_image.read_file(REAL_VDI, name))
            assert b"#BOOTCONFIG" not in raw

    def test_every_file_is_validated_clean_by_its_own_rules(self):
        with boot_image.BootImage.open(REAL_VDI) as img:
            for name in boot_image.BOOT_FILE_NAMES:
                data = img.read(name)
                img.validate(name, data)  # raises BootError if it would not boot

    def test_reading_the_kernel_does_not_reread_the_whole_image(self):
        """The 1000x read amplification, asserted on the real image.

        The boot ext2 uses 1 KiB blocks while a VDI block is 1 MiB, so the
        12,362,752-byte kernel spans 12,073 filesystem blocks inside only ~12
        container blocks.  Before the clean-block cache this read 12.7 GB from
        the image and took 40 s; the assertion is on the ratio, because that is
        the property, and it does not depend on machine speed.
        """
        with boot_image.BootImage.open(REAL_VDI) as img:
            img.read("kernel")
            stats = img._disk.vdi.read_stats
        pulled = stats.physical_bytes
        assert pulled < 64 << 20, (
            f"reading a 12 MB kernel pulled {pulled / 1e6:.0f} MB; the "
            f"clean-block cache is not working"
        )

    def test_a_same_size_kernel_is_planned_as_an_in_place_write(self):
        """The common case: no blocks move, so the free count cannot drift."""
        current = boot_image.read_file(REAL_VDI, "kernel")
        plan = boot_image.plan_replacement(REAL_VDI, "kernel", current)
        assert plan.fits_in_place
        assert plan.growth_bytes == 0
        assert plan.ok
        assert plan.free_bytes == 79_872


# --------------------------------------------------------------------------- #
# Planning arithmetic
# --------------------------------------------------------------------------- #
def test_ceil_to_rounds_up_and_refuses_a_zero_unit():
    assert ceil_to(0, 1024) == 0
    assert ceil_to(1, 1024) == 1024
    assert ceil_to(1024, 1024) == 1024
    assert ceil_to(1025, 1024) == 2048
    with pytest.raises(ValueError):
        ceil_to(10, 0)


def test_planning_a_smaller_value_never_allocates():
    plan = boot_image.plan_sizes(
        name="cmdline",
        installed_size=900,
        replacement_size=10,
        block_size=1024,
        free_bytes=0,
    )
    assert plan.fits_in_place
    assert plan.growth_bytes == 0
    assert plan.ok


def test_planning_a_same_size_value_is_in_place():
    plan = boot_image.plan_sizes(
        name="cmdline",
        installed_size=900,
        replacement_size=900,
        block_size=1024,
        free_bytes=0,
    )
    assert plan.fits_in_place and plan.growth_bytes == 0 and plan.ok


def test_growing_inside_one_block_allocates_nothing():
    """A bigger file whose extra bytes fit its last block costs no new blocks.

    It still takes the *allocating* writer, because ``replace_file_in_place``
    refuses any increase outright -- but the net growth is zero blocks, so it is
    affordable with no free space at all.  Conflating the two questions here
    produced a plan that said "in place" and a writer that refused.
    """
    plan = boot_image.plan_sizes(
        name="cmdline",
        installed_size=500,
        replacement_size=900,
        block_size=1024,
        free_bytes=0,
    )
    assert not plan.fits_in_place, "the in-place writer refuses any increase"
    assert plan.growth_bytes == 0
    assert plan.ok, "no new blocks are needed, so no free space is either"


def test_planning_across_a_block_boundary_costs_blocks():
    """From one 1 KiB block to three is two blocks of growth, not three."""
    plan = boot_image.plan_sizes(
        name="initrd",
        installed_size=1000,
        replacement_size=3000,
        block_size=1024,
        free_bytes=2048,
    )
    assert not plan.fits_in_place
    assert plan.growth_bytes == 2048
    assert plan.ok


def test_a_growing_write_is_affordable_when_the_growth_is_zero():
    """The "free" case is decided by the net blocks, not by the free count."""
    plan = boot_image.plan_sizes(
        name="ramdisk",
        installed_size=1100,
        replacement_size=1500,
        block_size=1024,
        free_bytes=0,
    )
    assert plan.growth_bytes == 0
    assert plan.ok and plan.shortfall == 0


def test_a_growing_write_that_exceeds_the_free_space_is_refused():
    plan = boot_image.plan_sizes(
        name="initrd",
        installed_size=1000,
        replacement_size=3000,
        block_size=1024,
        free_bytes=1024,
    )
    assert not plan.fits_in_place
    assert not plan.ok
    assert plan.shortfall == 1024


def test_an_exact_fit_is_allowed():
    """``<=`` and not ``<``: spending the last free block is legitimate."""
    plan = boot_image.plan_sizes(
        name="kernel",
        installed_size=1024,
        replacement_size=2048,
        block_size=1024,
        free_bytes=1024,
    )
    assert plan.growth_bytes == 1024
    assert plan.ok and plan.shortfall == 0


def test_planning_refuses_an_implausible_block_size():
    with pytest.raises(boot_image.BootError):
        boot_image.plan_sizes(
            name="cmdline",
            installed_size=1,
            replacement_size=1,
            block_size=0,
            free_bytes=0,
        )


def test_plan_summary_states_the_decision():
    plan = boot_image.ReplacementPlan(
        name="kernel",
        installed_size=100,
        replacement_size=200,
        fits_in_place=False,
        growth_bytes=1024,
        free_bytes=0,
        ok=False,
        shortfall=1024,
        notes=["because"],
    )
    text = plan.summary()
    assert "+100" in text
    assert "short by 1,024" in text
    assert "because" in text


# --------------------------------------------------------------------------- #
# Real round trips through the writer
# --------------------------------------------------------------------------- #
@pytest.fixture
def boot_fs(tmp_path):
    """A BootImage over a synthetic ext2 holding the four boot files.

    Uses the hand-built filesystem from ``test_disk`` rather than a VDI: the
    four-file machinery above the partition does not care what the device is
    (that is the point of the device stack), so this exercises the real
    ``replace_file_in_place`` and ``replace_file_growing`` paths without a
    1.8 GB image.
    """
    from disk.device import ByteDevice
    from test_disk import build_ext2_bytes

    fs_bytes = build_ext2_bytes(
        block_size=1024,
        nblocks=8192,
        ninodes=256,
        files={
            "kernel": make_bzimage(size=4096),
            "initrd": initrd_mod.pack_gzip(make_cpio([("init", b"x" * 200)])),
            "ramdisk": initrd_mod.pack_gzip(make_cpio([("data", b"y" * 50)])),
            "cmdline": b"root=/dev/ram0 console=ttyS0",
        },
    )
    path = tmp_path / "boot.img"
    path.write_bytes(fs_bytes)
    dev = ByteDevice(path, writable=True)
    img = boot_image.BootImage(dev, writable=True)
    yield img
    dev.close()


def test_replace_in_place_round_trips_a_shorter_cmdline(boot_fs):
    """The common case on this partition: same block, no allocation."""
    before_free = boot_fs.fs.free_blocks
    new = b"root=/dev/ram0"
    written = boot_fs.replace("cmdline", new)
    assert written == len(new)
    assert boot_fs.read("cmdline") == new
    assert boot_fs.fs.free_blocks == before_free, "an in-place write moved the free count"


def test_replace_growing_round_trips_a_larger_cmdline(boot_fs):
    """A bigger value still inside the block the file owns: still free."""
    before_free = boot_fs.fs.free_blocks
    new = b"root=/dev/ram0 " + b"a" * 500
    boot_fs.replace("cmdline", new)
    assert boot_fs.read("cmdline") == new
    assert boot_fs.fs.free_blocks == before_free


def test_replace_growing_across_blocks_allocates_and_stays_consistent(boot_fs):
    """Past one block, so the allocator runs -- the free count must agree."""
    before_free = boot_fs.fs.free_blocks
    new = b"root=/dev/ram0 " + b"b" * 4000
    boot_fs.replace("cmdline", new)
    assert boot_fs.read("cmdline") == new
    # The file is bigger, so fewer blocks are free -- and the descriptor counts
    # must have followed the bitmap rather than drifting from it.
    problems = boot_fs.fs.verify_geometry()
    assert problems == [], problems
    assert boot_fs.fs.free_blocks < before_free


def test_replace_does_not_disturb_the_other_files(boot_fs):
    kernel_before = boot_fs.read("kernel")
    initrd_before = boot_fs.read("initrd")
    boot_fs.replace("cmdline", b"root=/dev/ram1")
    assert boot_fs.read("kernel") == kernel_before
    assert boot_fs.read("initrd") == initrd_before


def test_replace_round_trips_a_ramdisk_with_one_member_changed(boot_fs):
    """The realistic ramdisk edit: decompress, rebuild, re-pack, write."""
    original = boot_fs.read("initrd")
    assert initrd_mod.entry_names(initrd_mod.unpack_gzip(original)) == ["init"]

    rebuilt = make_cpio([("init", b"z" * 200), ("bin/busybox", b"\x7fELF")])
    new = initrd_mod.repack(original, rebuilt)
    boot_fs.replace("initrd", new)
    assert boot_fs.read("initrd") == new
    assert initrd_mod.unpack_gzip(boot_fs.read("initrd")) == rebuilt


def test_replace_refuses_a_cmdline_with_a_newline(boot_fs):
    """GRUB passes this as one line; a newline would be silently dropped."""
    with pytest.raises(boot_image.BootError) as exc:
        boot_fs.replace("cmdline", b"root=/dev/ram0\nquiet")
    assert "newline" in str(exc.value)
    assert boot_fs.read("cmdline") == b"root=/dev/ram0 console=ttyS0"


def test_replace_refuses_a_cmdline_with_a_nul(boot_fs):
    with pytest.raises(boot_image.BootError) as exc:
        boot_fs.replace("cmdline", b"root=/dev/ram0\x00quiet")
    assert "NUL" in str(exc.value)


def test_replace_refuses_an_empty_cmdline(boot_fs):
    with pytest.raises(boot_image.BootError) as exc:
        boot_fs.replace("cmdline", b"")
    assert "empty" in str(exc.value)


def test_replace_refuses_a_non_bzimage_kernel(boot_fs):
    with pytest.raises(boot_image.BootError) as exc:
        boot_fs.replace("kernel", b"not a kernel" * 100)
    assert "bzImage" in str(exc.value)


def test_replace_refuses_a_ramdisk_that_is_not_gzip(boot_fs):
    with pytest.raises(boot_image.BootError) as exc:
        boot_fs.replace("initrd", b"plain text, not gzip")
    assert "gzip" in str(exc.value)


def test_replace_reports_an_unknown_boot_file(boot_fs):
    with pytest.raises(boot_image.BootError) as exc:
        boot_fs.replace("rootfs", b"x")
    assert "unknown boot file" in str(exc.value)


def test_extract_all_writes_four_named_files(boot_fs, tmp_path):
    out = tmp_path / "dump"
    written = boot_fs.extract_all(out)
    assert sorted(p.name for p in written) == ["cmdline", "initrd", "kernel", "ramdisk"]
    for path in written:
        assert path.read_bytes() == boot_fs.read(path.name)


def test_inventory_reports_the_free_space_the_filesystem_does(boot_fs):
    inv = boot_fs.inventory()
    assert inv.free_bytes == boot_fs.fs.free_blocks * boot_fs.fs.block_size
    assert inv.capacity == boot_fs.fs.blocks_count * boot_fs.fs.block_size
    assert inv.cmdline == "root=/dev/ram0 console=ttyS0"
    assert inv.kernel is not None
