"""Tests for the ext2/ext4 layer, and for the real image read end to end.

The VDI container's own tests live in ``test_vdi.py`` and the partition table's
in ``test_partition.py``; what is left here is the filesystem code, which is
the largest and most dangerous part of the project.  A bug here does not
produce a failed patch, it produces a corrupt Android system partition, so the
tests concentrate on the properties that make that survivable:

* the ext2/ext4 reader recovers bytes exactly, including through indirect
  blocks and extent trees;
* **a write that does not fit is refused**, because the failure mode this
  guards against -- ``debugfs`` recording an oversized inode after failing to
  allocate -- yields an image that looks fine to ``ls``;
* allocation, freeing and the group bookkeeping stay consistent, which is
  checked against a filesystem built by ``mke2fs`` rather than by this code
  agreeing with itself.

The synthetic fixtures build minimal images in a temp dir, so the suite runs
anywhere.  ``TestRealImage`` reads the installed emulator's image read-only,
and is skipped when it is not present.
"""

from __future__ import annotations

import struct
import tempfile
from pathlib import Path

import pytest

from disk import extfs, vdi
from disk import image as image_mod
from fixtures import ByteDevice


# --------------------------------------------------------------------------- #
# Fixtures: build a minimal valid VDI, and a minimal valid ext2
# --------------------------------------------------------------------------- #
def build_ext2_bytes(
    *,
    block_size: int = 1024,
    nblocks: int = 4096,
    ninodes: int = 128,
    files: dict[str, bytes] | None = None,
) -> bytes:
    """A minimal ext2 (rev 0, classic block maps) containing ``files``.

    Deliberately hand-built rather than shelling out to ``mkfs``: the tests
    must run on a machine with no ext2 tools at all, and a fixture we control
    is one whose layout we can assert against.
    """
    files = dict(files or {})
    bs = block_size
    img = bytearray(nblocks * bs)

    def put(off: int, data: bytes) -> None:
        img[off : off + len(data)] = data

    inode_size = 128
    first_data, bb, ib, it = 1, 3, 4, 5
    it_blocks = (ninodes * inode_size + bs - 1) // bs

    def setbit(bitmap: bytearray, block: int) -> None:
        """Set the block bitmap bit for ``block``.

        Bit *i* addresses block ``first_data + i``: with a 1 KiB block size
        block 0 is the boot block, which no group describes.
        """
        i = block - first_data
        bitmap[i // 8] |= 1 << (i % 8)

    def set_inode_bit(bitmap: bytearray, number: int) -> None:
        """Mark inode ``number`` used (indexed by number minus one)."""
        i = number - 1
        bitmap[i // 8] |= 1 << (i % 8)

    sb = bytearray(1024)
    struct.pack_into("<I", sb, 0x00, ninodes)
    struct.pack_into("<I", sb, 0x04, nblocks)
    struct.pack_into("<I", sb, 0x14, first_data)
    struct.pack_into("<I", sb, 0x18, 0)  # log_block_size -> 1024
    struct.pack_into("<I", sb, 0x20, nblocks)
    struct.pack_into("<I", sb, 0x28, ninodes)
    struct.pack_into("<H", sb, 0x38, extfs.EXT2_MAGIC)
    struct.pack_into("<I", sb, 0x4C, 0)  # rev 0 -> 128-byte inodes
    struct.pack_into("<H", sb, 0x58, inode_size)

    gdt = bytearray(32)
    struct.pack_into("<III", gdt, 0, bb, ib, it)
    put((first_data + 1) * bs, bytes(gdt))

    bm = bytearray(bs)
    for b in {0, 1, 2, bb, ib} | set(range(it, it + it_blocks)):
        setbit(bm, b)

    ino_off = it * bs

    def write_inode(num: int, mode: int, size: int, blocks, links: int = 1) -> None:
        o = ino_off + (num - 1) * inode_size
        d = bytearray(inode_size)
        struct.pack_into("<H", d, 0, mode)
        struct.pack_into("<I", d, 4, size)
        struct.pack_into("<H", d, 26, links)
        struct.pack_into("<15I", d, 40, *(list(blocks) + [0] * (15 - len(blocks))))
        put(o, bytes(d))

    inode_bm = bytearray(bs)
    set_inode_bit(inode_bm, 1)
    set_inode_bit(inode_bm, 2)

    next_block = it + it_blocks
    names = list(files)
    for i, name in enumerate(names):
        content = files[name]
        nb = max(1, (len(content) + bs - 1) // bs)
        blks = list(range(next_block, next_block + nb))
        next_block += nb
        for k, b in enumerate(blks):
            put(b * bs, content[k * bs : (k + 1) * bs])
            setbit(bm, b)
        write_inode(3 + i, 0o100644, len(content), blks)
        set_inode_bit(inode_bm, 3 + i)

    root_blk = next_block
    next_block += 1
    setbit(bm, root_blk)
    entries = [(2, ".", 2), (2, "..", 2)] + [(3 + i, n, 1) for i, n in enumerate(names)]
    data = bytearray(bs)
    off = 0
    for idx, (ino, name, ftype) in enumerate(entries):
        need = (8 + len(name) + 3) // 4 * 4
        rec = bs - off if idx == len(entries) - 1 else need
        struct.pack_into("<IHBB", data, off, ino, rec, len(name), ftype)
        data[off + 8 : off + 8 + len(name)] = name.encode()
        off += rec
    put(root_blk * bs, bytes(data))
    write_inode(2, 0o40755, bs, [root_blk], links=2)

    put(bb * bs, bytes(bm))
    put(ib * bs, bytes(inode_bm))
    used = sum(1 for i in range(nblocks) if bm[i // 8] >> (i % 8) & 1)
    struct.pack_into("<I", sb, 0x0C, nblocks - used)
    struct.pack_into("<I", sb, 0x10, ninodes - (2 + len(names)))
    put(1024, bytes(sb))
    return bytes(img)


@pytest.fixture
def ext2_file(tmp_path):
    path = tmp_path / "fs.img"
    path.write_bytes(build_ext2_bytes(files={"a.txt": b"A" * 400, "b.bin": bytes(range(256)) * 8}))
    dev = ByteDevice(path, writable=True)
    yield dev
    dev.close()


# --------------------------------------------------------------------------- #
# ext2 reading
# --------------------------------------------------------------------------- #
def test_ext2_reads_a_file_exactly(ext2_file):
    fs = extfs.Ext2(ext2_file)
    assert fs.read_path("/a.txt") == b"A" * 400


def test_ext2_reads_a_multi_block_file(ext2_file):
    fs = extfs.Ext2(ext2_file)
    assert fs.read_path("/b.bin") == bytes(range(256)) * 8


def test_ext2_lists_the_root_directory(ext2_file):
    fs = extfs.Ext2(ext2_file)
    names = {e.name for e in fs.list_dir(fs.read_inode(2))}
    assert {".", "..", "a.txt", "b.bin"} <= names


def test_ext2_reports_missing_paths(ext2_file):
    fs = extfs.Ext2(ext2_file)
    with pytest.raises(extfs.ExtError) as exc:
        fs.lookup("/nope")
    assert "not found" in str(exc.value)


def test_ext2_rejects_a_non_filesystem(tmp_path):
    p = tmp_path / "junk.img"
    p.write_bytes(b"\x00" * 8192)
    dev = ByteDevice(p, writable=True)
    with pytest.raises(extfs.ExtError) as exc:
        extfs.Ext2(dev)
    assert "not an ext2" in str(exc.value)
    dev.close()


def test_ext2_size_mismatch_is_reported(tmp_path):
    """A declared size larger than the mapped blocks must be an error.

    This is the shape of the debugfs corruption: the inode claims more bytes
    than its block pointers can supply.
    """
    raw = bytearray(build_ext2_bytes(files={"a.txt": b"A" * 100}))
    # Inflate i_size for inode 3 (inode table block 5, 128-byte entries).
    ino_off = 5 * 1024 + 2 * 128
    struct.pack_into("<I", raw, ino_off + 4, 999999)
    p = tmp_path / "bad.img"
    p.write_bytes(bytes(raw))
    dev = ByteDevice(p, writable=True)
    fs = extfs.Ext2(dev)
    with pytest.raises(extfs.ExtError) as exc:
        fs.read_path("/a.txt")
    assert "block map is inconsistent" in str(exc.value)
    dev.close()


# --------------------------------------------------------------------------- #
# ext2 writing -- the safety-critical part
# --------------------------------------------------------------------------- #
def test_write_shorter_replacement_succeeds(ext2_file):
    fs = extfs.Ext2(ext2_file, writable=True)
    fs.replace_file_in_place("/a.txt", b"B" * 10)
    assert fs.read_path("/a.txt") == b"B" * 10


def test_write_leaves_other_files_untouched(ext2_file):
    fs = extfs.Ext2(ext2_file, writable=True)
    before = fs.read_path("/b.bin")
    fs.replace_file_in_place("/a.txt", b"B" * 10)
    assert fs.read_path("/b.bin") == before


def test_oversized_replacement_is_refused(ext2_file):
    """The central guarantee of this module.

    A writer that allocated blocks would be free to half-succeed here, which is
    exactly how an oversized inode got recorded over a full filesystem.
    """
    fs = extfs.Ext2(ext2_file, writable=True)
    with pytest.raises(extfs.ExtError) as exc:
        fs.replace_file_in_place("/a.txt", b"X" * 5000)
    assert "will not allocate blocks" in str(exc.value)


def test_refused_write_does_not_touch_the_file(ext2_file):
    fs = extfs.Ext2(ext2_file, writable=True)
    before = fs.read_path("/a.txt")
    with pytest.raises(extfs.ExtError):
        fs.replace_file_in_place("/a.txt", b"X" * 5000)
    assert fs.read_path("/a.txt") == before


def test_write_pad_to_fills_with_zeros(ext2_file):
    fs = extfs.Ext2(ext2_file, writable=True)
    fs.replace_file_in_place("/a.txt", b"Z" * 10, pad_to=100)
    got = fs.read_path("/a.txt")
    assert len(got) == 100
    assert got[:10] == b"Z" * 10
    assert got[10:] == b"\x00" * 90


def test_pad_to_smaller_than_payload_is_refused(ext2_file):
    fs = extfs.Ext2(ext2_file, writable=True)
    with pytest.raises(extfs.ExtError) as exc:
        fs.replace_file_in_place("/a.txt", b"Z" * 50, pad_to=10)
    assert "exceeds the pad target" in str(exc.value)


def test_write_read_only_is_refused(ext2_file):
    fs = extfs.Ext2(ext2_file, writable=False)
    with pytest.raises(extfs.ExtError) as exc:
        fs.replace_file_in_place("/a.txt", b"x")
    assert "read-only" in str(exc.value)


def test_group_descriptor_and_inode_table_are_located(ext2_file):
    fs = extfs.Ext2(ext2_file)
    assert fs.inode_table_block(0) == 5
    assert fs.block_size == 1024
    assert fs.inodes_per_group == fs.inodes_count


# --------------------------------------------------------------------------- #
# Extent trees (the layout sda6 actually uses)
# --------------------------------------------------------------------------- #
def build_extent_node(entries: list[tuple[int, int, int]], *, depth: int) -> bytes:
    """Build one block-sized extent tree node.

    ``entries`` are ``(logical_or_index, len_or_hi, start_or_leaf)`` tuples.
    """
    node = bytearray(4096)
    struct.pack_into("<H", node, 0, 0xF30A)  # eh_magic
    struct.pack_into("<H", node, 2, len(entries))  # eh_entries
    struct.pack_into("<H", node, 4, 4)  # eh_max
    struct.pack_into("<H", node, 6, depth)  # eh_depth
    struct.pack_into("<I", node, 8, 0)  # eh_generation
    for i, (a, b, c) in enumerate(entries):
        off = 12 + i * 12
        if depth == 0:
            # ext4_extent: ee_block, ee_len, ee_start_hi, ee_start_lo
            struct.pack_into("<IHHI", node, off, a, b, (c >> 32) & 0xFFFF, c & 0xFFFFFFFF)
        else:
            # ext4_extent_idx: ei_block, ei_leaf_lo, ei_leaf_hi, ei_unused
            struct.pack_into("<IIHH", node, off, a, c & 0xFFFFFFFF, (c >> 32) & 0xFFFF, 0)
    return bytes(node)


def test_extent_index_records_are_not_read_as_extents():
    """Regression: ei_leaf_lo sits at +4, not +8.

    Reading an interior index node as a leaf produced a start block of
    0x400000000 -- far outside the filesystem.  This pins the layout.
    """
    node = build_extent_node([(0, 0, 0x1234)], depth=1)
    assert struct.unpack_from("<I", node, 12)[0] == 0  # ei_block
    assert struct.unpack_from("<I", node, 16)[0] == 0x1234  # ei_leaf_lo
    assert struct.unpack_from("<H", node, 20)[0] == 0  # ei_leaf_hi


def test_extent_leaf_entries_parse():
    node = build_extent_node([(0, 3, 500), (10, 2, 900)], depth=0)
    entries = []
    for i in range(2):
        off = 12 + i * 12
        logical = struct.unpack_from("<I", node, off)[0]
        length = struct.unpack_from("<H", node, off + 4)[0]
        hi = struct.unpack_from("<H", node, off + 6)[0]
        lo = struct.unpack_from("<I", node, off + 8)[0]
        entries.append((logical, length, (hi << 32) | lo))
    assert entries == [(0, 3, 500), (10, 2, 900)]


def test_extent_walk_rejects_an_out_of_range_child():
    """A misread index yields an impossible block; it must be caught."""

    class Dev:
        def __init__(self, data):
            self.data = data

        def read_at(self, off, length):
            return self.data[off : off + length]

    # A filesystem with 100 blocks whose root index points at block 9999.
    inner = build_extent_node([(0, 1, 50)], depth=0)
    dev = Dev(inner)
    fs = extfs.Ext2.__new__(extfs.Ext2)
    fs.dev = dev
    fs.block_size = 4096
    fs.blocks_count = 100
    fs.uses_extents = True

    inode = extfs.Inode(
        number=7,
        mode=extfs.S_IFREG | 0o644,
        size=4096,
        links=1,
        uid=0,
        gid=0,
        mtime=0,
        blocks=[0] * 15,
        raw=b"\x00" * 40 + build_extent_node([(0, 0, 9999)], depth=1),
    )
    with pytest.raises(extfs.ExtError) as exc:
        fs._extent_blocks(inode)
    assert "outside the filesystem" in str(exc.value)


def test_block_list_routes_directories_through_extents():
    """Regression: routing on ``is_file`` mis-parsed every directory.

    With the EXTENTS feature, directories carry an extent tree too.  Deciding
    by inode type sent directories to the classic parser, which read the extent
    header as block pointers and returned garbage.
    """
    fs = extfs.Ext2.__new__(extfs.Ext2)
    fs.uses_extents = True

    called = {}

    def fake_extents(inode):
        called["extents"] = True
        return [42]

    def fake_map(inode):
        called["map"] = True
        return [99]

    fs._extent_blocks = fake_extents
    fs._block_map = fake_map

    directory = extfs.Inode(
        number=2,
        mode=extfs.S_IFDIR | 0o755,
        size=4096,
        links=2,
        uid=0,
        gid=0,
        mtime=0,
        blocks=[0] * 15,
        raw=b"\x00" * 128,
    )
    assert fs._block_list(directory) == [42]
    assert "extents" in called
    assert "map" not in called


# --------------------------------------------------------------------------- #
# Against the real image, when one is installed
# --------------------------------------------------------------------------- #
def _real_vdi():
    """The installed emulator's system.vdi, or None if not present."""
    import os
    from pathlib import Path

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


@pytest.mark.skipif(REAL_VDI is None, reason="no MuMu installation present")
class TestRealImage:
    """Read-only assertions against the installed image.

    These carry the most weight of anything in the file: every bug found while
    writing ``extfs`` -- the extent-index layout, extent handling for
    directories -- was caught here and *not* by the synthetic fixtures.  They
    only read, so they are safe to run against a live installation.
    """

    #: Known inode identity of the shipped launcher, established independently
    #: by extracting it through ``vbox-img convert`` and hashing the result.
    LAWNCHAIR_SHA256 = "c1f3370c12ec636ddf83d3125bfd82ef56716ead7fa5c3a729732e40e5bfe277"
    LAWNCHAIR_SIZE = 43_330_672

    def _mount(self, v, lba: int):
        class Slice:
            def __init__(self, dev, base):
                self.dev, self.base = dev, base

            def read_at(self, off, length):
                return self.dev.read_at(self.base + off, length)

            def write_at(self, off, data):
                return self.dev.write_at(self.base + off, data)

        return extfs.Ext2(Slice(v, lba * 512))

    def test_header_matches_vbox_img(self):
        with vdi.VdiDevice(REAL_VDI) as v:
            assert v.header.disk_size == 2_463_370_240
            assert v.header.cb_block == 0x100000
            assert v.header.c_blocks == 2350
            assert v.header.c_blocks_allocated == 1789
            assert v.header.off_blocks == 0x100000
            assert v.header.off_data == 0x200000
            assert v.header.magic_ok

    def test_mbr_is_present_and_lists_the_expected_partitions(self):
        with vdi.VdiDevice(REAL_VDI) as v:
            mbr = v.read_at(0, 512)
            assert mbr[510:512] == b"\x55\xaa"
            starts = []
            for i in range(4):
                entry = mbr[446 + i * 16 : 446 + i * 16 + 16]
                if entry[4]:
                    starts.append(struct.unpack_from("<I", entry, 8)[0])
            # sda1, sda2, sda3 and the extended partition.
            assert starts[:3] == [2048, 18176, 34304]

    def test_boot_partition_holds_the_kernel(self):
        with vdi.VdiDevice(REAL_VDI) as v:
            fs = self._mount(v, 34304)
            assert fs.block_size == 1024
            names = {e.name for e in fs.list_dir(fs.read_inode(2))}
            assert {"cmdline", "kernel", "initrd", "ramdisk"} <= names
            assert fs.read_path("/cmdline").startswith(b"root=/dev/ram0")

    def test_system_partition_uses_extents(self):
        with vdi.VdiDevice(REAL_VDI) as v:
            fs = self._mount(v, 79068)
            assert fs.uses_extents is True
            assert fs.block_size == 4096

    def test_launcher_apk_extracts_intact(self):
        """The decisive check: a multi-MiB file must come back a valid APK.

        This exercises the extent tree end to end -- the launcher is 17-43 MiB
        described by a deep tree, so a wrong index layout or a directory routed
        to the classic parser produces garbage rather than a readable ZIP.

        The assertion is *structural* rather than a fixed hash because the
        image is a working one: the launcher is replaced whenever the desktop
        is swapped, and a pinned digest would only be asserting that nobody has
        used the tool.  A wrong extent walk cannot produce a ZIP whose central
        directory, manifest and dex entries all parse.
        """
        import io
        import zipfile

        with vdi.VdiDevice(REAL_VDI) as v:
            fs = self._mount(v, 79068)
            inode = fs.lookup("/system/priv-app/Lawnchair/Lawnchair.apk")
            data = fs.read_path("/system/priv-app/Lawnchair/Lawnchair.apk")

        assert data[:4] == b"PK\x03\x04"
        assert len(data) == inode.size, "read back fewer bytes than the inode declares"
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            assert z.testzip() is None, "a corrupt entry means the blocks are wrong"
            names = z.namelist()
            assert "AndroidManifest.xml" in names
            assert any(n.startswith("classes") and n.endswith(".dex") for n in names)
            abis = {n.split("/")[1] for n in names if n.startswith("lib/")}
            assert "x86_64" in abis, f"this guest is x86_64; found {sorted(abis)}"

    def test_pristine_backup_still_holds_the_fork_byte_exactly(self):
        """The known-value check, against a copy that is not being edited.

        The live image is a working one, so its launcher changes; the baseline
        backup taken before the first edit does not.  This keeps a hard
        known-good hash in the suite -- a wrong extent walk cannot reproduce a
        43 MiB file's SHA-256 -- without pinning the image to its original
        state.  Skipped when no such backup exists.
        """
        import hashlib
        from pathlib import Path

        backup = Path(REAL_VDI).parent / "mumu-patch-backups"
        candidates = sorted(backup.glob("*/*/system.vdi")) if backup.is_dir() else []
        if not candidates:
            pytest.skip("no image backup to compare against")

        with vdi.VdiDevice(candidates[0]) as v:
            fs = self._mount(v, 79068)
            data = fs.read_path("/system/priv-app/Lawnchair/Lawnchair.apk")
        assert len(data) == self.LAWNCHAIR_SIZE
        assert hashlib.sha256(data).hexdigest() == self.LAWNCHAIR_SHA256


# --------------------------------------------------------------------------- #
# Growing a filesystem after its partition grew
# --------------------------------------------------------------------------- #
def test_grow_adds_groups_and_free_blocks(tmp_path):
    """A grown partition is useless until the ext2 inside it knows it grew."""
    p = tmp_path / "grow.img"
    p.write_bytes(build_ext2_bytes(nblocks=4096, files={"a.txt": b"A" * 100}))
    dev = ByteDevice(p, writable=True)
    fs = extfs.Ext2(dev, writable=True)
    before_free = fs.free_blocks

    result = fs.grow_to(16384)
    assert fs.blocks_count == 16384
    assert fs.free_blocks > before_free
    assert result["added_groups"] >= 1
    # Existing content is untouched.
    assert fs.read_path("/a.txt") == b"A" * 100
    dev.close()


def test_grown_group_free_counts_fit_within_their_groups(tmp_path):
    """Regression: metadata was placed at a global cursor, not in its group.

    That made a group claim more free blocks than it contains -- the last group
    reported 18,420 free when it only spanned 4,109 blocks.
    """
    p = tmp_path / "grow2.img"
    p.write_bytes(build_ext2_bytes(nblocks=4096))
    dev = ByteDevice(p, writable=True)
    fs = extfs.Ext2(dev, writable=True)
    fs.grow_to(20000)

    groups = extfs._ceil_div(fs.blocks_count, fs.blocks_per_group)
    for group in range(groups):
        gd = fs.group_descriptor(group)
        free = struct.unpack_from("<H", gd, 12)[0]
        start = group * fs.blocks_per_group
        end = min(start + fs.blocks_per_group, fs.blocks_count)
        assert free <= end - start, (
            f"group {group} claims {free} free blocks but spans only {end - start}"
        )
    dev.close()


def test_grown_metadata_lives_inside_its_own_group(tmp_path):
    p = tmp_path / "grow3.img"
    p.write_bytes(build_ext2_bytes(nblocks=4096))
    dev = ByteDevice(p, writable=True)
    fs = extfs.Ext2(dev, writable=True)
    fs.grow_to(20000)

    groups = extfs._ceil_div(fs.blocks_count, fs.blocks_per_group)
    bpg = fs.blocks_per_group
    for group in range(1, groups):
        gd = fs.group_descriptor(group)
        bb, ib, it = struct.unpack_from("<III", gd, 0)
        start = group * bpg
        end = min(start + bpg, fs.blocks_count)
        for label, block in (("bb", bb), ("ib", ib), ("it", it)):
            assert start <= block < end, (
                f"group {group} {label} block {block} is outside its range {start}..{end - 1}"
            )
    dev.close()


def test_grown_superblock_free_count_matches_the_groups(tmp_path):
    p = tmp_path / "grow4.img"
    p.write_bytes(build_ext2_bytes(nblocks=4096))
    dev = ByteDevice(p, writable=True)
    fs = extfs.Ext2(dev, writable=True)
    fs.grow_to(20000)

    groups = extfs._ceil_div(fs.blocks_count, fs.blocks_per_group)
    total = sum(struct.unpack_from("<H", fs.group_descriptor(g), 12)[0] for g in range(groups))
    assert total == fs.free_blocks
    dev.close()


def test_grow_reports_geometry_problems_when_none(tmp_path):
    p = tmp_path / "grow5.img"
    p.write_bytes(build_ext2_bytes(nblocks=4096))
    dev = ByteDevice(p, writable=True)
    fs = extfs.Ext2(dev, writable=True)
    fs.grow_to(12000)
    assert fs.verify_geometry() == []
    dev.close()


def test_grow_refuses_to_shrink(tmp_path):
    p = tmp_path / "grow6.img"
    p.write_bytes(build_ext2_bytes(nblocks=4096))
    dev = ByteDevice(p, writable=True)
    fs = extfs.Ext2(dev, writable=True)
    with pytest.raises(extfs.ExtError) as exc:
        fs.grow_to(1024)
    assert "shrink" in str(exc.value)
    dev.close()


def test_grow_to_the_same_size_is_a_noop(tmp_path):
    p = tmp_path / "grow7.img"
    p.write_bytes(build_ext2_bytes(nblocks=4096))
    dev = ByteDevice(p, writable=True)
    fs = extfs.Ext2(dev, writable=True)
    result = fs.grow_to(4096)
    assert result == {"added_blocks": 0, "added_groups": 0}
    dev.close()


def test_grow_too_small_for_new_group_metadata_is_refused(tmp_path):
    """Growing by less than a group's metadata needs must fail, not overrun.

    Each new group needs a block bitmap, an inode bitmap and an inode table, so
    a request that leaves no room for them has to be refused rather than writing
    metadata past the end of the filesystem.
    """
    p = tmp_path / "grow8.img"
    p.write_bytes(build_ext2_bytes(nblocks=4096))
    dev = ByteDevice(p, writable=True)
    fs = extfs.Ext2(dev, writable=True)
    before = fs.blocks_count
    with pytest.raises(extfs.ExtError) as exc:
        fs.grow_to(before + 1)
    assert "cannot hold its own metadata" in str(exc.value)
    dev.close()


def test_grow_by_whole_groups_succeeds(tmp_path):
    p = tmp_path / "grow9.img"
    p.write_bytes(build_ext2_bytes(nblocks=4096))
    dev = ByteDevice(p, writable=True)
    fs = extfs.Ext2(dev, writable=True)
    before_free = fs.free_blocks
    fs.grow_to(fs.blocks_per_group * 2)
    assert fs.free_blocks > before_free
    assert fs.verify_geometry() == []
    dev.close()


# --------------------------------------------------------------------------- #
# Block allocation (only ever run after the partition grew)
# --------------------------------------------------------------------------- #
def test_allocate_returns_the_requested_count(tmp_path):
    p = tmp_path / "alloc.img"
    p.write_bytes(build_ext2_bytes(nblocks=4096, files={"a.txt": b"A" * 10}))
    dev = ByteDevice(p, writable=True)
    fs = extfs.Ext2(dev, writable=True)
    fs.grow_to(fs.blocks_per_group * 3)
    blocks = fs._allocate_blocks(50)
    assert len(blocks) == 50
    assert len(set(blocks)) == 50, "a block must never be handed out twice"
    dev.close()


def test_allocate_never_returns_metadata_blocks(tmp_path):
    """Handing out a group's own bitmap would corrupt it on the next write."""
    p = tmp_path / "alloc2.img"
    p.write_bytes(build_ext2_bytes(nblocks=4096))
    dev = ByteDevice(p, writable=True)
    fs = extfs.Ext2(dev, writable=True)
    fs.grow_to(fs.blocks_per_group * 3)

    groups = extfs._ceil_div(fs.blocks_count, fs.blocks_per_group)
    forbidden = {0, fs.first_data_block}
    for group in range(groups):
        gd = fs.group_descriptor(group)
        forbidden.update(struct.unpack_from("<III", gd, 0))
        start = group * fs.blocks_per_group
        forbidden.add(start)

    blocks = fs._allocate_blocks(200)
    overlap = forbidden & set(blocks)
    assert not overlap, f"allocator returned metadata blocks: {sorted(overlap)}"
    dev.close()


def test_allocate_sets_bits_in_the_bitmap(tmp_path):
    p = tmp_path / "alloc3.img"
    p.write_bytes(build_ext2_bytes(nblocks=4096))
    dev = ByteDevice(p, writable=True)
    fs = extfs.Ext2(dev, writable=True)
    fs.grow_to(fs.blocks_per_group * 3)
    before = fs.free_blocks
    blocks = fs._allocate_blocks(64)
    assert fs.free_blocks == before - 64
    # And the bits really are set.
    for block in blocks[:10]:
        group = block // fs.blocks_per_group
        gd = fs.group_descriptor(group)
        bb = struct.unpack_from("<I", gd, 0)[0]
        bitmap = fs.read_block(bb)
        assert extfs._get_bit(bitmap, block - group * fs.blocks_per_group)
    dev.close()


def test_allocate_more_than_free_is_refused(tmp_path):
    p = tmp_path / "alloc4.img"
    p.write_bytes(build_ext2_bytes(nblocks=4096))
    dev = ByteDevice(p, writable=True)
    fs = extfs.Ext2(dev, writable=True)
    with pytest.raises(extfs.ExtError) as exc:
        fs._allocate_blocks(fs.free_blocks + 1)
    assert "free" in str(exc.value)
    dev.close()


def test_free_then_allocate_reuses_the_freed_blocks(tmp_path):
    """Reuse is the point: the kernel swap frees the old blocks, then allocates.

    Without freeing first, a swap needs room for the whole new file while the
    old one's blocks sit stranded -- about 7 MB more than the filesystem has.
    Reuse is therefore required, not merely acceptable.
    """
    p = tmp_path / "alloc5.img"
    p.write_bytes(build_ext2_bytes(nblocks=4096, files={"a.txt": b"A" * 4096}))
    dev = ByteDevice(p, writable=True)
    fs = extfs.Ext2(dev, writable=True)
    fs.grow_to(fs.blocks_per_group * 3)

    inode = fs.lookup("/a.txt")
    old = [b for b in fs._block_list(inode) if b]
    fs._free_blocks(old)
    new = fs._allocate_blocks(len(old))
    assert set(old) & set(new), "freed blocks should be reused"
    assert len(set(new)) == len(new), "no block may be handed out twice"
    dev.close()


def test_freeing_then_allocating_more_than_was_freed_is_bounded(tmp_path):
    """The freed space plus the new space is what the allocator may hand out."""
    p = tmp_path / "alloc5b.img"
    p.write_bytes(build_ext2_bytes(nblocks=4096, files={"a.txt": b"A" * 4096}))
    dev = ByteDevice(p, writable=True)
    fs = extfs.Ext2(dev, writable=True)
    inode = fs.lookup("/a.txt")
    old = [b for b in fs._block_list(inode) if b]
    fs._free_blocks(old)
    before = fs.free_blocks
    fs._allocate_blocks(before)
    with pytest.raises(extfs.ExtError):
        fs._allocate_blocks(1)
    dev.close()


def test_free_refuses_a_block_already_marked_free(tmp_path):
    """Freeing twice would double-count the space."""
    p = tmp_path / "alloc6.img"
    p.write_bytes(build_ext2_bytes(nblocks=4096, files={"a.txt": b"A" * 4096}))
    dev = ByteDevice(p, writable=True)
    fs = extfs.Ext2(dev, writable=True)
    inode = fs.lookup("/a.txt")
    old = [b for b in fs._block_list(inode) if b]
    fs._free_blocks(old)
    with pytest.raises(extfs.ExtError) as exc:
        fs._free_blocks(old)
    assert "already" in str(exc.value)
    dev.close()


def test_free_refuses_a_block_outside_the_filesystem(tmp_path):
    p = tmp_path / "alloc7.img"
    p.write_bytes(build_ext2_bytes(nblocks=4096))
    dev = ByteDevice(p, writable=True)
    fs = extfs.Ext2(dev, writable=True)
    with pytest.raises(extfs.ExtError) as exc:
        fs._free_blocks([fs.blocks_count + 10])
    assert "outside" in str(exc.value)
    dev.close()


def test_replace_file_growing_writes_a_larger_file(tmp_path):
    """The whole point: a file bigger than the old one, on a grown filesystem."""
    p = tmp_path / "grow_file.img"
    p.write_bytes(build_ext2_bytes(nblocks=2048, files={"k": b"K" * 1024}))
    dev = ByteDevice(p, writable=True)
    fs = extfs.Ext2(dev, writable=True)
    fs.grow_to(fs.blocks_per_group * 4)

    payload = bytes(range(256)) * 400  # 102400 bytes, far bigger than 1 KiB
    result = fs.replace_file_growing("/k", payload)
    assert result["allocated"] > 0
    assert fs.read_path("/k") == payload
    dev.close()


def test_replace_file_growing_updates_the_bitmaps_consistently(tmp_path):
    p = tmp_path / "grow_file2.img"
    p.write_bytes(build_ext2_bytes(nblocks=2048, files={"k": b"K" * 1024}))
    dev = ByteDevice(p, writable=True)
    fs = extfs.Ext2(dev, writable=True)
    fs.grow_to(fs.blocks_per_group * 4)
    fs.replace_file_growing("/k", b"Z" * 40_000)
    assert fs.verify_geometry() == []
    dev.close()


def test_replace_file_growing_refuses_when_the_data_does_not_fit(tmp_path):
    p = tmp_path / "grow_file3.img"
    p.write_bytes(build_ext2_bytes(nblocks=2048, files={"k": b"K" * 1024}))
    dev = ByteDevice(p, writable=True)
    fs = extfs.Ext2(dev, writable=True)
    # No grow_to: the filesystem is still tiny, so this must be refused.
    with pytest.raises(extfs.ExtError) as exc:
        fs.replace_file_growing("/k", b"Z" * 10_000_000)
    assert "free" in str(exc.value)
    dev.close()


def test_replace_file_growing_shrinks_via_the_in_place_path(tmp_path):
    p = tmp_path / "grow_file4.img"
    p.write_bytes(build_ext2_bytes(nblocks=2048, files={"k": b"K" * 4000}))
    dev = ByteDevice(p, writable=True)
    fs = extfs.Ext2(dev, writable=True)
    result = fs.replace_file_growing("/k", b"S" * 100)
    assert result["allocated"] == 0
    assert fs.read_path("/k") == b"S" * 100
    dev.close()


def test_indirect_chain_reports_every_table_it_allocates(tmp_path):
    """Regression: inner double-indirect tables were allocated but unrecorded.

    They stayed marked used in the bitmap with nothing referring to them, so the
    free counts drifted from reality.
    """
    p = tmp_path / "chain.img"
    p.write_bytes(build_ext2_bytes(nblocks=4096))
    dev = ByteDevice(p, writable=True)
    fs = extfs.Ext2(dev, writable=True)
    fs.grow_to(fs.blocks_per_group * 6)

    per = fs.block_size // 4
    # Enough blocks to need a double-indirect table with several inner tables.
    needed = 12 + per + per * 2 + 5
    data = fs._allocate_blocks(needed)
    ptrs, tables = fs._write_indirect_chain(data)

    assert len(tables) >= 4, "should have allocated several pointer tables"
    assert len(set(tables)) == len(tables), "a table must not be allocated twice"
    assert not (set(tables) & set(data)), "tables must not overlap the data"
    assert ptrs[12] in tables and ptrs[13] in tables
    dev.close()


# --------------------------------------------------------------------------- #
# Extents: the on-disk layout the system partition actually uses
# --------------------------------------------------------------------------- #
def build_ext4_extents_bytes(
    *,
    block_size: int = 1024,
    nblocks: int = 4096,
    files: dict[str, bytes] | None = None,
    holes: dict[str, list[int]] | None = None,
) -> bytes:
    """A minimal ext4 with the EXTENTS feature containing ``files``.

    Built by hand for the same reason as the ext2 fixture.  ``holes`` names
    logical block indices per file that are left unmapped, which is how ext4
    stores a sparse file -- and, it turns out, how it stores the real launcher
    APK, whose ZIP alignment padding is full of them.
    """
    import struct as _s

    files = dict(files or {})
    holes = dict(holes or {})
    bs = block_size
    img = bytearray(nblocks * bs)

    def put(off, data):
        img[off : off + len(data)] = data

    inode_size = 256
    first_data, bb, ib, it = 1, 3, 4, 5
    it_blocks = (128 * inode_size + bs - 1) // bs

    def setbit(bitmap, block):
        """Set the block bitmap bit for ``block``.

        Bit *i* addresses block ``first_data + i``, so a 1 KiB block size
        offsets every index by one: group 0's first bit is block 1.
        """
        i = block - first_data
        bitmap[i // 8] |= 1 << (i % 8)

    def set_inode_bit(bitmap, number):
        """Mark inode ``number`` used.

        An inode bitmap is indexed by inode number minus one and has no
        boot-block offset, so it must not go through :func:`setbit`.
        """
        i = number - 1
        bitmap[i // 8] |= 1 << (i % 8)

    bm = bytearray(bs)
    inode_bm = bytearray(bs)
    sb = bytearray(1024)
    # Bitmap bit *i* addresses block ``first_data + i``: with a 1 KiB block
    # size block 0 is the boot block and is not described by any group, so
    # group 0's first bit is block 1 (the superblock).
    setbit(bm, 0)

    _s.pack_into("<I", sb, 0x00, 128)
    _s.pack_into("<I", sb, 0x04, nblocks)
    _s.pack_into("<I", sb, 0x0C, 0)
    _s.pack_into("<I", sb, 0x10, 128 - 3)
    _s.pack_into("<I", sb, 0x14, first_data)
    _s.pack_into("<I", sb, 0x18, 0)
    _s.pack_into("<I", sb, 0x20, nblocks)
    _s.pack_into("<I", sb, 0x28, 128)
    _s.pack_into("<H", sb, 0x38, 0xEF53)
    _s.pack_into("<I", sb, 0x4C, 1)
    _s.pack_into("<H", sb, 0x58, inode_size)
    # The EXTENTS incompat bit is what makes this an extent-mapped filesystem.
    _s.pack_into("<I", sb, 0x60, extfs.INCOMPAT_EXTENTS)
    assert _s.unpack_from("<H", sb, 0x38)[0] == 0xEF53

    # This group's own metadata: block bitmap, inode bitmap, inode table.
    for blk in (bb, ib):
        setbit(bm, blk)
    for i in range(it_blocks):
        setbit(bm, it + i)
    # Padding past the end of the group.  mke2fs sets these and e2fsck
    # requires it ("Padding at end of block bitmap is not set"), so a fixture
    # that leaves them clear is not the filesystem it claims to be.  The
    # bitmap has blocks_per_group bits and this group is short, so the bits
    # from the last real block to the end of the bitmap are padding.
    for i in range(nblocks - first_data, nblocks):
        setbit(bm, first_data + i)
    set_inode_bit(inode_bm, 1)
    set_inode_bit(inode_bm, 2)

    def write_inode(num, mode, size, extents, links=1):
        off = it * bs + (num - 1) * inode_size
        raw = bytearray(inode_size)
        _s.pack_into("<H", raw, 0, mode)
        _s.pack_into("<I", raw, 4, size)
        _s.pack_into("<H", raw, 26, links)
        sectors = sum(n for _, _, n in extents) * (bs // 512)
        _s.pack_into("<I", raw, 28, sectors)
        _s.pack_into("<HHHH", raw, 40, 0xF30A, len(extents), 4, 0)
        for i, (logical, physical, length) in enumerate(extents):
            _s.pack_into(
                "<IHHI",
                raw,
                52 + i * 12,
                logical,
                length,
                physical >> 32,
                physical & 0xFFFFFFFF,
            )
        put(off, bytes(raw))

    next_block = it + it_blocks
    names = list(files)
    for i, name in enumerate(names):
        content = files[name]
        nb = max(1, (len(content) + bs - 1) // bs)
        hole_set = set(holes.get(name, []))
        runs = []
        blks = []
        logical = 0
        while logical < nb:
            if logical in hole_set:
                blks.append(0)
                logical += 1
                continue
            start = next_block
            next_block += 1
            setbit(bm, start)
            run_len = 1
            blks.append(start)
            logical += 1
            while logical < nb and logical not in hole_set and run_len < 32768:
                blks.append(next_block)
                setbit(bm, next_block)
                next_block += 1
                run_len += 1
                logical += 1
            runs.append((logical - run_len, start, run_len))
        for k, b in enumerate(blks):
            if b:
                put(b * bs, content[k * bs : (k + 1) * bs])
        write_inode(3 + i, 0o100644, len(content), runs)
        set_inode_bit(inode_bm, 3 + i)

    root_blk = next_block
    next_block += 1
    setbit(bm, root_blk)
    entries = [(2, ".", 2), (2, "..", 2)] + [(3 + i, n, 1) for i, n in enumerate(names)]
    data = bytearray(bs)
    off = 0
    for idx, (ino, name, ftype) in enumerate(entries):
        need = (8 + len(name) + 3) // 4 * 4
        rec = bs - off if idx == len(entries) - 1 else need
        _s.pack_into("<IHBB", data, off, ino, rec, len(name), ftype)
        data[off + 8 : off + 8 + len(name)] = name.encode()
        off += rec
    put(root_blk * bs, bytes(data))
    # The root directory is extent-mapped too, like the real one.
    root_off = it * bs + 1 * inode_size
    raw = bytearray(inode_size)
    _s.pack_into("<H", raw, 0, 0o40755)
    _s.pack_into("<I", raw, 4, bs)
    _s.pack_into("<H", raw, 26, 2)
    _s.pack_into("<I", raw, 28, bs // 512)
    _s.pack_into("<HHHH", raw, 40, 0xF30A, 1, 4, 0)
    _s.pack_into("<IHHI", raw, 52, 0, 1, 0, root_blk)
    put(root_off, bytes(raw))

    put(bb * bs, bytes(bm))
    put(ib * bs, bytes(inode_bm))
    # The group descriptor table.  The reader takes each group's bitmap,
    # inode bitmap and inode table from here, so a fixture without it looks
    # like a filesystem whose every metadata pointer is zero.
    gd = bytearray(bs)
    _s.pack_into("<III", gd, 0, bb, ib, it)
    used = sum(1 for i in range(nblocks) if bm[i // 8] >> (i % 8) & 1)
    _s.pack_into("<HHH", gd, 12, nblocks - used, 128 - 3, 1)
    put((first_data + 1) * bs, bytes(gd))
    _s.pack_into("<I", sb, 0x0C, nblocks - used)
    put(1024, bytes(sb))
    return bytes(img)


@pytest.fixture
def ext4_file(tmp_path):
    path = tmp_path / "ext4.img"
    path.write_bytes(
        build_ext4_extents_bytes(
            nblocks=8192,
            files={"big.bin": bytes(range(256)) * 20},
        )
    )
    dev = ByteDevice(path, writable=True)
    yield dev
    dev.close()


def test_extents_filesystem_is_recognised(ext4_file):
    fs = extfs.Ext2(ext4_file)
    assert fs.uses_extents is True
    assert fs.read_path("/big.bin") == bytes(range(256)) * 20


def test_freeing_an_extents_inode_never_frees_metadata(tmp_path):
    """Regression: slots 12-14 of an extents inode are index entries.

    They were being read as classic indirect pointers, so ``_free_blocks`` was
    handed whatever integers happen to live in the extent tree.  In the real
    image one of those numbers was 1 -- the group descriptor table -- and
    freeing it corrupted the filesystem structure.
    """
    p = tmp_path / "ext4.img"
    p.write_bytes(build_ext4_extents_bytes(nblocks=8192, files={"big.bin": bytes(range(256)) * 20}))
    dev = ByteDevice(p, writable=True)
    fs = extfs.Ext2(dev, writable=True)

    inode = fs.lookup("/big.bin")
    tree = fs._extent_tree_blocks(inode)
    # The tree blocks must be reported, and none of them may be metadata.
    for block in tree:
        assert not fs.is_metadata_block(block), (
            f"extent tree block {block} is filesystem metadata; freeing it "
            f"would destroy the filesystem"
        )
    dev.close()


def test_is_metadata_block_covers_every_structural_block(tmp_path):
    """The guard has to know all of the metadata, not just the superblock.

    The original check was ``block < first_data_block + 1``, which only shields
    the superblock -- every group's bitmap and inode table were fair game.
    """
    p = tmp_path / "ext4.img"
    p.write_bytes(build_ext4_extents_bytes(nblocks=8192))
    dev = ByteDevice(p, writable=True)
    fs = extfs.Ext2(dev)

    assert fs.is_metadata_block(0), "boot block"
    assert fs.is_metadata_block(1), "group descriptor table"
    for group in range(4):
        gd = fs.group_descriptor(group)
        for offset, label in ((0, "block bitmap"), (4, "inode bitmap"), (8, "inode table")):
            block = struct.unpack_from("<I", gd, offset)[0]
            assert fs.is_metadata_block(block), f"group {group} {label}"
    # A block in the middle of a data group is not metadata.
    assert not fs.is_metadata_block(fs.inode_table_block(0) + 200)
    dev.close()


def test_free_blocks_refuses_metadata(tmp_path):
    """Direct guard: handing ``_free_blocks`` a metadata block must raise."""
    p = tmp_path / "ext4.img"
    p.write_bytes(build_ext4_extents_bytes(nblocks=8192))
    dev = ByteDevice(p, writable=True)
    fs = extfs.Ext2(dev, writable=True)

    with pytest.raises(extfs.ExtError) as exc:
        fs._free_blocks([1])
    assert "metadata" in str(exc.value)

    # ...and the superblock free count must be untouched by the refusal.
    before = fs.free_blocks
    with pytest.raises(extfs.ExtError):
        fs._free_blocks([1, 2, 3])
    assert fs.free_blocks == before
    dev.close()


def test_allocate_blocks_never_hands_out_metadata(tmp_path):
    """The allocate side has the same guard, for a drifted bitmap."""
    p = tmp_path / "ext4.img"
    p.write_bytes(build_ext4_extents_bytes(nblocks=8192))
    dev = ByteDevice(p, writable=True)
    fs = extfs.Ext2(dev, writable=True)

    blocks = fs._allocate_blocks(64)
    assert len(blocks) == 64
    for block in blocks:
        assert not fs.is_metadata_block(block)
    dev.close()


def test_growing_an_extents_file_writes_an_extent_tree(tmp_path):
    """Growing must produce a valid extent tree, not an indirect chain.

    Writing the classic chain into an extents inode puts pointer tables where
    the tree header belongs; the file then reads back as garbage.
    """
    p = tmp_path / "ext4.img"
    p.write_bytes(build_ext4_extents_bytes(nblocks=8192, files={"f.bin": b"A" * 4096}))
    dev = ByteDevice(p, writable=True)
    fs = extfs.Ext2(dev, writable=True)

    payload = bytes(range(256)) * 200  # ~51 KB, needs many more blocks
    fs.replace_file_growing("/f.bin", payload)

    assert fs.read_path("/f.bin") == payload
    inode = fs.lookup("/f.bin")
    assert struct.unpack_from("<H", inode.raw, 40)[0] == 0xF30A, "still an extent tree"
    runs = fs._extent_runs(inode.raw)
    assert runs, "the tree must describe at least one extent"
    for _logical, physical, length in runs:
        for k in range(length):
            assert not fs.is_metadata_block(physical + k)
    dev.close()


def test_growing_a_sparse_extents_file_preserves_holes(tmp_path):
    """A hole is a logical block with no storage; rewriting must keep that.

    The real launcher APK has 29 of them (ZIP alignment padding).  Treating
    every logical block as backed by storage made the writer allocate blocks
    for regions that were never there.
    """
    p = tmp_path / "ext4.img"
    p.write_bytes(
        build_ext4_extents_bytes(
            nblocks=8192,
            files={"f.bin": b"A" * 8192},
            holes={"f.bin": [2, 3, 4]},
        )
    )
    dev = ByteDevice(p, writable=True)
    fs = extfs.Ext2(dev, writable=True)

    before = fs._block_list(fs.lookup("/f.bin"))
    assert before[2] == 0 and before[3] == 0 and before[4] == 0, "fixture has holes"

    payload = b"A" * 8192 + b"B" * 4096
    fs.replace_file_growing("/f.bin", payload)
    assert fs.read_path("/f.bin") == payload
    dev.close()


def test_growing_an_extents_file_sets_i_blocks_correctly(tmp_path):
    """Regression: i_blocks was double-counted when rewriting an extents file.

    ``write_inode`` derived the sector count from ``inode.raw`` *before* packing
    the new tree into it, so it measured the previous tree and then added the
    new one.  On the real image e2fsck reported "i_blocks is 170768, should be
    85384" -- exactly twice the data blocks.  Nothing else noticed, because a
    wrong i_blocks does not affect reads: it only makes e2fsck complain and
    makes df(1) misreport usage.
    """
    p = tmp_path / "ext4.img"
    p.write_bytes(build_ext4_extents_bytes(nblocks=8192, files={"f.bin": b"A" * 4096}))
    dev = ByteDevice(p, writable=True)
    fs = extfs.Ext2(dev, writable=True)

    payload = bytes(range(256)) * 200
    fs.replace_file_growing("/f.bin", payload)

    inode = fs.lookup("/f.bin")
    stored = struct.unpack_from("<I", inode.raw, 28)[0]

    runs = fs._extent_runs(inode.raw)
    tree = fs._extent_tree_blocks(inode)
    expected = (sum(n for _, _, n in runs) + len(tree)) * (fs.block_size // 512)
    assert stored == expected, (
        f"i_blocks is {stored}, should be {expected} "
        f"(data {sum(n for _, _, n in runs)} + tree {len(tree)} blocks)"
    )

    # And the rewrite must be idempotent in its accounting: doing it twice must
    # not double the count again.
    fs.replace_file_growing("/f.bin", payload + b"B" * 4096)
    inode2 = fs.lookup("/f.bin")
    stored2 = struct.unpack_from("<I", inode2.raw, 28)[0]
    runs2 = fs._extent_runs(inode2.raw)
    tree2 = fs._extent_tree_blocks(inode2)
    expected2 = (sum(n for _, _, n in runs2) + len(tree2)) * (fs.block_size // 512)
    assert stored2 == expected2
    dev.close()


def test_group_free_counts_ignore_bits_past_the_group_end(tmp_path):
    """Free counts must not include blocks that do not exist.

    e2fsck reported group 12 as holding blocks 417107-425983 free when the
    filesystem ends at 421086.  Counting bits past the end of a short final
    group inflates the free total and hands out blocks beyond the device.
    """
    p = tmp_path / "ext4.img"
    # A size that leaves a deliberately short final group.
    p.write_bytes(build_ext4_extents_bytes(nblocks=8192, files={"a": b"x" * 100}))
    dev = ByteDevice(p, writable=True)
    fs = extfs.Ext2(dev, writable=True)

    fs._refresh_group_counts()
    groups = -(-fs.blocks_count // fs.blocks_per_group)
    counted = 0
    for g in range(groups):
        gd = fs.group_descriptor(g)
        free = struct.unpack_from("<H", gd, 12)[0]
        counted += free
        # Every claimed-free block must be a real block.
        bb = struct.unpack_from("<I", gd, 0)[0]
        bitmap = fs.read_block(bb)
        # group_bounds(), not group * blocks_per_group: a 1 KiB block size
        # reserves block 0 as the boot block, so group 0 starts at block 1.
        start, end = fs.group_bounds(g)
        claimed = sum(1 for i in range(end - start) if not (bitmap[i // 8] >> (i % 8) & 1))
        assert free == claimed, f"group {g}: descriptor says {free}, bitmap has {claimed}"
        assert start + claimed <= fs.blocks_count
    assert counted == fs.free_blocks
    dev.close()


def test_group_descriptor_checksum_matches_known_good_vectors():
    """Pin the GDT checksum algorithm against values from the real image.

    These four descriptors come from the guest's system partition, and all four
    were accepted by e2fsck 1.47.2.  If the algorithm drifts, every descriptor
    this code rewrites becomes invalid and e2fsck reports the filesystem as
    corrupt -- which is exactly what happened before this was implemented.
    """
    uuid_bytes = bytes.fromhex("6e05f15cae895f97aef59f8bc6faff34")
    vectors = {
        0: (
            "02000000030000000400000000000000290000000000000000000000000011b1",
            0xB111,
        ),
        1: (
            "028000000380000004800000000000000b0000000000000000000000000002bc",
            0xBC02,
        ),
        2: (
            "0000010001000100020001000000000014000000000000000000000000005827",
            0x2758,
        ),
        12: (
            "0000060001000600020006000e10b000080000000000000000000000b000077a",
            0x7A07,
        ),
    }
    for group, (hexbytes, expected) in vectors.items():
        raw = bytearray(bytes.fromhex(hexbytes))
        assert struct.unpack_from("<H", raw, 30)[0] == expected, "fixture is wrong"
        # Recompute over the descriptor with the checksum field zeroed.
        raw[30:32] = b"\x00\x00"
        crc = extfs._crc16(uuid_bytes)
        crc = extfs._crc16(struct.pack("<I", group), crc)
        crc = extfs._crc16(bytes(raw[:30]), crc)
        assert crc == expected, (
            f"group {group}: computed {crc:#06x}, the image stores {expected:#06x}"
        )


def test_rewriting_a_descriptor_updates_its_checksum(tmp_path):
    """Changing a free count must re-checksum the descriptor.

    The real image had group 12 report a stale checksum after a write: the free
    count had been updated but not the CRC, so e2fsck called the filesystem
    corrupt even though the count itself was right.
    """
    p = tmp_path / "ext4.img"
    p.write_bytes(build_ext4_extents_bytes(nblocks=8192))
    dev = ByteDevice(p, writable=True)
    fs = extfs.Ext2(dev, writable=True)
    # Claim the GDT_CSUM feature so the checksum path is exercised.
    fs.ro_compat |= extfs.RO_COMPAT_GDT_CSUM

    before = fs.group_descriptor(0)
    fs._write_group_descriptor_free(0, 1234)
    after = fs.group_descriptor(0)

    assert struct.unpack_from("<H", after, 12)[0] == 1234
    stored = struct.unpack_from("<H", after, 30)[0]
    raw = bytearray(after)
    raw[30:32] = b"\x00\x00"
    crc = extfs._crc16(fs.uuid)
    crc = extfs._crc16(struct.pack("<I", 0), crc)
    crc = extfs._crc16(bytes(raw[:30]), crc)
    assert stored == crc, "the checksum must be recomputed, not left stale"
    assert stored != struct.unpack_from("<H", before, 30)[0]
    dev.close()


def test_crc16_matches_a_known_ext4_value():
    """The CRC-16 variant matters: ext4 uses the reflected 0x8005 polynomial.

    Getting this wrong does not corrupt data, it makes every checksum wrong,
    which e2fsck reports as a corrupt filesystem.
    """
    assert extfs._crc16(b"") == 0xFFFF
    assert extfs._crc16(b"123456789") == 0x4B37  # CRC-16/ARC check value
    # Chaining must be equivalent to one pass over the concatenation.
    a, b = b"hello ", b"world"
    assert extfs._crc16(a + b) == extfs._crc16(b, extfs._crc16(a))


def test_padding_bits_past_a_short_group_are_set(tmp_path):
    """mke2fs sets the bitmap padding; e2fsck requires it set.

    The direction of this invariant is easy to get backwards: clearing these
    bits makes e2fsck report "Padding at end of block bitmap is not set" on
    every write.
    """
    p = tmp_path / "pad.img"
    # 8192 blocks over 1000-block groups leaves a short final group.
    p.write_bytes(build_ext2_bytes(nblocks=8192, block_size=1024, ninodes=128))
    dev = ByteDevice(p, writable=True)
    fs = extfs.Ext2(dev, writable=True)
    fs.grow_to(fs.blocks_per_group * 5 + 100)

    groups = -(-fs.blocks_count // fs.blocks_per_group)
    for group in range(groups):
        gd = fs.group_descriptor(group)
        bb = struct.unpack_from("<I", gd, 0)[0]
        bitmap = fs.read_block(bb)
        start = group * fs.blocks_per_group
        end = min(start + fs.blocks_per_group, fs.blocks_count)
        for bit in range(end - start, fs.blocks_per_group):
            assert extfs._get_bit(bitmap, bit), (
                f"group {group}: padding bit {bit} is clear; mke2fs sets these"
            )
    assert fs.verify_geometry() == []
    dev.close()


def test_verify_geometry_reports_cleared_padding(tmp_path):
    """The check must flag clear padding, and pass when it is set."""
    p = tmp_path / "pad2.img"
    p.write_bytes(build_ext2_bytes(nblocks=8192, block_size=1024, ninodes=128))
    dev = ByteDevice(p, writable=True)
    fs = extfs.Ext2(dev, writable=True)
    fs.grow_to(fs.blocks_per_group * 5 + 100)
    assert fs.verify_geometry() == []

    # Clear the padding in the last group and confirm it is reported.
    groups = -(-fs.blocks_count // fs.blocks_per_group)
    gd = fs.group_descriptor(groups - 1)
    bb = struct.unpack_from("<I", gd, 0)[0]
    bitmap = bytearray(fs.read_block(bb))
    start = (groups - 1) * fs.blocks_per_group
    end = min(start + fs.blocks_per_group, fs.blocks_count)
    for bit in range(end - start, fs.blocks_per_group):
        bitmap[bit // 8] &= ~(1 << (bit % 8))
    fs.dev.write_at(fs.block_offset(bb), bytes(bitmap))

    problems = fs.verify_geometry()
    assert any("padding" in p for p in problems)
    dev.close()


def test_shrinking_a_file_frees_its_tail_blocks(tmp_path):
    """Regression: a shorter replacement left the old extent tree in place.

    Writing 17 MB over a 43 MB file kept the inode describing the whole old
    run, so e2fsck reported "i_blocks is 84408, should be 8" and the bitmap
    reserved 10,000 blocks nothing referenced.
    """
    p = tmp_path / "shrink.img"
    p.write_bytes(build_ext4_extents_bytes(nblocks=8192, files={"f": b"A" * (4096 * 40)}))
    dev = ByteDevice(p, writable=True)
    fs = extfs.Ext2(dev, writable=True)

    before = fs.lookup("/f")
    before_blocks = len([b for b in fs._block_list(before) if b])
    free_before = fs.free_blocks

    payload = b"B" * 4096
    fs.replace_file_in_place("/f", payload)

    after = fs.lookup("/f")
    mapped = [b for b in fs._block_list(after) if b]
    iblocks = struct.unpack_from("<I", after.raw, 28)[0]

    assert fs.read_path("/f") == payload
    assert len(mapped) < before_blocks, "the block map must shrink with the file"
    assert iblocks == len(mapped) * (fs.block_size // 512), (
        f"i_blocks is {iblocks}, should be {len(mapped) * (fs.block_size // 512)}"
    )
    assert fs.free_blocks > free_before, "the tail blocks must return to the bitmap"
    assert fs.verify_geometry() == []
    dev.close()


def test_unlink_inode_clears_links_and_frees_the_inode(tmp_path):
    """Unlinking must zero the inode and free its slot, not just its blocks.

    Half an unlink is what e2fsck reports as "Unattached inode N / Connect to
    /lost+found?".
    """
    p = tmp_path / "unlink.img"
    p.write_bytes(build_ext4_extents_bytes(nblocks=8192, files={"f": b"C" * 8192}))
    dev = ByteDevice(p, writable=True)
    fs = extfs.Ext2(dev, writable=True)

    target = fs.lookup("/f")
    number = target.number
    inodes_before = fs.free_inodes
    assert target.links == 1

    freed = fs.unlink_inode(number)

    after = fs.read_inode(number)
    assert after.links == 0, "the link count must be zero"
    assert after.mode == 0, "the mode must be zero, as e2fsck expects"
    assert struct.unpack_from("<I", after.raw, 28)[0] == 0, "i_blocks must be zero"
    assert fs.free_inodes == inodes_before + 1, "the inode slot must be released"
    assert freed >= 1, "its data blocks must be released"
    dev.close()


def test_unlink_refuses_a_directory(tmp_path):
    """Removing a directory needs its parent's entry count updated too."""
    p = tmp_path / "unlinkdir.img"
    p.write_bytes(build_ext4_extents_bytes(nblocks=8192, files={"f": b"x"}))
    dev = ByteDevice(p, writable=True)
    fs = extfs.Ext2(dev, writable=True)
    with pytest.raises(extfs.ExtError) as exc:
        fs.unlink_inode(2)  # the root directory
    assert "directory" in str(exc.value)
    dev.close()


def test_shared_blocks_are_detected_without_a_feature_bit(tmp_path):
    """Deduplicated blocks are found by counting references.

    ``dumpe2fs`` prints ``shared_blocks`` for the real filesystem, but none of
    its three feature words has the 0x8000 bit set, so the flag cannot be read
    directly.  On the real image 9,247 blocks are shared between APKs; freeing
    one of those when a *different* inode goes away makes e2fsck report
    ``Block bitmap differences: +276491--276500``.
    """
    p = tmp_path / "shared.img"
    p.write_bytes(
        build_ext4_extents_bytes(nblocks=8192, files={"a": b"A" * 4096, "b": b"B" * 4096})
    )
    dev = ByteDevice(p, writable=True)
    fs = extfs.Ext2(dev, writable=True)
    assert fs.has_shared_blocks is False, "the fixture starts out unshared"

    # Point /b's extent at /a's data block, which is what dedup produces: two
    # inodes describing the same physical block.
    a_block = next(b for b in fs._block_list(fs.lookup("/a")) if b)
    inode = fs.lookup("/b")
    raw = bytearray(inode.raw)
    struct.pack_into("<IHHI", raw, 52, 0, 1, a_block >> 32, a_block & 0xFFFFFFFF)
    inode.blocks = list(struct.unpack_from("<15I", raw, 40))
    inode.raw = bytes(raw)
    fs.write_inode(inode)

    assert next(b for b in fs._block_list(fs.lookup("/b")) if b) == a_block
    fs._shared_blocks_cache = None  # the map changed, so drop the cache
    assert fs.has_shared_blocks is True, "the shared block must be detected"
    assert a_block in fs._shared_blocks_in_use()
    dev.close()


def test_unlink_keeps_blocks_another_inode_still_uses(tmp_path):
    """Freeing a deduplicated block corrupts the other file that reads it.

    This is the real-image failure: unlinking the fork's .odex released blocks
    that three other APKs in priv-app were still using, and e2fsck reported the
    bitmap as wrong by exactly those blocks.
    """
    p = tmp_path / "sharedunlink.img"
    p.write_bytes(
        build_ext4_extents_bytes(nblocks=8192, files={"keep": b"K" * 4096, "drop": b"D" * 4096})
    )
    dev = ByteDevice(p, writable=True)
    fs = extfs.Ext2(dev, writable=True)

    shared = next(b for b in fs._block_list(fs.lookup("/keep")) if b)
    drop = fs.lookup("/drop")
    raw = bytearray(drop.raw)
    struct.pack_into("<IHHI", raw, 52, 0, 1, shared >> 32, shared & 0xFFFFFFFF)
    drop.blocks = list(struct.unpack_from("<15I", raw, 40))
    drop.raw = bytes(raw)
    fs.write_inode(drop)
    fs._shared_blocks_cache = None

    assert fs.has_shared_blocks is True
    fs.unlink_inode(drop.number)

    # The block the survivor still points at must remain allocated.
    group = shared // fs.blocks_per_group
    bb = struct.unpack_from("<I", fs.group_descriptor(group), 0)[0]
    bitmap = fs.read_block(bb)
    index = shared - group * fs.blocks_per_group
    assert extfs._get_bit(bitmap, index), (
        "block shared with a live inode was freed; that file now reads free space"
    )
    assert fs.read_path("/keep") == b"K" * 4096
    dev.close()


# --------------------------------------------------------------------------- #
# Group geometry: the boot block offset
# --------------------------------------------------------------------------- #
def test_group_bounds_account_for_the_boot_block():
    """Group *N* starts at ``first_data_block + N * blocks_per_group``.

    For a 1 KiB block size ext2 reserves block 0 as the boot block, so
    ``s_first_data_block`` is 1 and the naive ``group * blocks_per_group`` is
    off by one.  Every bitmap bit is an index into its own group's range, so
    that error shifts every allocation and free by one bit -- and it went
    unnoticed because the boot partition's bitmaps are nearly full, where a
    one-bit shift usually lands on another used bit.

    For a 4 KiB block size ``first_data_block`` is 0, which is why the Android
    system partition never showed it.
    """
    p = Path(tempfile.mkdtemp()) / "g.img"
    p.write_bytes(build_ext2_bytes(nblocks=4096))
    dev = ByteDevice(p, writable=True)
    fs = extfs.Ext2(dev, writable=True)

    assert fs.block_size == 1024
    assert fs.first_data_block == 1
    assert fs.blocks_per_group == 4096
    assert fs.group_bounds(0) == (1, 4096)
    # Group 1 would start one block after group 0 ends, not at 4096.
    assert fs.group_bounds(1)[0] == 4097

    # A 4 KiB filesystem has no boot block, so first_data_block is 0 and the
    # naive product is right.  Asserted against the rule rather than against a
    # fixture, because the hand-built fixtures all use 1 KiB blocks.
    class ZeroOffset:
        first_data_block = 0
        blocks_per_group = 2048
        blocks_count = 4096

    assert extfs.Ext2.group_bounds(ZeroOffset, 0) == (0, 2048)
    assert extfs.Ext2.group_bounds(ZeroOffset, 1) == (2048, 4096)
    assert extfs.Ext2.group_bounds(ZeroOffset, 2) == (4096, 4096)
    dev.close()


def test_group_index_and_group_of_round_trip():
    """``group_of``/``group_index`` must invert ``group_bounds``."""
    p = Path(tempfile.mkdtemp()) / "g.img"
    p.write_bytes(build_ext2_bytes(nblocks=4096))
    dev = ByteDevice(p, writable=True)
    fs = extfs.Ext2(dev, writable=True)
    bpg = fs.blocks_per_group
    # The fixture is one group, so exercise the arithmetic directly against
    # the same rule: for a 1 KiB block size the offset is 1.
    for block in (1, 2, bpg, bpg + 1, bpg + 2):
        g = fs.group_of(block)
        index = fs.group_index(block)
        assert index == block - 1 - g * bpg, f"block {block} in group {g}"
        assert 0 <= index < bpg
    assert fs.group_of(1) == 0 and fs.group_index(1) == 0
    assert fs.group_of(bpg) == 0 and fs.group_index(bpg) == bpg - 1
    assert fs.group_of(bpg + 1) == 1 and fs.group_index(bpg + 1) == 0
    dev.close()


def test_freeing_a_block_at_a_group_boundary_uses_the_right_bit():
    """A block in group 1 must be looked up in group 1's bitmap, offset.

    This is the failure the boot-block bug produced: the block was recorded in
    the inode but the bitmap bit consulted belonged to the *next* block, so the
    writer refused with "recorded in the inode but already marked free".
    """
    p = Path(tempfile.mkdtemp()) / "gb.img"
    p.write_bytes(build_ext2_bytes(nblocks=4096, files={"a": b"A" * 4096}))
    dev = ByteDevice(p, writable=True)
    fs = extfs.Ext2(dev, writable=True)

    inode = fs.lookup("/a")
    blocks = [b for b in fs._block_list(inode) if b]
    assert blocks
    for block in blocks:
        g = fs.group_of(block)
        start, end = fs.group_bounds(g)
        assert start <= block < end
        gd = fs.group_descriptor(g)
        bb = struct.unpack_from("<I", gd, 0)[0]
        bitmap = fs.read_block(bb)
        index = fs.group_index(block)
        assert (bitmap[index // 8] >> (index % 8)) & 1, (
            f"block {block} is owned by /a but its bit is clear in group "
            f"{g}'s bitmap at index {index}"
        )
    dev.close()


def _mke2fs_with_big_file(tmp_path, *, blocks: int, block_size: int = 1024):
    """A real mke2fs ext2 holding one file large enough to need indirection.

    The hand-built fixture writes only direct pointers, so indirection has to
    be exercised against a filesystem a real tool made -- and that is better
    evidence anyway, since mke2fs is the authority on the layout being read.
    """
    import shutil
    import subprocess

    mke2fs = shutil.which("mke2fs") or "/usr/sbin/mke2fs"
    debugfs = shutil.which("debugfs") or "/usr/sbin/debugfs"
    if not Path(mke2fs).is_file() or not Path(debugfs).is_file():
        pytest.skip("e2fsprogs is not installed")

    image = tmp_path / "real.img"
    # Small inode count and a tight block count keep it quick; the point is the
    # pointer layout, not the size.
    subprocess.run(
        [
            mke2fs,
            "-q",
            "-F",
            "-b",
            str(block_size),
            "-I",
            "128",
            "-N",
            "64",
            "-O",
            "none",
            str(image),
            "8192",
        ],
        check=True,
        capture_output=True,
    )
    payload = tmp_path / "payload.bin"
    payload.write_bytes(b"B" * (blocks * block_size))
    subprocess.run(
        [debugfs, "-w", "-R", f"write {payload} /big", str(image)],
        check=True,
        capture_output=True,
    )
    return image


def test_i_blocks_counts_data_blocks_and_every_indirect_table(tmp_path):
    """``i_blocks`` must count the data blocks, not just the pointer slots.

    Counting only the 15 slots in ``inode.blocks`` was wrong by orders of
    magnitude -- a 12 MiB file has 15 pointers and 12,300 blocks, so e2fsck
    reported "i_blocks is 28, should be 28356".  It must also include the
    single-indirect tables a double-indirect table points at, which a
    slots-only count misses.
    """
    image = _mke2fs_with_big_file(tmp_path, blocks=400)
    dev = ByteDevice(image, writable=True)
    fs = extfs.Ext2(dev, writable=True)

    inode = fs.lookup("/big")
    data = [b for b in fs._block_list(inode) if b]
    tables = fs._indirect_tables(inode)
    recorded = struct.unpack_from("<I", inode.raw, 28)[0]
    expected = (len(data) + len(tables)) * (fs.block_size // 512)

    assert len(data) > 12, "the file must need indirect pointers"
    assert len(tables) >= 1, f"expected an indirect table, got {tables}"
    assert recorded == expected, (
        f"i_blocks is {recorded}, should be {expected} "
        f"({len(data)} data blocks + {len(tables)} tables)"
    )
    dev.close()


def test_freeing_a_classic_inode_releases_its_inner_indirect_tables(tmp_path):
    """Every table the inode owns must go back to the bitmap.

    Listing only slots 12-14 left the single-indirect tables under a
    double-indirect table allocated forever: invisible space that accumulates
    on every kernel replacement.
    """
    image = _mke2fs_with_big_file(tmp_path, blocks=400)
    dev = ByteDevice(image, writable=True)
    fs = extfs.Ext2(dev, writable=True)

    inode = fs.lookup("/big")
    tables = fs._indirect_tables(inode)
    assert len(tables) >= 1

    for block in tables:
        g = fs.group_of(block)
        gd = fs.group_descriptor(g)
        bb = struct.unpack_from("<I", gd, 0)[0]
        index = fs.group_index(block)
        assert (fs.read_block(bb)[index // 8] >> (index % 8)) & 1, (
            f"table {block} should be marked used before the free"
        )

    fs._free_blocks(tables)
    fs._refresh_group_counts()

    for block in tables:
        g = fs.group_of(block)
        gd = fs.group_descriptor(g)
        bb = struct.unpack_from("<I", gd, 0)[0]
        index = fs.group_index(block)
        assert not (fs.read_block(bb)[index // 8] >> (index % 8)) & 1, (
            f"indirect table {block} is still marked used after being freed"
        )
    dev.close()


# --------------------------------------------------------------------------- #
# Growing the boot filesystem in place (the boot --grow path)
# --------------------------------------------------------------------------- #
def _raw_disk_with_ext2(tmp_path: Path, *, part_sectors: int, fs_blocks: int):
    """A raw disk: MBR with one ext2 partition holding ``/kernel``.

    Built by hand so the grow path can be exercised without an installed
    emulator, and so the partition is deliberately *larger* than the filesystem
    inside it -- which is the state ``apply_growth`` leaves behind and the
    precondition ``resize_boot_filesystem`` exists to resolve.
    """
    start_lba = 2048
    fs_bytes = build_ext2_bytes(nblocks=fs_blocks, files={"kernel": b"K" * 512})
    # One partition, type 0x83, big enough to hold a grown filesystem.
    mbr = bytearray(512)
    struct.pack_into("<II", mbr, 446 + 8, start_lba, part_sectors)
    mbr[446 + 4] = 0x83
    mbr[510:512] = b"\x55\xaa"

    total = (start_lba + part_sectors) * 512
    img = bytearray(total)
    img[0:512] = mbr
    off = start_lba * 512
    img[off : off + len(fs_bytes)] = fs_bytes

    path = tmp_path / "disk.raw"
    path.write_bytes(bytes(img))
    return path


def test_grow_boot_filesystem_extends_the_ext2_in_place(tmp_path):
    """The in-tree grow must raise the block count and stay self-consistent.

    This is the path `boot --grow` takes, and it is the highest-risk code in the
    project: a mistake here corrupts the filesystem GRUB boots from.  It is done
    entirely in-tree by `extfs.Ext2.grow_to`, so the grow, the no-op case and the
    post-grow check are all pinned here.
    """
    from boot import grow as grow_mod

    fs_blocks = 4096
    part_sectors = 4 * fs_blocks  # 4x the filesystem, so there is room to grow
    image = _raw_disk_with_ext2(tmp_path, part_sectors=part_sectors, fs_blocks=fs_blocks)

    with image_mod.open_image(image) as disk:
        part = disk.partitions().boot()
        before = extfs.Ext2(part).blocks_count
    assert before == fs_blocks, before

    target = part_sectors * 512
    grow_mod.resize_boot_filesystem(image, target)

    # Re-open through a fresh handle: the count really moved and the file that
    # was already there survived.
    with image_mod.open_image(image) as disk:
        part = disk.partitions().boot()
        fs = extfs.Ext2(part)
        assert fs.blocks_count > before, (fs.blocks_count, before)
        assert fs.blocks_count * fs.block_size <= part.size_bytes
        assert fs.read_file(fs.lookup("/kernel")) == b"K" * 512

    # Allocation past the old end must now succeed, and must never hand out a
    # group's own metadata.  Opened writable, since allocating mutates bitmaps.
    with image_mod.open_image(image, writable=True) as disk:
        part = disk.partitions().boot()
        fs = extfs.Ext2(part, writable=True)
        blocks = fs._allocate_blocks(64)
        assert len(set(blocks)) == 64
        groups = extfs._ceil_div(fs.blocks_count, fs.blocks_per_group)
        forbidden = {0, fs.first_data_block}
        for group in range(groups):
            gd = fs.group_descriptor(group)
            forbidden.update(struct.unpack_from("<III", gd, 0))
            forbidden.add(group * fs.blocks_per_group)
        assert not (forbidden & set(blocks)), "allocator returned metadata"


def test_grow_boot_filesystem_is_a_noop_when_already_big_enough(tmp_path):
    """Asking for no growth must not rewrite anything."""
    from boot import grow as grow_mod

    fs_blocks = 4096
    part_sectors = 4 * fs_blocks
    image = _raw_disk_with_ext2(tmp_path, part_sectors=part_sectors, fs_blocks=fs_blocks)
    with image_mod.open_image(image) as disk:
        fs = extfs.Ext2(disk.partitions().boot())
        already = fs.blocks_count * fs.block_size

    grow_mod.resize_boot_filesystem(image, already)

    with image_mod.open_image(image) as disk:
        fs = extfs.Ext2(disk.partitions().boot())
        assert fs.blocks_count == fs_blocks


def test_verify_boot_filesystem_rejects_a_superblock_bigger_than_its_partition(tmp_path):
    """The post-grow check must catch a filesystem that overruns its partition.

    `_verify_boot_filesystem` re-reads the result; if it cannot catch a
    superblock that claims more blocks than the partition holds, the check is
    decoration.
    """
    from boot import grow as grow_mod

    image = _raw_disk_with_ext2(tmp_path, part_sectors=4096, fs_blocks=4096)
    with pytest.raises(grow_mod.BootError, match="claims"):
        grow_mod._verify_boot_filesystem(image)
