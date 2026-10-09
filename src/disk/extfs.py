"""Read and write ext2/ext4 filesystems inside a MuMu disk image.

Why this exists
---------------
The MuMu guest disk holds two filesystems we need to change:

* ``sda3`` -- 14 MiB ext2 (rev 0, no journal, 1024-byte blocks) holding the
  kernel, initrd, ramdisk and cmdline;
* ``sda6`` -- 1.6 GiB ext4 holding the Android system partition, where the
  launcher APK lives.

Both are edited offline, before the emulator starts.

Why not just use a library
--------------------------
The ``ext4`` package on PyPI is read-only, and a from-scratch builder (TIK's
``make_ext4fs``) produces a whole new filesystem rather than editing one.  Since
we must *replace a file in place* and keep the rest of the image untouched, this
module implements the parts of the format that are actually needed.

The one rule that matters
-------------------------
Writing a file that does not fit must **fail**, not half-succeed.  This is not
hypothetical: driving ``debugfs`` to write a 24 MB kernel into the 14 MiB boot
partition printed *both* ``write: Could not allocate block in ext2 filesystem``
*and* ``Allocated inode: 11``, then recorded a 24,725,504-byte size with zero
free blocks -- an image that looks correct to ``ls`` and is corrupt.  So every
write here is followed by a re-read and a byte comparison, and the free-block
count is checked before and after.

Layout notes
------------
Both filesystems in this image are *small* and use only direct block pointers
(12), single indirect, double indirect and triple indirect blocks.  ``sda3``
uses 1024-byte blocks, so a 12 MB kernel needs double-indirect; ``sda6`` uses
4096-byte blocks.  ``s_inode_size`` is 128 on ``sda3`` (rev 0) but is read from
the superblock rather than assumed, because rev-1 filesystems commonly use 256.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

EXT2_MAGIC = 0xEF53

# Inode type/permission bits.
S_IFMT = 0o170000
S_IFREG = 0o100000
S_IFDIR = 0o040000

# Directory entry file types.
FT_UNKNOWN, FT_REG, FT_DIR = 0, 1, 2

# Superblock field offsets (relative to the 1024-byte superblock).
SB_INODES_COUNT = 0x00
SB_BLOCKS_COUNT = 0x04
SB_FREE_BLOCKS = 0x0C
SB_FREE_INODES = 0x10
SB_FIRST_DATA_BLOCK = 0x14
SB_LOG_BLOCK_SIZE = 0x18
SB_BLOCKS_PER_GROUP = 0x20
SB_INODES_PER_GROUP = 0x28
SB_MAGIC = 0x38
SB_REV_LEVEL = 0x4C
SB_INODE_SIZE = 0x58
SB_FEATURE_INCOMPAT = 0x60
SB_FEATURE_RO_COMPAT = 0x64
SB_UUID = 0x68

INCOMPAT_EXTENTS = 0x0040
INCOMPAT_64BIT = 0x0080

#: ``uninit_bg``.  Every group descriptor carries a CRC-16 once this is set.
RO_COMPAT_GDT_CSUM = 0x0010

SUPERBLOCK_OFFSET = 1024
SUPERBLOCK_SIZE = 1024


class ExtError(Exception):
    """Raised when a filesystem cannot be parsed or safely modified."""


def _ceil_div(a: int, b: int) -> int:
    return -(-a // b)


def _crc16(data: bytes, seed: int = 0xFFFF) -> int:
    """CRC-16 with the reflected 0x8005 polynomial, as e2fsprogs uses.

    Seed with a previous result to chain: ``crc = _crc16(chunk, crc)``.  This is
    the routine behind ext4's group-descriptor and directory-block checksums.
    """
    crc = seed & 0xFFFF
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ 0xA001 if crc & 1 else crc >> 1
    return crc & 0xFFFF


def _set_bit(bitmap: bytearray, index: int) -> None:
    bitmap[index // 8] |= 1 << (index % 8)


# Read-only, so it accepts the `bytearray` buffers the callers build in place
# rather than forcing a copy at every call site.
def _get_bit(bitmap: bytes | bytearray, index: int) -> int:
    return (bitmap[index // 8] >> (index % 8)) & 1


@dataclass(frozen=True)
class DirEntry:
    inode: int
    name: str
    file_type: int

    @property
    def is_dir(self) -> bool:
        return self.file_type == FT_DIR


@dataclass
class Inode:
    number: int
    mode: int
    size: int
    links: int
    uid: int
    gid: int
    mtime: int
    blocks: list[int]  # the 15 pointer slots, incl. indirect ones
    raw: bytes

    @property
    def is_file(self) -> bool:
        return (self.mode & S_IFMT) == S_IFREG

    @property
    def is_dir(self) -> bool:
        return (self.mode & S_IFMT) == S_IFDIR


class Ext2:
    """A read/write view over an ext2/ext4 filesystem on a block device.

    The backing object is a :class:`~disk.device.Device`: it needs
    ``read_at``, ``write_at`` and ``write_blocks``.  Anything satisfying that
    works -- a VDI, a raw image, a partition, or a plain file -- which is what
    keeps this module testable without a container.
    """

    def __init__(self, device, *, writable: bool = False) -> None:
        self.dev = device
        self.writable = writable
        sb = self.dev.read_at(SUPERBLOCK_OFFSET, SUPERBLOCK_SIZE)
        if len(sb) < SUPERBLOCK_SIZE:
            raise ExtError("could not read a full superblock")
        magic = struct.unpack_from("<H", sb, SB_MAGIC)[0]
        if magic != EXT2_MAGIC:
            raise ExtError(
                f"not an ext2/ext4 filesystem: magic {magic:#06x} at "
                f"offset {SUPERBLOCK_OFFSET + SB_MAGIC} (expected {EXT2_MAGIC:#06x})"
            )
        self.sb = sb
        log_bs = struct.unpack_from("<I", sb, SB_LOG_BLOCK_SIZE)[0]
        if log_bs > 6:
            raise ExtError(f"implausible s_log_block_size {log_bs}")
        self.block_size = 1024 << log_bs
        self.first_data_block = struct.unpack_from("<I", sb, SB_FIRST_DATA_BLOCK)[0]
        self.blocks_count = struct.unpack_from("<I", sb, SB_BLOCKS_COUNT)[0]
        self.inodes_count = struct.unpack_from("<I", sb, SB_INODES_COUNT)[0]
        self.blocks_per_group = struct.unpack_from("<I", sb, SB_BLOCKS_PER_GROUP)[0]
        self.inodes_per_group = struct.unpack_from("<I", sb, SB_INODES_PER_GROUP)[0]
        self.rev_level = struct.unpack_from("<I", sb, SB_REV_LEVEL)[0]
        self.inode_size = struct.unpack_from("<H", sb, SB_INODE_SIZE)[0] if self.rev_level else 128
        if self.inode_size == 0:
            self.inode_size = 128
        self.incompat = struct.unpack_from("<I", sb, SB_FEATURE_INCOMPAT)[0]
        # Group-descriptor checksums are seeded with the filesystem UUID, so it
        # has to be kept for any descriptor rewrite to checksum correctly.
        self.ro_compat = struct.unpack_from("<I", sb, SB_FEATURE_RO_COMPAT)[0]
        self.uuid = sb[SB_UUID : SB_UUID + 16]
        # Deduplication changes what "the file owns this block" means, so the
        # free paths have to know about it.  Computed on demand by
        # has_shared_blocks(); see that property for why it is not read from a
        # feature bit.
        self._shared_blocks_cache: bool | None = None
        if self.incompat & INCOMPAT_EXTENTS:
            # extents replace the classic 15-pointer block map with a B-tree
            # rooted in i_block.  Supported (see _extent_blocks), but the flag
            # is recorded so callers can tell which layout is in play.
            self.uses_extents = True
        else:
            self.uses_extents = False
        if self.blocks_per_group == 0 or self.inodes_per_group == 0:
            raise ExtError("superblock has zero blocks_per_group/inodes_per_group")
        self._inode_table_cache: dict[int, int] = {}

    # -- helpers -----------------------------------------------------------
    @property
    def free_blocks(self) -> int:
        return struct.unpack_from("<I", self.dev.read_at(SUPERBLOCK_OFFSET, 1024), SB_FREE_BLOCKS)[
            0
        ]

    @property
    def free_inodes(self) -> int:
        return struct.unpack_from("<I", self.dev.read_at(SUPERBLOCK_OFFSET, 1024), SB_FREE_INODES)[
            0
        ]

    def _require_writable(self) -> None:
        if not self.writable:
            raise ExtError("filesystem opened read-only")

    def block_offset(self, block: int) -> int:
        if not 0 <= block < self.blocks_count:
            raise ExtError(
                f"block {block} is outside the filesystem (blocks_count={self.blocks_count})"
            )
        return block * self.block_size

    def read_block(self, block: int) -> bytes:
        return self.dev.read_at(self.block_offset(block), self.block_size)

    def group_descriptor(self, group: int) -> bytes:
        """Group descriptors follow the superblock's block."""
        gd_block = self.first_data_block + 1
        off = self.block_offset(gd_block) + group * 32
        return self.dev.read_at(off, 32)

    def inode_table_block(self, group: int) -> int:
        if group not in self._inode_table_cache:
            gd = self.group_descriptor(group)
            self._inode_table_cache[group] = struct.unpack_from("<I", gd, 8)[0]
        return self._inode_table_cache[group]

    # -- inodes ------------------------------------------------------------
    def read_inode(self, number: int) -> Inode:
        if not 1 <= number <= self.inodes_count:
            raise ExtError(f"inode {number} is out of range (inodes_count={self.inodes_count})")
        group = (number - 1) // self.inodes_per_group
        index = (number - 1) % self.inodes_per_group
        off = self.block_offset(self.inode_table_block(group)) + index * self.inode_size
        raw = self.dev.read_at(off, self.inode_size)
        if len(raw) < 128:
            raise ExtError(f"short read for inode {number}")
        mode = struct.unpack_from("<H", raw, 0)[0]
        uid = struct.unpack_from("<H", raw, 2)[0]
        size = struct.unpack_from("<I", raw, 4)[0]
        mtime = struct.unpack_from("<I", raw, 8)[0]
        gid = struct.unpack_from("<H", raw, 24)[0]
        links = struct.unpack_from("<H", raw, 26)[0]
        blocks = list(struct.unpack_from("<15I", raw, 40))
        if self.inode_size > 128:
            # High 32 bits of i_size_high for regular files (rev 1 + large file).
            size_hi = struct.unpack_from("<I", raw, 108)[0]
            if (mode & S_IFMT) == S_IFREG and size_hi:
                size |= size_hi << 32
        return Inode(
            number=number,
            mode=mode,
            size=size,
            links=links,
            uid=uid,
            gid=gid,
            mtime=mtime,
            blocks=blocks,
            raw=raw,
        )

    def write_inode(self, inode: Inode) -> None:
        self._require_writable()
        group = (inode.number - 1) // self.inodes_per_group
        index = (inode.number - 1) % self.inodes_per_group
        off = self.block_offset(self.inode_table_block(group)) + index * self.inode_size
        raw = bytearray(inode.raw)
        struct.pack_into("<I", raw, 4, inode.size & 0xFFFFFFFF)
        if self.uses_extents:
            # i_blocks counts 512-byte sectors actually allocated.  It must be
            # derived from the tree that is *about to be written*, so pack the
            # new i_block into `raw` first and read the runs back from there.
            # Computing it from the incoming `inode.raw` instead double-counted:
            # that field still held whatever the previous call wrote, so the new
            # tree got added to the old one (e2fsck reported 170,768 sectors
            # where 85,384 was correct -- exactly twice the data blocks).
            struct.pack_into("<15I", raw, 40, *inode.blocks)
            sectors = 0
            for _logical, _physical, length in self._extent_runs(bytes(raw)):
                sectors += length * (self.block_size // 512)
            for _ in range(len(self._extent_tree_blocks_from(bytes(raw)))):
                sectors += self.block_size // 512
        else:
            # Classic block map: i_blocks counts the data blocks *and* the
            # indirect tables that address them.  Counting only the 15 pointer
            # slots in ``inode.blocks`` was wrong by orders of magnitude -- a
            # 12 MiB file has 15 pointers and 12,300 blocks, so e2fsck reported
            # "i_blocks is 28, should be 28356".  The slots themselves are the
            # indirect tables (slots 12-14) plus the direct pointers (0-11).
            data_blocks = sum(1 for b in self._block_map(inode) if b)
            sectors = (data_blocks + len(self._indirect_tables(inode))) * (self.block_size // 512)
        struct.pack_into("<I", raw, 28, sectors)
        struct.pack_into("<15I", raw, 40, *inode.blocks)
        if self.inode_size > 128 and inode.size >> 32:
            struct.pack_into("<I", raw, 108, inode.size >> 32)
        self.dev.write_at(off, bytes(raw))
        inode.raw = bytes(raw)

    def _extent_blocks(self, inode: Inode) -> list[int]:
        """Resolve data blocks from an extent tree rooted in ``i_block``.

        An extent maps a run of logical blocks to a contiguous run of physical
        blocks, so it is far more compact than a block map -- a 41 MB APK here
        is described by only 35 extents.

        The inode's 60-byte ``i_block`` area holds an ``ext4_extent_header``::

            u16 eh_magic     (0xF30A)
            u16 eh_entries
            u16 eh_max
            u16 eh_depth     0 = this node holds extents, >0 = it holds indexes
            u32 eh_generation

        followed by ``eh_entries`` records of 12 bytes each::

            u32 ee_block     first logical block covered
            u16 ee_len       block count (see note below)
            u16 ee_start_hi
            u32 ee_start_lo  first physical block

        ``ee_len > 32768`` marks an *uninitialised* extent (a preallocated
        hole), whose blocks read as zeros; the real length is ``ee_len-32768``.
        Interior nodes instead hold 12-byte ``ext4_extent_idx`` records whose
        last 4 bytes are the child block number.
        """
        EXTENT_MAGIC = 0xF30A
        EXTENT_UNINIT = 32768
        if inode.size == 0:
            return []
        magic = struct.unpack_from("<H", inode.raw, 40)[0]
        if magic != EXTENT_MAGIC:
            raise ExtError(
                f"inode {inode.number}: expected extent magic {EXTENT_MAGIC:#06x} "
                f"at i_block, found {magic:#06x}"
            )

        # Sparse files are addressed by logical index, so build a map rather
        # than a dense list.
        mapping: dict[int, int] = {}
        uninit: set[int] = set()

        def walk(node: bytes, base_off: int) -> None:
            entries = struct.unpack_from("<H", node, base_off + 2)[0]
            depth = struct.unpack_from("<H", node, base_off + 6)[0]
            for i in range(entries):
                off = base_off + 12 + i * 12
                if depth == 0:
                    logical = struct.unpack_from("<I", node, off)[0]
                    raw_len = struct.unpack_from("<H", node, off + 4)[0]
                    start_hi = struct.unpack_from("<H", node, off + 6)[0]
                    start_lo = struct.unpack_from("<I", node, off + 8)[0]
                    start = (start_hi << 32) | start_lo
                    if raw_len > EXTENT_UNINIT:
                        length = raw_len - EXTENT_UNINIT
                        for k in range(length):
                            mapping[logical + k] = start + k
                            uninit.add(logical + k)
                    else:
                        for k in range(raw_len):
                            mapping[logical + k] = start + k
                else:
                    # An interior node holds ``ext4_extent_idx`` records, whose
                    # layout differs from an extent's::
                    #
                    #   u32 ei_block      first logical block covered
                    #   u32 ei_leaf_lo    low 32 bits of the child block
                    #   u16 ei_leaf_hi    high 16 bits
                    #   u16 ei_unused
                    #
                    # Reading these as extents (start at +8, length at +4) is
                    # how this first went wrong: it yielded a start block of
                    # 0x400000000, far outside a 421,086-block filesystem.
                    child_lo = struct.unpack_from("<I", node, off + 4)[0]
                    child_hi = struct.unpack_from("<H", node, off + 8)[0]
                    child = (child_hi << 32) | child_lo
                    if child == 0:
                        raise ExtError(
                            f"inode {inode.number}: extent index {i} at depth "
                            f"{depth} points at block 0"
                        )
                    if not 0 < child < self.blocks_count:
                        raise ExtError(
                            f"inode {inode.number}: extent index {i} points at "
                            f"block {child}, outside the filesystem "
                            f"(blocks_count={self.blocks_count})"
                        )
                    walk(self.read_block(child), 0)

        # The inode's own 60-byte i_block is the tree root.  When its depth is
        # 0 it holds extents directly; when it is > 0 it holds indexes, and
        # walk() follows them.  Either way the entry point is the same.
        walk(inode.raw, 40)

        need = (inode.size + self.block_size - 1) // self.block_size
        blocks: list[int] = []
        for index in range(need):
            if index in mapping and index not in uninit:
                blocks.append(mapping[index])
            else:
                # A hole (or uninitialised extent): zero-filled, and writing
                # over it is not supported by this reader.
                blocks.append(0)
        return blocks

    def _extent_runs(self, raw: bytes) -> list[tuple[int, int, int]]:
        """The ``(logical, physical, length)`` runs of an extent tree.

        Walks the tree rooted in ``raw[40:100]`` and returns initialised
        extents only.  Used to compute ``i_blocks`` from what the tree really
        describes, rather than from an inode's 15 pointer slots.
        """
        EXTENT_MAGIC = 0xF30A
        EXTENT_UNINIT = 32768
        if len(raw) < 100:
            return []
        if struct.unpack_from("<H", raw, 40)[0] != EXTENT_MAGIC:
            return []
        runs: list[tuple[int, int, int]] = []

        def walk(node: bytes, base_off: int) -> None:
            entries = struct.unpack_from("<H", node, base_off + 2)[0]
            depth = struct.unpack_from("<H", node, base_off + 6)[0]
            for i in range(entries):
                off = base_off + 12 + i * 12
                if depth == 0:
                    logical = struct.unpack_from("<I", node, off)[0]
                    raw_len = struct.unpack_from("<H", node, off + 4)[0]
                    start_hi = struct.unpack_from("<H", node, off + 6)[0]
                    start_lo = struct.unpack_from("<I", node, off + 8)[0]
                    start = (start_hi << 32) | start_lo
                    if raw_len > EXTENT_UNINIT:
                        continue  # uninitialised: occupies no blocks
                    runs.append((logical, start, raw_len))
                else:
                    child_lo = struct.unpack_from("<I", node, off + 4)[0]
                    child_hi = struct.unpack_from("<H", node, off + 8)[0]
                    child = (child_hi << 32) | child_lo
                    if 0 < child < self.blocks_count:
                        walk(self.read_block(child), 0)

        walk(raw, 40)
        return runs

    def _block_list(self, inode: Inode) -> list[int]:
        """Resolve the inode's data blocks by whichever layout it uses.

        The choice is a property of the *filesystem* (the EXTENTS incompat
        feature), not of the inode type: with that feature enabled, directories
        carry an extent tree in ``i_block`` just as files do.  Routing on
        ``is_file`` here silently mis-parsed every directory, because the
        classic parser then read the extent header as block pointers.
        """
        if self.uses_extents:
            return self._extent_blocks(inode)
        return self._block_map(inode)

    def _indirect_tables(self, inode: Inode) -> list[int]:
        """Every indirect pointer table a classic inode owns.

        Not just the three slots in ``inode.blocks``: a double-indirect table
        points at single-indirect tables, and those are blocks the inode owns
        too.  Counting only the slots under-reported ``i_blocks`` by one block
        per double-indirect table -- e2fsck reported "i_blocks is 28246, should
        be 28356" on a 14 MB kernel, which has 47 of them.  They were also left
        allocated when the file was freed, so the space leaked.
        """
        if self.uses_extents:
            return self._extent_tree_blocks(inode)
        ptrs = list(inode.blocks[:15])
        per = self.block_size // 4
        found: list[int] = []

        def walk(block: int, depth: int) -> None:
            if not block:
                return
            found.append(block)
            if depth == 1:
                return
            for value in struct.unpack_from(f"<{per}I", self.read_block(block), 0):
                if value:
                    walk(value, depth - 1)

        for slot, depth in ((12, 1), (13, 2), (14, 3)):
            if ptrs[slot]:
                walk(ptrs[slot], depth)
        return found

    def _block_map(self, inode: Inode) -> list[int]:
        """Resolve blocks from the classic direct/indirect pointer layout."""
        ptrs = list(inode.blocks[:15])
        per = self.block_size // 4
        out: list[int] = []

        def read_indirect(block: int, depth: int) -> None:
            if block == 0:
                # A hole.  Record zeros so file offsets stay aligned.
                return
            data = self.read_block(block)
            values = struct.unpack_from(f"<{per}I", data, 0)
            for value in values:
                if depth == 1:
                    out.append(value)
                elif value:
                    read_indirect(value, depth - 1)

        out.extend(ptrs[:12])
        if ptrs[12]:
            read_indirect(ptrs[12], 1)
        if ptrs[13]:
            read_indirect(ptrs[13], 2)
        if ptrs[14]:
            read_indirect(ptrs[14], 3)
        return out

    def read_file(self, inode: Inode) -> bytes:
        """Read a regular file's contents."""
        blocks = self._block_list(inode)
        out = bytearray()
        for block in blocks:
            if len(out) >= inode.size:
                break
            if block == 0:
                out += b"\x00" * self.block_size
            else:
                out += self.read_block(block)
        data = bytes(out[: inode.size])
        if len(data) != inode.size:
            raise ExtError(
                f"inode {inode.number}: read {len(data):,} bytes but the inode "
                f"declares {inode.size:,}; the block map is inconsistent"
            )
        return data

    # -- directories -------------------------------------------------------
    def list_dir(self, inode: Inode) -> list[DirEntry]:
        if not inode.is_dir:
            raise ExtError(f"inode {inode.number} is not a directory")
        raw = self.read_file(inode)
        entries: list[DirEntry] = []
        off = 0
        while off + 8 <= len(raw):
            ino, rec_len, name_len, ftype = struct.unpack_from("<IHBB", raw, off)
            if rec_len == 0:
                break
            if rec_len < 8 or off + rec_len > len(raw):
                raise ExtError(
                    f"inode {inode.number}: corrupt directory entry at {off} (rec_len={rec_len})"
                )
            if ino:
                name = raw[off + 8 : off + 8 + name_len].decode("utf-8", "replace")
                entries.append(DirEntry(ino, name, ftype))
            off += rec_len
        return entries

    def lookup(self, path: str, *, root_inode: int = 2) -> Inode:
        """Resolve an absolute path like ``/system/priv-app`` to an inode."""
        current = self.read_inode(root_inode)
        for part in [p for p in path.strip("/").split("/") if p]:
            if not current.is_dir:
                raise ExtError(f"{part!r} is not a directory in {path!r}")
            found = None
            for entry in self.list_dir(current):
                if entry.name == part:
                    found = entry
                    break
            if found is None:
                raise ExtError(f"path not found: {path!r} (missing {part!r})")
            current = self.read_inode(found.inode)
        return current

    def read_path(self, path: str, *, root_inode: int = 2) -> bytes:
        inode = self.lookup(path, root_inode=root_inode)
        if not inode.is_file:
            raise ExtError(f"{path!r} is not a regular file")
        return self.read_file(inode)

    # -- growing -----------------------------------------------------------
    def grow_to(self, new_blocks: int) -> dict[str, int]:
        """Extend the filesystem to ``new_blocks`` blocks, adding groups.

        Needed after a partition grows: the partition table can hand ``sda3``
        more sectors, but the ext2 inside it still believes it is 14 MiB until
        its superblock and group descriptors say otherwise.

        What this does, and what it deliberately does not:

        * raises ``s_blocks_count`` and the free counts;
        * for each new group, places a block bitmap, inode bitmap and inode
          table in the new region and writes a group descriptor for it;
        * leaves every existing group byte-identical, so nothing that is
          already stored has to move.

        That last point is what makes this safe on a populated filesystem: the
        operation only ever appends.
        """
        self._require_writable()
        old_blocks = self.blocks_count
        if new_blocks < old_blocks:
            raise ExtError(f"refusing to shrink from {old_blocks:,} to {new_blocks:,} blocks")
        if new_blocks == old_blocks:
            return {"added_blocks": 0, "added_groups": 0}

        bpg = self.blocks_per_group
        old_groups = _ceil_div(old_blocks, bpg)
        new_groups = _ceil_div(new_blocks, bpg)
        it_blocks = _ceil_div(self.inodes_per_group * self.inode_size, self.block_size)

        if new_groups == old_groups:
            extra = new_blocks - old_blocks
            # Raise the count first: block_offset() validates against it, and
            # the added blocks are outside the old extent by definition.
            self._set_blocks_count(new_blocks)
            self._adjust_group_free(old_groups - 1, extra)
            return {"added_blocks": extra, "added_groups": 0}

        # The new blocks lie beyond the current s_blocks_count, and
        # block_offset() refuses to address anything past it. Raise the count up
        # front so the metadata writes below land in the extended region; every
        # existing group is still byte-identical, so nothing can be disturbed.
        self._set_blocks_count(new_blocks)

        free_added = 0

        for group in range(old_groups, new_groups):
            # group_bounds() accounts for the boot block: for a 1 KiB block
            # size the groups are offset by one, and laying metadata out at
            # group * bpg instead would put each new group's bitmap one block
            # early -- inside the previous group, whose bitmap bit for that
            # block says something else entirely.
            group_start = self.first_data_block + group * bpg
            group_end = min(group_start + bpg, new_blocks)
            size = group_end - group_start

            # Metadata must live INSIDE its own group.  Placing it at a global
            # cursor instead puts group N's bitmaps in group N-1's range, which
            # makes the free counts nonsense -- a group ends up claiming more
            # free blocks than it has, which is how this was caught.
            #
            # The first block of each group is reserved for the group's own
            # bookkeeping, matching where the existing groups put theirs.
            bb = group_start
            ib = group_start + 1
            it = group_start + 2
            metadata_end = it + it_blocks
            if metadata_end > group_end:
                raise ExtError(
                    f"group {group} cannot hold its own metadata: needs blocks "
                    f"through {metadata_end - 1:,} but the group ends at "
                    f"{group_end - 1:,}"
                )

            # The superblock and group descriptors are replicated at the start
            # of every group, as ext2 requires for a filesystem of this vintage.
            # Copying them verbatim keeps that invariant.
            self._replicate_superblock_and_gdt(group_start)

            # Reserve the metadata blocks: set their bits in the block bitmap.
            bb_data = bytearray(self.block_size)
            for block in range(group_start, metadata_end):
                _set_bit(bb_data, block - group_start)
            # Padding: a short final group has bits past its end, and mke2fs
            # sets them.  e2fsck reports a filesystem as corrupt when they are
            # clear ("Padding at end of block bitmap is not set"), so a freshly
            # created group has to set them too.
            for index in range(size, self.blocks_per_group):
                _set_bit(bb_data, index)
            self.dev.write_at(self.block_offset(bb), bytes(bb_data))

            # Inodes beyond s_inodes_count are marked used, as mke2fs does, so
            # that a linear inode scan does not walk non-existent entries.
            usable = self._inodes_in_group(group)
            ib_data = bytearray(self.block_size)
            for i in range(usable, self.inodes_per_group):
                _set_bit(ib_data, i)
            self.dev.write_at(self.block_offset(ib), bytes(ib_data))

            for k in range(it_blocks):
                self.dev.write_at(self.block_offset(it + k), b"\x00" * self.block_size)

            group_free = size - (metadata_end - group_start)
            self._write_group_descriptor(
                group,
                block_bitmap=bb,
                inode_bitmap=ib,
                inode_table=it,
                free_blocks=group_free,
                free_inodes=usable,
                used_dirs=0,
            )
            free_added += group_free

        # Recompute the total from the descriptors, so the superblock cannot
        # drift from the parts it describes.
        self._refresh_group_counts()
        return {
            "added_blocks": free_added,
            "added_groups": new_groups - old_groups,
        }

    def _replicate_superblock_and_gdt(self, group_start: int) -> None:
        """Copy the superblock and group descriptors to a group's start.

        ext2 keeps a backup of both at the beginning of every block group (the
        "sparse_super" rule: for 1 KiB blocks that is groups 0, 1 and every
        power of 3, 5 and 7, but writing them everywhere is also valid and is
        what the original mke2fs does for filesystems of this size).

        The copy is taken *after* the superblock has been updated with the new
        block count, so the backups agree with the primary rather than carrying
        the old geometry.
        """
        sb = self.dev.read_at(SUPERBLOCK_OFFSET, SUPERBLOCK_SIZE)
        self.dev.write_at(self.block_offset(group_start), sb)

        gdt_block = self.first_data_block + 1
        # Only the descriptors that exist need copying; the table is sized to
        # the number of groups.
        groups = _ceil_div(self.blocks_count, self.blocks_per_group)
        table_bytes = groups * 32
        gdt = self.dev.read_at(self.block_offset(gdt_block), table_bytes)
        self.dev.write_at(self.block_offset(group_start + 1), gdt)

    def _inodes_in_group(self, group: int) -> int:
        """Inodes of ``group`` that are within ``s_inodes_count``."""
        first = group * self.inodes_per_group
        if first >= self.inodes_count:
            return 0
        return min(self.inodes_per_group, self.inodes_count - first)

    def group_bounds(self, group: int) -> tuple[int, int]:
        """The half-open block range ``[start, end)`` that group ``group`` covers.

        **This is not ``group * blocks_per_group``.**  For a 1 KiB block size
        ext2 reserves block 0 as the boot block, so ``s_first_data_block`` is 1
        and group *N* begins at ``1 + N * blocks_per_group`` -- one block later
        than the naive product.  Group 0 is the visible case: it covers blocks
        1..7160, not 0..7159.

        Every bitmap bit is an index into *its own group's* range, so getting
        this wrong shifts every allocation, free and count by one bit.  It went
        unnoticed because the boot partition's bitmaps are nearly full and a
        one-bit shift usually lands on another used bit; it surfaced only when
        a write had to free the block at a group boundary.

        For a 4 KiB block size ``first_data_block`` is 0 and the naive product
        happens to be right, which is why the 4 KiB system partition never
        showed the problem.
        """
        start = self.first_data_block + group * self.blocks_per_group
        end = min(start + self.blocks_per_group, self.blocks_count)
        return start, end

    def group_of(self, block: int) -> int:
        """Which group a block belongs to, accounting for the boot block."""
        return (block - self.first_data_block) // self.blocks_per_group

    def group_index(self, block: int) -> int:
        """The bit index of ``block`` within its own group's bitmap."""
        return (block - self.first_data_block) % self.blocks_per_group

    def is_metadata_block(self, block: int) -> bool:
        """Is ``block`` filesystem metadata rather than file data?

        Metadata is: the boot block, the superblock and group descriptor table,
        and every group's block bitmap, inode bitmap and inode table.  This is
        derived from the descriptors, not from an assumed layout, so group 0
        (whose superblock sits at byte 1024 of block 1) is handled correctly.

        The free/allocate paths both consult this.  A bitmap that has drifted
        can mark a metadata block free, and handing that block to a file -- or
        "freeing" it -- destroys the filesystem structure itself.
        """
        if block == 0:
            return True
        if block >= self.blocks_count:
            return False
        # The block holding the superblock.  At 1 KiB block size the superblock
        # lives at byte 1024 -- inside block 1 -- so this is ``first_data_block``
        # and *not* block 0.
        if block == self.first_data_block:
            return True
        # The descriptor table that follows it, which can span several blocks
        # once there are many groups.
        groups = _ceil_div(self.blocks_count, self.blocks_per_group)
        gdt_block = self.first_data_block + 1
        groups_per_block = max(1, self.block_size // 32)
        for k in range(_ceil_div(groups, groups_per_block)):
            if block == gdt_block + k:
                return True
        group = block // self.blocks_per_group
        if group == 0:
            # Group 0's superblock lives in block 1 at a 1024-byte offset when
            # the block size is 1 KiB; block 0 holds the boot block.
            pass
        else:
            # A replicated superblock at the start of every later group.
            if block == self.group_bounds(group)[0]:
                return True
        gd = self.group_descriptor(group)
        bitmap_block, inode_bitmap_block, table = struct.unpack_from("<III", gd, 0)
        if block in (bitmap_block, inode_bitmap_block):
            return True
        it_blocks = _ceil_div(self.inodes_per_group * self.inode_size, self.block_size)
        return table <= block < table + it_blocks

    @property
    def has_shared_blocks(self) -> bool:
        """Whether any block is referenced by more than one live inode.

        Detected by counting references rather than by trusting a feature bit.
        ``dumpe2fs`` reports ``shared_blocks`` for this filesystem, but that
        string is a libext2fs pseudo-feature that is not present in any of
        ``s_feature_compat``/``_incompat``/``_ro_compat`` (all three were
        checked on the real image: 0x28, 0x42, 0x407b -- none has 0x8000 set).
        Guessing at the encoding is how a free path ends up releasing blocks
        another file still reads, so this asks the filesystem directly.

        The answer is cached: it is only consulted by the unlink and shrink
        paths, and the walk is proportional to the inode count.
        """
        if self._shared_blocks_cache is None:
            self._shared_blocks_cache = bool(self._shared_blocks_in_use())
        return self._shared_blocks_cache

    def _shared_blocks_in_use(self) -> set[int]:
        """Blocks referenced by more than one live inode.

        This filesystem deduplicates: several APKs in ``priv-app`` point at the
        same physical blocks.  A block in that state must never be freed when
        *one* of its owners goes away -- the others still read it.  Freeing it
        leaves the bitmap claiming the block is available while live files
        reference it, which e2fsck reports as
        ``Block bitmap differences: +276491--276500`` and then "repairs" by
        marking them used again.

        Walking every inode is expensive, but this only runs on an unlink or a
        shrink, which happens a handful of times per image edit.
        """
        counts: dict[int, int] = {}
        for number in range(1, self.inodes_count + 1):
            try:
                inode = self.read_inode(number)
            except ExtError:
                continue
            if inode.links == 0:
                continue
            try:
                owned = self._block_list(inode)
            except ExtError:
                continue
            for block in set(b for b in owned if b):
                counts[block] = counts.get(block, 0) + 1
        return {b for b, n in counts.items() if n > 1}

    def unlink_inode(self, number: int) -> int:
        """Delete inode ``number``: clear its links, free its blocks and inode.

        A directory entry removal alone leaves the inode alive and its blocks
        reserved, which e2fsck reports as an unattached inode plus a block
        bitmap that is too full.  Fully unlinking means all three have to agree:
        the directory entry (done by the caller), the link count, and the
        bitmap bits for the data blocks and the inode itself.

        Blocks this filesystem has *deduplicated* are deliberately left
        allocated: another inode still references them, and freeing them would
        corrupt that file.  See :meth:`_shared_blocks_in_use`.

        Returns the number of data blocks actually freed.
        """
        self._require_writable()
        inode = self.read_inode(number)
        if inode.links == 0:
            return 0  # already gone; nothing to do rather than a double free

        if inode.is_dir:
            raise ExtError(
                f"refusing to unlink inode {number}: it is a directory, and "
                f"removing one requires updating its parent's entry count"
            )

        owned = [b for b in self._block_list(inode) if b]
        # Every table the inode owns, including the single-indirect tables a
        # double-indirect table points at.  Listing only the three slots left
        # the inner tables allocated forever.
        tables = self._indirect_tables(inode)

        shared = self._shared_blocks_in_use() if self.has_shared_blocks else set()
        releasable = [b for b in owned + tables if b not in shared]
        freed = self._free_blocks(releasable) if releasable else 0

        # Zero the inode and free its slot in the inode bitmap, which is what
        # e2fsck expects of a deleted entry: dtime set, links zero, no blocks.
        raw = bytearray(self.inode_size)
        struct.pack_into("<H", raw, 0, 0)  # mode: nothing
        struct.pack_into("<H", raw, 26, 0)  # links
        struct.pack_into("<I", raw, 28, 0)  # i_blocks
        struct.pack_into("<I", raw, 20, int(__import__("time").time()))  # dtime
        group = (number - 1) // self.inodes_per_group
        index = (number - 1) % self.inodes_per_group
        off = self.block_offset(self.inode_table_block(group)) + index * self.inode_size
        self.dev.write_at(off, bytes(raw))
        self._inode_table_cache.pop(group, None)

        # Clear the inode's bit and record one more free inode.
        gd = self.group_descriptor(group)
        ib = struct.unpack_from("<I", gd, 4)[0]
        bitmap = bytearray(self.read_block(ib))
        if not _get_bit(bitmap, index):
            raise ExtError(
                f"inode {number} is already marked free in the bitmap but its "
                f"link count was not zero; the filesystem is inconsistent"
            )
        bitmap[index // 8] &= ~(1 << (index % 8))
        self.dev.write_at(self.block_offset(ib), bytes(bitmap))
        free_inodes = struct.unpack_from("<H", gd, 14)[0] + 1
        self._write_group_descriptor_inodes(group, free_inodes)

        sb = bytearray(self.dev.read_at(SUPERBLOCK_OFFSET, SUPERBLOCK_SIZE))
        total = struct.unpack_from("<I", sb, SB_FREE_INODES)[0] + 1
        struct.pack_into("<I", sb, SB_FREE_INODES, total)
        self.dev.write_at(SUPERBLOCK_OFFSET, bytes(sb))
        return freed

    def _write_group_descriptor_inodes(self, group: int, free_inodes: int) -> None:
        gd_block = self.first_data_block + 1
        off = self.block_offset(gd_block) + group * 32
        raw = bytearray(self.dev.read_at(off, 32))
        struct.pack_into("<H", raw, 14, free_inodes & 0xFFFF)
        self._set_group_desc_checksum(group, raw)
        self.dev.write_at(off, bytes(raw))

    def _write_group_descriptor(
        self,
        group: int,
        *,
        block_bitmap: int,
        inode_bitmap: int,
        inode_table: int,
        free_blocks: int,
        free_inodes: int,
        used_dirs: int,
    ) -> None:
        gd_block = self.first_data_block + 1
        off = self.block_offset(gd_block) + group * 32
        raw = bytearray(self.dev.read_at(off, 32))
        struct.pack_into("<I", raw, 0, block_bitmap)
        struct.pack_into("<I", raw, 4, inode_bitmap)
        struct.pack_into("<I", raw, 8, inode_table)
        struct.pack_into("<H", raw, 12, free_blocks & 0xFFFF)
        struct.pack_into("<H", raw, 14, free_inodes & 0xFFFF)
        struct.pack_into("<H", raw, 16, used_dirs & 0xFFFF)
        self._set_group_desc_checksum(group, raw)
        self.dev.write_at(off, bytes(raw))
        self._inode_table_cache.pop(group, None)

    def _set_blocks_count(self, blocks: int) -> None:
        sb = bytearray(self.dev.read_at(SUPERBLOCK_OFFSET, SUPERBLOCK_SIZE))
        struct.pack_into("<I", sb, SB_BLOCKS_COUNT, blocks)
        self.dev.write_at(SUPERBLOCK_OFFSET, bytes(sb))
        self.blocks_count = blocks

    def _adjust_group_free(self, group: int, delta: int) -> None:
        gd_block = self.first_data_block + 1
        off = self.block_offset(gd_block) + group * 32
        raw = bytearray(self.dev.read_at(off, 32))
        current = struct.unpack_from("<H", raw, 12)[0]
        struct.pack_into("<H", raw, 12, (current + delta) & 0xFFFF)
        self.dev.write_at(off, bytes(raw))
        self._refresh_group_counts()

    def _extent_tree_blocks_from(self, raw: bytes) -> list[int]:
        """Blocks used by the extent tree held in ``raw``'s i_block: leaves
        and index nodes only, never the data blocks."""
        EXTENT_MAGIC = 0xF30A
        if len(raw) < 100:
            return []
        if struct.unpack_from("<H", raw, 40)[0] != EXTENT_MAGIC:
            return []
        found: list[int] = []

        def walk(node: bytes, base_off: int) -> None:
            entries = struct.unpack_from("<H", node, base_off + 2)[0]
            depth = struct.unpack_from("<H", node, base_off + 6)[0]
            if depth == 0:
                return  # a leaf's entries describe data, not tree blocks
            for i in range(entries):
                off = base_off + 12 + i * 12
                child_lo = struct.unpack_from("<I", node, off + 4)[0]
                child_hi = struct.unpack_from("<H", node, off + 8)[0]
                child = (child_hi << 32) | child_lo
                if 0 < child < self.blocks_count:
                    found.append(child)
                    walk(self.read_block(child), 0)

        walk(raw, 40)
        return found

    def _extent_tree_blocks(self, inode: Inode) -> list[int]:
        """Every block belonging to an extent tree: leaves plus index nodes."""
        return self._extent_tree_blocks_from(inode.raw)

    def _refresh_group_counts(self) -> None:
        """Recompute every free count from the bitmaps themselves.

        The bitmaps are the ground truth: a block is free exactly when its bit
        is clear.  Deriving the descriptor counts and the superblock total from
        them means the three can never disagree, which is the failure mode that
        matters -- a filesystem whose counts are optimistic corrupts itself the
        next time it allocates.
        """
        groups = _ceil_div(self.blocks_count, self.blocks_per_group)
        total = 0
        for group in range(groups):
            gd = self.group_descriptor(group)
            bb = struct.unpack_from("<I", gd, 0)[0]
            bitmap = self.read_block(bb)
            group_start, group_end = self.group_bounds(group)
            size = group_end - group_start
            free = sum(1 for i in range(size) if not _get_bit(bitmap, i))
            self._write_group_descriptor_free(group, free)
            total += free
        sb = bytearray(self.dev.read_at(SUPERBLOCK_OFFSET, SUPERBLOCK_SIZE))
        struct.pack_into("<I", sb, SB_FREE_BLOCKS, total)
        self.dev.write_at(SUPERBLOCK_OFFSET, bytes(sb))

    def verify_geometry(self) -> list[str]:
        """Check that the superblock and group descriptors agree. Read-only.

        Called after a resize: a filesystem whose free counts disagree with its
        group descriptors still mounts, and then corrupts itself later.
        """
        problems: list[str] = []
        groups = _ceil_div(self.blocks_count, self.blocks_per_group)
        bpg = self.blocks_per_group
        counted = 0
        for group in range(groups):
            gd = self.group_descriptor(group)
            for label, offset in (
                ("block bitmap", 0),
                ("inode bitmap", 4),
                ("inode table", 8),
            ):
                block = struct.unpack_from("<I", gd, offset)[0]
                if not 0 < block < self.blocks_count:
                    problems.append(
                        f"group {group}: {label} block {block:,} is outside the "
                        f"filesystem ({self.blocks_count:,} blocks)"
                    )
            # Count free blocks from the *bitmap*, which is the ground truth,
            # rather than from ``bg_free_blocks_count_lo``.
            #
            # That descriptor field is 16 bits while the superblock's total is
            # 32, so on any filesystem with more than 65,535 free blocks the
            # two can never be equal -- the comparison below used to compare
            # the sum of the truncated halves against the full total and report
            # a phantom inconsistency on exactly the large images that matter.
            # The bitmaps have no such ceiling, and ``_refresh_group_counts``
            # already derives the counts from them, so this agrees with the
            # writer by construction.
            bb = struct.unpack_from("<I", gd, 0)[0]
            if not 0 < bb < self.blocks_count:
                continue
            bitmap = self.read_block(bb)
            group_start, group_end = self.group_bounds(group)
            counted += sum(1 for i in range(group_end - group_start) if not _get_bit(bitmap, i))
        sb = self.dev.read_at(SUPERBLOCK_OFFSET, SUPERBLOCK_SIZE)
        declared = struct.unpack_from("<I", sb, SB_FREE_BLOCKS)[0]
        if counted != declared:
            problems.append(
                f"the block bitmaps account for {counted:,} free blocks but "
                f"the superblock declares {declared:,}"
            )
        # Trailing bits in a short final group address no real block.  mke2fs
        # *sets* them as padding, and e2fsck requires that ("Padding at end of
        # block bitmap is not set"), so a set bit here is correct and a clear
        # one is the anomaly.  Note the direction: an earlier version of this
        # check had it backwards and reported the pristine image as drifted,
        # while the writer dutifully cleared the bits and made e2fsck complain.
        bpg = self.blocks_per_group
        for group in range(groups):
            gd = self.group_descriptor(group)
            bb = struct.unpack_from("<I", gd, 0)[0]
            bitmap = self.read_block(bb)
            group_start, group_end = self.group_bounds(group)
            clear = sum(
                1 for bit in range(group_end - group_start, bpg) if not _get_bit(bitmap, bit)
            )
            if clear:
                problems.append(
                    f"group {group}: block bitmap has {clear:,} padding bits "
                    f"clear past the end of the group; mke2fs sets these and "
                    f"e2fsck expects them set"
                )
        return problems

    def _allocate_blocks(self, count: int) -> list[int]:
        """Claim ``count`` free blocks, updating the bitmaps and counts.

        This is the operation the in-place writer deliberately avoids, because
        getting it wrong corrupts a filesystem silently.  It is safe here only
        because the caller has already made room: the partition grew and
        :meth:`grow_to` added a matching number of free blocks, so the bitmap
        says the space exists.

        The allocation walk is the reverse of :meth:`_block_map`: find a group
        with free blocks, find a clear bit, set it, and decrement the counts in
        both the group descriptor and the superblock.
        """
        self._require_writable()
        if count <= 0:
            return []

        groups = _ceil_div(self.blocks_count, self.blocks_per_group)
        free_per_group: list[int] = []
        for group in range(groups):
            gd = self.group_descriptor(group)
            free_per_group.append(struct.unpack_from("<H", gd, 12)[0])
        if sum(free_per_group) < count:
            raise ExtError(
                f"need {count:,} blocks but the filesystem reports only "
                f"{sum(free_per_group):,} free; grow the partition and run "
                f"grow_to() first"
            )

        allocated: list[int] = []
        for group in range(groups):
            if len(allocated) >= count:
                break
            if free_per_group[group] == 0:
                continue

            gd = self.group_descriptor(group)
            bb = struct.unpack_from("<I", gd, 0)[0]
            bitmap = bytearray(self.read_block(bb))
            group_start, group_end = self.group_bounds(group)

            taken = 0
            for index in range(group_end - group_start):
                if len(allocated) >= count:
                    break
                if _get_bit(bitmap, index):
                    continue
                block = group_start + index
                # Never hand out metadata -- this group's bitmap/descriptor, or
                # any other block the filesystem structure lives in.  A bitmap
                # that has drifted can mark such a block free, and writing file
                # data there destroys the structure itself.
                if self.is_metadata_block(block):
                    continue
                _set_bit(bitmap, index)
                allocated.append(block)
                taken += 1

            # Bits past the end of a short final group are deliberately left
            # alone.  They address no real block, and mke2fs *sets* them as
            # padding; clearing them makes e2fsck report "Padding at end of
            # block bitmap is not set", which is a complaint about exactly this
            # edit.  They are not counted as free either, because the scan above
            # is bounded by the group's real size.
            if taken:
                self.dev.write_at(self.block_offset(bb), bytes(bitmap))
                self._write_group_descriptor_free(group, free_per_group[group] - taken)
                free_per_group[group] -= taken

        if len(allocated) != count:
            raise ExtError(
                f"allocated {len(allocated):,} blocks but {count:,} were needed; "
                f"the bitmaps disagree with the free counts"
            )
        self._refresh_group_counts()
        return allocated

    def _set_group_desc_checksum(self, group: int, raw: bytearray) -> None:
        """Recompute a group descriptor's checksum, in place.

        With the ``uninit_bg`` (GDT_CSUM) feature -- which the guest's system
        partition has -- every group descriptor carries a CRC-16 in its last
        two bytes.  Leaving it stale is not cosmetic: e2fsck reports the
        descriptor as invalid, and a kernel told to mount ``errors=panic`` can
        refuse the filesystem outright.

        The algorithm is e2fsprogs' ``ext2fs_group_desc_csum``: CRC-16 (the
        reflected 0x8005 polynomial) seeded with the filesystem UUID, then the
        group number as a little-endian u32, then the descriptor up to -- but
        not including -- the checksum field itself.  Determined by matching
        every descriptor in the real image, including one that e2fsck had
        already validated.
        """
        if not (self.ro_compat & RO_COMPAT_GDT_CSUM):
            return
        crc = _crc16(self.uuid)
        crc = _crc16(struct.pack("<I", group), crc)
        crc = _crc16(bytes(raw[:30]), crc)
        struct.pack_into("<H", raw, 30, crc)

    def _write_group_descriptor_free(self, group: int, free_blocks: int) -> None:
        gd_block = self.first_data_block + 1
        off = self.block_offset(gd_block) + group * 32
        raw = bytearray(self.dev.read_at(off, 32))
        struct.pack_into("<H", raw, 12, free_blocks & 0xFFFF)
        self._set_group_desc_checksum(group, raw)
        self.dev.write_at(off, bytes(raw))

    def _write_extent_tree(self, blocks: list[int]) -> tuple[bytes, list[int]]:
        """Build the ``i_block`` contents for an extent-based inode.

        ``blocks`` is the file's *logical* block list; a ``0`` entry is a hole
        (a block the file never wrote, which reads back as zeros).  Holes are
        left out of the extent tree entirely -- that is exactly how ext4
        represents them, and it is why an APK with alignment padding occupies
        fewer blocks than its size implies.

        Returns ``(i_block_bytes, tree_blocks)`` where ``tree_blocks`` are the
        non-inline tree nodes that were allocated, so the caller can account
        for them and free them on a later rewrite.

        Layout: a contiguous run of logical blocks sharing consecutive
        physical blocks becomes one extent.  The root node lives inline in
        ``i_block`` while it fits (4 extents, or 4 indices); beyond that the
        tree is given a level, with the root holding index entries that point
        at leaf blocks.
        """
        EXTENT_MAGIC = 0xF30A
        ENTRY = 12
        # The inline root has 60 bytes: a 12-byte header plus up to 4 entries.
        MAX_INLINE = (60 - 12) // ENTRY
        per_node = (self.block_size - 12) // ENTRY

        runs: list[tuple[int, int, int]] = []  # (logical, physical, length)
        index = 0
        total = len(blocks)
        while index < total:
            if blocks[index] == 0:
                # Hole: skip it and any following holes.
                while index < total and blocks[index] == 0:
                    index += 1
                continue
            start_logical = index
            start_physical = blocks[index]
            length = 0
            while (
                index < total
                and blocks[index] != 0
                and blocks[index] == start_physical + length
                and length < 32768  # ee_len is a signed 16-bit count
            ):
                length += 1
                index += 1
            runs.append((start_logical, start_physical, length))

        tree_blocks: list[int] = []

        def pack_extent(buf: bytearray, off: int, run) -> None:
            logical, physical, length = run
            struct.pack_into(
                "<IHHI", buf, off, logical, length, physical >> 32, physical & 0xFFFFFFFF
            )

        def pack_index(buf: bytearray, off: int, logical: int, child: int) -> None:
            struct.pack_into("<IIH", buf, off, logical, child & 0xFFFFFFFF, child >> 32)

        root = bytearray(60)
        if len(runs) <= MAX_INLINE:
            struct.pack_into("<HHHH", root, 0, EXTENT_MAGIC, len(runs), MAX_INLINE, 0)
            for i, run in enumerate(runs):
                pack_extent(root, 12 + i * ENTRY, run)
            return bytes(root), tree_blocks

        # More runs than fit inline: one level of leaves under the root.
        struct.pack_into("<HHHH", root, 0, EXTENT_MAGIC, 0, MAX_INLINE, 1)
        leaves: list[tuple[int, int]] = []  # (first logical, leaf block)
        position = 0
        while position < len(runs):
            chunk = runs[position : position + per_node]
            leaf = self._allocate_blocks(1)[0]
            tree_blocks.append(leaf)
            buf = bytearray(self.block_size)
            struct.pack_into("<HHHH", buf, 0, EXTENT_MAGIC, len(chunk), per_node, 0)
            for i, run in enumerate(chunk):
                pack_extent(buf, 12 + i * ENTRY, run)
            self.dev.write_at(self.block_offset(leaf), bytes(buf))
            leaves.append((chunk[0][0], leaf))
            position += len(chunk)

        if len(leaves) > MAX_INLINE:
            raise ExtError(
                f"{len(runs):,} extents need more than one index level "
                f"({len(leaves):,} leaves against {MAX_INLINE} inline slots); "
                f"a deeper extent tree is not implemented"
            )
        struct.pack_into("<H", root, 2, len(leaves))
        for i, (logical, leaf) in enumerate(leaves):
            pack_index(root, 12 + i * ENTRY, logical, leaf)
        return bytes(root), tree_blocks

    def _write_data_blocks(self, blocks: list[int], data: bytes, *, describe: str = "") -> None:
        """Write ``data`` across ``blocks`` in one batched call.

        ``write_blocks`` is *required* of the device, not probed for.  It used
        to be reached through ``getattr(self.dev, "write_blocks", None)``, with
        a per-block fallback -- which meant a device that lost the method went
        quietly back to issuing one write per 4 KiB block.  On the Windows 9p
        mount this runs against that is the difference between 0.4 s and 228 s
        for a 43 MB file, and nothing would have said so.

        Every device in the stack provides it: ``Device.write_blocks`` has a
        correct default, so a plain file costs one write per block exactly as
        the fallback did, and a container coalesces.
        """
        block_size = self.block_size
        writes: list[tuple[int, bytes]] = []
        for index, block in enumerate(blocks):
            start = index * block_size
            chunk = data[start : start + block_size]
            if len(chunk) < block_size:
                chunk = chunk + b"\x00" * (block_size - len(chunk))
            writes.append((self.block_offset(block), chunk))
        self.dev.write_blocks(writes)

    def _shrink_extents_in_place(self, inode: Inode, new_size: int) -> int:
        """Truncate an extents inode to ``new_size``, freeing the tail blocks.

        The blocks that remain keep their current physical positions, so the
        data already written stays put and only the tree and the bitmap change.
        Returns the number of blocks freed.

        This is the operation ``replace_file_in_place`` needs when a file gets
        smaller.  Writing a shorter file without shrinking leaves an inode whose
        extent tree still claims the old blocks: reads look fine (the size cuts
        them off) but ``i_blocks`` is wrong, the bitmap keeps those blocks
        reserved forever, and e2fsck reports the filesystem as corrupt.
        """
        keep_blocks = _ceil_div(new_size, self.block_size)
        logical = self._block_list(inode)
        if keep_blocks >= len(logical):
            return 0

        keep = logical[:keep_blocks]
        drop = [b for b in logical[keep_blocks:] if b]
        old_tree = self._extent_tree_blocks(inode)

        # Rebuild the tree over the surviving blocks.  A hole in the kept range
        # stays a hole: _write_extent_tree omits zero entries on purpose.
        tree, new_tree_blocks = self._write_extent_tree(keep)
        raw = bytearray(inode.raw)
        raw[40:100] = tree
        inode.raw = bytes(raw)
        inode.blocks = list(struct.unpack_from("<15I", inode.raw, 40))

        # Free the old tree's nodes and the data blocks that fell off the end.
        # The new tree may have reused one of the old nodes, so exclude it --
        # and on a deduplicating filesystem, exclude anything another inode
        # still points at, or that file's data would be freed underneath it.
        reusable = set(new_tree_blocks) | set(keep)
        stale_tree = [b for b in old_tree if b not in reusable]
        candidates = drop + stale_tree
        if self.has_shared_blocks and candidates:
            shared = self._shared_blocks_in_use()
            candidates = [b for b in candidates if b not in shared]
        freed = self._free_blocks(candidates) if candidates else 0
        self._refresh_group_counts()
        return freed

    def _shrink_block_map_in_place(self, inode: Inode, new_size: int) -> int:
        """Truncate a classic indirect-mapped inode to ``new_size``."""
        keep_blocks = _ceil_div(new_size, self.block_size)
        logical = self._block_list(inode)
        if keep_blocks >= len(logical):
            return 0
        keep = logical[:keep_blocks]
        drop = [b for b in logical[keep_blocks:] if b]
        old_tables = self._indirect_tables(inode)

        ptrs, _ = self._write_indirect_chain(keep)
        reusable = set(ptrs) | set(keep)
        inode.blocks = ptrs
        stale_tables = [b for b in old_tables if b not in reusable]
        freed = self._free_blocks(drop + stale_tables)
        self._refresh_group_counts()
        return freed

    def _write_indirect_chain(self, blocks: list[int]) -> tuple[list[int], list[int]]:
        """Lay out ``blocks`` into the 15 pointer slots, plus indirect blocks.

        Layout for 1 KiB blocks, matching :meth:`_block_map`:

        * slots 0-11 -> direct blocks
        * slot 12    -> single indirect (``per`` entries)
        * slot 13    -> double indirect (``per`` + ``per*per`` entries)

        An 18 MB kernel needs ~18,000 blocks, which fits in direct + single +
        double.  Triple indirection is refused rather than silently truncated.

        Pointer tables themselves consume blocks, so they are allocated first
        and the data blocks follow; the caller has already reserved everything.
        """
        per = self.block_size // 4
        capacity = 12 + per + per * per
        if len(blocks) > capacity:
            raise ExtError(
                f"{len(blocks):,} blocks exceeds what direct+single+double "
                f"indirection can address ({capacity:,}) at "
                f"{self.block_size}-byte blocks; triple indirection is not "
                f"implemented"
            )

        ptrs = [0] * 15
        # Every pointer table this allocates is recorded, so the caller can
        # account for it.  Forgetting them leaks blocks: they are marked used
        # in the bitmap but unreachable from the inode.
        tables: list[int] = []
        remaining = list(blocks)

        for i in range(12):
            if remaining:
                ptrs[i] = remaining.pop(0)

        if remaining:
            table = self._allocate_blocks(1)[0]
            tables.append(table)
            ptrs[12] = table
            chunk = remaining[:per]
            remaining = remaining[per:]
            data = bytearray(self.block_size)
            for i, block in enumerate(chunk):
                struct.pack_into("<I", data, i * 4, block)
            self.dev.write_at(self.block_offset(table), bytes(data))

        if remaining:
            outer_block = self._allocate_blocks(1)[0]
            tables.append(outer_block)
            ptrs[13] = outer_block
            outer = bytearray(self.block_size)
            slot = 0
            while remaining:
                if slot >= per:
                    raise ExtError(
                        "double-indirect table overflowed; the layout calculation is wrong"
                    )
                inner = self._allocate_blocks(1)[0]
                tables.append(inner)
                struct.pack_into("<I", outer, slot * 4, inner)
                chunk = remaining[:per]
                remaining = remaining[per:]
                data = bytearray(self.block_size)
                for i, block in enumerate(chunk):
                    struct.pack_into("<I", data, i * 4, block)
                self.dev.write_at(self.block_offset(inner), bytes(data))
                slot += 1
            self.dev.write_at(self.block_offset(outer_block), bytes(outer))

        return ptrs, tables

    # -- writing -----------------------------------------------------------
    def replace_file_growing(
        self,
        path: str,
        data: bytes,
        *,
        root_inode: int = 2,
        expect_free_blocks: int | None = None,
    ) -> dict[str, int]:
        """Replace a file, allocating new blocks if the data is larger.

        Separate from :meth:`replace_file_in_place` on purpose.  That method
        must never allocate, because it is used on filesystems with no spare
        room and allocation is where the silent-corruption failure mode lives.
        This one allocates, and is only safe once the caller has *made* room --
        by growing the partition and running :meth:`grow_to`.

        ``expect_free_blocks`` records how much free space the caller believes
        exists; if the filesystem disagrees, nothing is written.  That check is
        what stops this being a way to overfill a filesystem by accident.
        """
        self._require_writable()
        inode = self.lookup(path, root_inode=root_inode)
        if not inode.is_file:
            raise ExtError(f"{path!r} is not a regular file")

        if expect_free_blocks is not None:
            actual = self.free_blocks
            if actual < len(data) // self.block_size + 16:
                raise ExtError(
                    f"the filesystem reports only {actual:,} free blocks; "
                    f"{len(data):,} bytes cannot be written safely"
                )

        if len(data) <= inode.size:
            # Shrinking or same-size: no allocation needed.
            self.replace_file_in_place(path, data, root_inode=root_inode)
            return {"allocated": 0, "freed": 0}

        needed = _ceil_div(len(data), self.block_size)
        # The file's logical block list, *including* holes as zeros.  A hole is
        # a block the file never wrote and reads back as zeros; APKs commonly
        # have them (ZIP alignment padding), so assuming every logical block
        # has storage behind it is wrong.
        old_logical = self._block_list(inode)
        old_blocks = [b for b in old_logical if b]
        # The pointer tables the inode owns.  Which slots those are depends on
        # the on-disk layout: an *extents* inode stores a B-tree in those same
        # 60 bytes, so slots 12-14 are index-node entries pointing at leaf
        # blocks -- not indirect tables.  Reading them as indirect pointers
        # yields whatever integers happen to sit there, and freeing those
        # numbers deletes live filesystem structure (block 1, the group
        # descriptor table, is a value that really does occur in an index
        # node).  Use the layout-aware walk instead.
        old_indirect = self._indirect_tables(inode)

        # Free what the old file owned *first*.  Otherwise the allocator has to
        # find room for the entire new file while the old one's blocks sit
        # stranded -- which for a kernel swap means needing ~7 MB more than the
        # filesystem actually has, and failing for no good reason.
        #
        # This is safe because the inode is updated further down and the image
        # is restored from backup if anything fails in between.
        freed = self._free_blocks(old_blocks + old_indirect)

        new_blocks = self._allocate_blocks(needed)
        total_allocated = needed

        # Write the file contents into the new blocks.  Trailing bytes of the
        # last block are zero-filled so the unused tail of the final block does
        # not leak whatever was there before.
        self._write_data_blocks(new_blocks, data)

        if self.uses_extents:
            # An extents inode must get an extent tree.  Writing the classic
            # indirect chain into it would put pointer tables where the tree
            # header belongs, and the filesystem would be unreadable.
            tree, tree_blocks = self._write_extent_tree(new_blocks)
            raw = bytearray(inode.raw)
            raw[40:100] = tree
            inode.raw = bytes(raw)
            inode.blocks = list(struct.unpack_from("<15I", inode.raw, 40))
            total_allocated = needed + len(tree_blocks)
        else:
            ptrs, tables = self._write_indirect_chain(new_blocks)
            total_allocated = needed + len(tables)
            inode.blocks = ptrs
        inode.size = len(data)
        self.write_inode(inode)

        # Reconcile the free counts with the bitmaps.  The incremental update
        # in _allocate_blocks and _free_blocks has already set the right bits;
        # this only makes the descriptors and the superblock agree with them,
        # so the three cannot disagree about how much space is left.
        #
        # The bitmaps are NOT recomputed wholesale here.  That would mean
        # rewriting every bitmap from a walk of the inode tables -- a larger and
        # slower operation, and one that belongs to repairing a filesystem that
        # has already drifted rather than to an edit whose bits were set
        # deliberately.  Running `e2fsck` outside this tool is the place for
        # that repair.
        self._refresh_group_counts()

        # Re-read and compare: allocating carefully is pointless if the result
        # is not verified.
        verify = self.read_path(path, root_inode=root_inode)
        if verify != data:
            where = next(
                # The lengths may differ -- that is one of the failures being located
                # -- so truncating to the shorter is intended here.
                (i for i, (a, b) in enumerate(zip(data, verify, strict=False)) if a != b),
                min(len(data), len(verify)),
            )
            block_index = where // self.block_size
            mapped = (
                self._block_list(self.lookup(path, root_inode=root_inode))
                if block_index < len(self._block_list(inode))
                else None
            )
            detail = ""
            if mapped is not None and block_index < len(mapped):
                detail = (
                    f" The first difference is in block {block_index} of the "
                    f"file, which is physical block {mapped[block_index]:,}."
                )
            raise ExtError(
                f"verification failed after growing {path!r}: read back "
                f"{len(verify):,} bytes, expected {len(data):,}; first "
                f"difference at byte {where:,}.{detail} The filesystem may be "
                f"inconsistent -- restore from backup."
            )
        return {
            "allocated": total_allocated,
            "freed": freed,
            "net": total_allocated - freed,
        }

    def _free_blocks(self, blocks: list[int]) -> int:
        """Mark ``blocks`` free in their group bitmaps and update the counts.

        The inverse of :meth:`_allocate_blocks`.  Duplicates are ignored, since
        a block can legitimately appear once in the list and once as an indirect
        table only if the block map is corrupt -- in which case freeing it twice
        would double-count.
        """
        self._require_writable()
        if not blocks:
            return 0

        by_group: dict[int, list[int]] = {}
        for block in set(blocks):
            if not 0 < block < self.blocks_count:
                raise ExtError(f"refusing to free block {block:,}: outside the filesystem")
            if self.is_metadata_block(block):
                raise ExtError(
                    f"refusing to free block {block:,}: it is filesystem "
                    f"metadata (superblock, descriptor table, bitmap or inode "
                    f"table), not file data.  Freeing it would destroy the "
                    f"filesystem structure.  This means the block list was "
                    f"derived from the inode incorrectly -- nothing was written."
                )
            group = self.group_of(block)
            by_group.setdefault(group, []).append(block)

        freed = 0
        for group, group_blocks in by_group.items():
            gd = self.group_descriptor(group)
            bb = struct.unpack_from("<I", gd, 0)[0]
            bitmap = bytearray(self.read_block(bb))
            for block in group_blocks:
                index = self.group_index(block)
                if not _get_bit(bitmap, index):
                    # Already free: the block map and bitmap disagree.
                    raise ExtError(
                        f"block {block:,} is recorded in the inode but already "
                        f"marked free in the bitmap; the filesystem is "
                        f"inconsistent, so nothing further was changed"
                    )
                bitmap[index // 8] &= ~(1 << (index % 8))
                freed += 1
            # Bits past the end of a short final group are left as they are:
            # mke2fs sets them as padding and e2fsck requires that, so clearing
            # them would be the edit that introduces a complaint.
            self.dev.write_at(self.block_offset(bb), bytes(bitmap))
            current = struct.unpack_from("<H", gd, 12)[0]
            self._write_group_descriptor_free(group, current + len(group_blocks))

        self._refresh_group_counts()
        return freed

    def replace_file_in_place(
        self,
        path: str,
        data: bytes,
        *,
        root_inode: int = 2,
        pad_to: int | None = None,
    ) -> None:
        """Overwrite an existing file's contents without changing its size.

        This is the only write this module supports, and deliberately so.  It
        requires the replacement to be **no larger** than the current file, and
        it rewrites only the blocks the inode already owns -- so no allocation
        happens, the free-block count cannot be disturbed, and nothing else in
        the filesystem moves.

        That constraint is what makes this safe.  Allocating blocks is where
        the failure mode lives: ``debugfs`` writing a 24 MB kernel into a 14 MiB
        boot partition emitted ``Could not allocate block`` *and* still recorded
        a 24,725,504-byte inode, producing an image that ``ls`` renders as fine.

        ``pad_to`` pads the replacement up to exactly that many bytes (used to
        fill a slot whose reader stops at an end-of-image marker).  The result
        must still fit.
        """
        self._require_writable()
        inode = self.lookup(path, root_inode=root_inode)
        if not inode.is_file:
            raise ExtError(f"{path!r} is not a regular file")

        payload = data
        if pad_to is not None:
            if len(payload) > pad_to:
                raise ExtError(
                    f"replacement for {path!r} is {len(payload):,} bytes, which "
                    f"already exceeds the pad target {pad_to:,}"
                )
            payload = payload + b"\x00" * (pad_to - len(payload))

        if len(payload) > inode.size:
            raise ExtError(
                f"replacement for {path!r} is {len(payload):,} bytes but the "
                f"existing file is only {inode.size:,}; this writer only "
                f"overwrites in place and will not allocate blocks (doing so "
                f"risks a silently corrupt filesystem)"
            )

        blocks = self._block_list(inode)
        capacity = len(blocks) * self.block_size
        if len(payload) > capacity:
            raise ExtError(
                f"replacement is {len(payload):,} bytes but the inode only maps "
                f"{len(blocks)} block(s) = {capacity:,} bytes"
            )

        # Only the blocks the payload actually reaches are written; a hole in
        # the region being overwritten is refused rather than silently filled.
        targets = blocks[: _ceil_div(len(payload), self.block_size)]
        for index, block in enumerate(targets):
            if block == 0:
                raise ExtError(
                    f"{path!r} has a hole at block {index}; writing into a "
                    f"sparse region is not supported"
                )
        self._write_data_blocks([b for b in targets], payload, describe=path)

        if len(payload) < inode.size:
            # The file shrinks, so the blocks that used to hold the tail are no
            # longer part of it.  They have to be released and the *block map*
            # rewritten, not just i_size: leaving the old extent tree in place
            # makes i_blocks describe storage the file does not own, and e2fsck
            # reports "i_blocks is 84408, should be 8" while the bitmap still
            # reserves the whole old run.  That is exactly what a shrink from a
            # 43 MB launcher to a 17 MB one produced.
            if self.uses_extents:
                self._shrink_extents_in_place(inode, len(payload))
            else:
                self._shrink_block_map_in_place(inode, len(payload))
            inode.size = len(payload)
            self.write_inode(inode)

        # Prove the write landed: re-read and compare.  Any mismatch means the
        # image is now inconsistent, and saying so is far better than leaving a
        # caller to discover it at boot.
        verify = self.read_path(path, root_inode=root_inode)
        if verify != payload:
            raise ExtError(
                f"verification failed after writing {path!r}: read back "
                f"{len(verify):,} bytes, expected {len(payload):,}, and the "
                f"contents differ. The filesystem may be inconsistent -- "
                f"restore from backup before using this image."
            )
