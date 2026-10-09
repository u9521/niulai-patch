# The ext2/ext4 writer, and why it is trustworthy

The invariants the in-tree writer holds, and the bugs they came from.

`src/disk/extfs.py` is the only thing in the project that writes a filesystem
structure. A bug there does not produce a failed patch; it produces a corrupt
Android system partition. This file records the invariants it has to hold and the
specific bugs that were found while establishing them.

## The one rule that matters

**A write that does not fit must fail, not half-succeed.** This is not
hypothetical. Driving `debugfs` to write a 24 MB kernel into the 14 MiB boot
partition printed *both*

```
write: Could not allocate block in ext2 filesystem
Allocated inode: 11
```

and then recorded a 24,725,504-byte size with zero free blocks — an image that
looks correct to `ls` and is corrupt. The in-tree writer refuses the same request
outright (`need 19,532 blocks but the filesystem reports only 12,153 free`) and
leaves the file untouched.

So every write is followed by a re-read and a byte comparison, and the free-block
count is checked before and after.

## The five bugs the invariants came from

An independent checker (`e2fsck`, driven by the project before that dependency
was dropped) was run over every edit. It caught five genuine bugs that the
in-tree checks were happy with. Each is now pinned by a regression test in
`tests/test_disk.py`, and **those tests are what carry the guarantee.**

| Bug | How it presented |
| --- | --- |
| `i_blocks` double-counted when rewriting an extents file | `170768` where `85384` was correct — exactly twice the data blocks |
| group-descriptor checksums never recomputed | every descriptor the writer touched was invalid under `uninit_bg` |
| bitmap padding bits past a short final group were *cleared* | `mke2fs` sets them and `e2fsck` requires them set |
| group start computed as `N * blocks_per_group` | ignored the boot block a 1 KiB block size reserves, so every bitmap bit was off by one |
| `i_blocks` counted only the 15 pointer slots | the inner indirect tables leaked, and the free list named only slots 12–14 |

The last three share a cause worth naming: the boot partition's bitmaps are
nearly full, so a one-bit shift usually lands on another *used* bit and the error
stays invisible until a write has to free a block at a group boundary. The 4 KiB
system partition has no boot block, so it never showed the problem.

## Invariants worth keeping in view

* **`s_blocks_count` counts data blocks and excludes `s_first_data_block`.** A
  grown filesystem therefore ends one 1 KiB block short of the partition it was
  given, whereas the factory image from `mke2fs` fits exactly. The tail is
  zeroed, and the growth margin means this is never the difference between
  fitting and not.
* **Group *N* does not start at `N * blocks_per_group`.** With a 1 KiB block
  size, block 0 is the boot block and the first group holds one block fewer.
* **Padding bits past the end of a short final group must be *set*.** `mke2fs`
  sets them; clearing them makes `e2fsck` report a corrupt filesystem.
* **`i_blocks` counts 512-byte sectors, including every indirect table the inode
  owns** — not just the 15 pointer slots.
* **Group-descriptor checksums must be recomputed** whenever a descriptor is
  written, using `e2fsprogs`' `ext2fs_group_desc_csum` (CRC-16 with the
  reflected `0x8005` polynomial, seeded with the group number and the
  filesystem UUID). The implementation is asserted against every descriptor in
  the real image.

## Growing a filesystem

`Ext2.grow_to` only ever *appends*. It raises `s_blocks_count` and writes a
bitmap, an inode bitmap and an inode table for each new group, replicating the
superblock and group descriptors at each new group start as ext2 requires.
Every existing group is left byte-identical, so nothing already stored moves.

This replaced an external `resize2fs` round trip, which also had to lift the
14 MiB partition out to a temp file because it needed a seekable image.
`grow_to` writes through the `Partition` device directly.

**What is checked afterwards.** `_verify_boot_filesystem` in `src/boot/grow.py`
re-opens the image, walks every group descriptor, and checks that
`s_blocks_count` agrees with the partition's extent and that each group's free
counts are within its own bounds.

**What that check cannot do.** It re-reads through the same reader that wrote the
data, so it can only prove *self-consistency*. Nothing in the project now reads
an edited filesystem with an independent implementation. For an outside opinion,
extract the partition and run `e2fsck -fn` yourself — it is read-only and exits
non-zero when something is wrong:

```bash
uv run niulai-patch boot grow --image big-bzImage --apply --yes
# then, outside this tool:
e2fsck -fn /path/to/extracted-sda3.img
```

## Where the writer is exercised

`tests/test_disk.py` carries the weight. Its decisive assertion extracts the
41 MiB launcher from inside the live image and checks its SHA-256, which
exercises the extent tree end to end. The indirection tests build a real
filesystem with `mke2fs` and check the answer against `debugfs`, because a
hand-built fixture can only confirm the layout it was written to have — those two
tools are *test fixture generators*, never part of the product.
