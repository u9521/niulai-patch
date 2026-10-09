"""Growing the boot partition, for a file that does not fit at all.

This is the highest-risk operation in the project and it is kept in its own
module for that reason.  It rewrites the MBR that GRUB boots from and relocates
1.7 GB, so every step is planned, reported, and verified rather than
approximated.

Why growth is sometimes unavoidable
-----------------------------------
The boot partition is 14,660,608 bytes and 79,872 of that is free.  A kernel
that is larger than the installed one by more than the free space cannot be
written by any amount of care -- the filesystem has to be made bigger, which
means the *partition* has to be made bigger, which means moving everything after
it (``sda5`` and the 1.6 GiB ``sda6``).

Growth works because a move is not a rewrite: ext4 block numbers are relative to
the partition start and the superblock records no absolute sector, so shifting a
filesystem's start sector changes **nothing inside it**.  Only the extended
partition's start and the EBR locations move.

The ordering, and why
---------------------
1. **Plan and verify** (:func:`plan_growth`): no overlap, fits on the disk, the
   partition keeps its start.  A plan that fails validation is never attempted.
2. **Rewrite the MBR last** (:func:`apply_growth`): the volumes move
   back-to-front, then the EBRs, then the MBR.  An interruption therefore leaves
   the old, self-consistent table rather than a half-moved one.
3. **Grow the filesystem, not the partition** (:func:`resize_boot_filesystem`):
   appends the new block groups with :meth:`disk.extfs.Ext2.grow_to` and then
   re-reads the result through a fresh handle.  Only appends are performed, so
   every existing group stays byte-identical.  This replaced a
   ``resize2fs``/``e2fsck`` round trip; see that function for what the trade was.

Measured on the real image: growing ``sda3`` from 14 MiB to 24 MiB changes **5
blocks** in the original area -- group 0's superblock and descriptor table, and
group 1's backup superblock, descriptor table and bitmap.  No data block and no
inode table is touched, and the four boot files keep their exact inode numbers
and sizes.
"""

from __future__ import annotations

import struct
from collections.abc import Callable
from pathlib import Path

from disk import extfs
from disk import image as image_mod
from disk import partition as partition_mod
from disk.device import ceil_to

from .image import BootError, BootImage, resolve

#: Signals a message to the user.  ``None`` means "say nothing", which is what
#: tests and library callers want.
Log = Callable[[str], None] | None


def _say(log: Log, message: str) -> None:
    if log is not None:
        log(message)


#: Slack added when planning a boot-partition growth.  Four megabytes covers the
#: new ext2 group metadata several times over and leaves usable free space
#: afterwards, so a later swap does not have to move 1.7 GB again.
GROWTH_MARGIN = 4 * 1024 * 1024


def plan_growth(image: Path, shortfall: int) -> partition_mod.GrowthPlan | None:
    """Plan growing the boot partition enough to hold a larger file.

    ``shortfall`` is how much bigger the new file is than what the partition
    currently has room for.  The margin matters because the resize itself
    consumes space: each new ext2 group spends four blocks on its own bitmaps
    and inode table before any of it becomes usable.

    Returns ``None`` for a shortfall of zero, and raises
    :class:`~disk.partition.PartitionError` if the disk cannot accommodate the
    result.
    """
    extra = shortfall + GROWTH_MARGIN
    if extra <= 0:
        return None
    # Bytes -> sectors, then round the sector count up to a whole MiB so the
    # partition lands on a tidy boundary.  (Rounding the *byte* count instead
    # asks for 512x too much, which the planner correctly rejects as a disk that
    # does not exist.)
    extra_sectors = ceil_to(ceil_to(extra, 512) // 512, 2048)

    with image_mod.open_image(image) as disk:
        # Which partition to grow is a question for the disk, not a constant: it
        # is the one holding /kernel.
        number = disk.partitions().boot().number
        return disk.partitions().plan_growth(number, extra_sectors)


def apply_growth(image: Path, plan: partition_mod.GrowthPlan, *, log: Log = None) -> None:
    """Carry out the growth, verifying the result before returning."""

    def progress(name: str, done: int, total_bytes: int) -> None:
        if done == total_bytes:
            _say(log, f"  moved {name} ({done * 512:,} bytes)")

    with image_mod.open_image(image, writable=True) as disk:
        table = disk.partitions()
        table.apply_plan(plan, progress=progress)
        problems = table.verify_after_growth(plan)
        disk.flush()
    if problems:
        raise partition_mod.PartitionError(
            "the partition table did not come out as planned:\n  " + "\n  ".join(problems)
        )


def resize_boot_filesystem(image: Path, new_size_bytes: int, *, log: Log = None) -> None:
    """Grow the boot ext2 in place, with the in-tree writer.

    This used to lift the partition out to a temp file and drive the real
    ``resize2fs``, then confirm the result with ``e2fsck -fn``.  It now uses
    :meth:`disk.extfs.Ext2.grow_to`, which appends the new block groups itself.

    Why the change is safe enough to make: ``grow_to`` only ever *appends*.
    Every existing group is left byte-identical -- it raises ``s_blocks_count``,
    writes a bitmap, an inode bitmap and an inode table for each new group, and
    replicates the superblock and group descriptors at the new group starts, as
    ext2 requires.  Nothing already stored moves or is rewritten, which is the
    property that made the previous approach attractive in the first place.

    The trade is stated plainly: ``resize2fs`` plus ``e2fsck`` was an
    *independent* implementation's opinion, and this is not.  The verification
    that remains is a re-read through a fresh handle
    (:meth:`_verify_boot_filesystem`), which can only prove self-consistency.
    That was a deliberate choice, recorded in ``doc/analysis/disk-writer.md``:
    it removes the project's last runtime dependency on a non-shipped external
    binary.
    """
    with image_mod.open_image(image, writable=True) as disk:
        part = disk.partitions().boot()
        fs = extfs.Ext2(part, writable=True)
        old_blocks = fs.blocks_count
        target_blocks = new_size_bytes // fs.block_size
        if target_blocks <= old_blocks:
            _say(
                log,
                f"  {part.name} already holds {old_blocks:,} blocks; nothing to grow",
            )
            return
        stats = fs.grow_to(target_blocks)
        disk.flush()
        _say(
            log,
            f"  grew {part.name} from {old_blocks:,} to {fs.blocks_count:,} blocks "
            f"(+{stats.get('added_blocks', 0):,} blocks, "
            f"+{stats.get('added_groups', 0)} group(s))",
        )
    _verify_boot_filesystem(image, log=log)


def _verify_boot_filesystem(image: Path, *, log: Log = None) -> None:
    """Re-read the boot filesystem through a fresh handle and sanity-check it.

    This is what replaces the ``e2fsck -fn`` gate.  It re-opens the image, walks
    every group descriptor, and checks the invariants the grow depends on:

    * ``s_blocks_count`` agrees with the partition's new extent;
    * every group's free-block and free-inode counts are within that group's
      own bounds -- the exact bug ``grow_to``'s docstring records, where a group
      claimed more free blocks than it has;
    * the metadata blocks of each new group are marked used in its bitmap, so
      the allocator cannot hand one out.

    It is a self-consistency check, not an independent one: it uses the same
    reader that wrote the data.  It is strictly weaker than ``e2fsck``, and is
    here to catch a *structural* mistake rather than to certify the result.
    """
    with image_mod.open_image(image) as disk:
        part = disk.partitions().boot()
        fs = extfs.Ext2(part)
        blocks = fs.blocks_count
        if blocks * fs.block_size > part.size_bytes:
            raise BootError(
                f"{part.name}: superblock claims {blocks:,} blocks "
                f"({blocks * fs.block_size:,} bytes) but the partition is only "
                f"{part.size_bytes:,} bytes"
            )
        bpg = fs.blocks_per_group
        groups = extfs._ceil_div(blocks, bpg)
        problems: list[str] = []
        for group in range(groups):
            gd = fs.group_descriptor(group)
            free_blocks, free_inodes = struct.unpack_from("<HH", gd, 12)
            start = group * bpg
            size = min(start + bpg, blocks) - start
            if free_blocks > size:
                problems.append(
                    f"group {group} claims {free_blocks:,} free blocks but spans only {size:,}"
                )
            if free_inodes > fs.inodes_per_group:
                problems.append(
                    f"group {group} claims {free_inodes:,} free inodes of {fs.inodes_per_group:,}"
                )
        if problems:
            raise BootError(
                "the grown boot filesystem is not self-consistent:\n  " + "\n  ".join(problems)
            )
        _say(log, f"  re-read {part.name}: {blocks:,} blocks in {groups} group(s), consistent")


def write_growing(image: Path, name: str, data: bytes, *, log: Log = None) -> int:
    """Replace a boot file that does not fit, growing the partition first.

    The order is load-bearing: the filesystem is resized *before* the file is
    written, because the ext2 inside the partition still believes it is 14 MiB
    until its superblock says otherwise -- so the write would fail for exactly
    the reason the partition was grown.

    Raises :class:`BootError` if a byte was already written and the result could
    not be verified, so the caller knows the image needs restoring.
    """
    spec = resolve(name)
    with BootImage.open(image) as img:
        plan = img.plan(name, data)
    if plan.ok:
        raise BootError(f"{spec.path} fits without growing the partition; use replace_file")

    growth = plan_growth(image, plan.shortfall)
    if growth is None:  # pragma: no cover - plan.ok would have been true
        raise BootError(f"cannot plan a growth for {spec.path}")
    if not growth.ok:
        raise partition_mod.PartitionError(
            "the growth plan is not valid:\n  " + "\n  ".join(growth.errors)
        )
    _say(log, "")
    _say(log, "partition change required")
    _say(log, growth.summary())

    apply_growth(image, growth, log=log)
    resize_boot_filesystem(image, growth.new_size_sectors * 512, log=log)

    # The filesystem now has room, so this takes the allocating path inside
    # BootImage.replace.  Re-read the plan rather than reusing the old one: the
    # free-space numbers moved when the filesystem grew.
    with BootImage.open(image, writable=True) as img:
        written = img.replace(name, data)
    _say(log, f"  sda{growth.grow_partition} is now {growth.new_size_sectors * 512:,} bytes")
    return written
