# The boot partition

The four files GRUB reads, and growing the partition that holds them.

Four files in a 14 MiB ext2, read by GRUB *by partition index*:

| File | Size | What it is |
| --- | --- | --- |
| `/kernel` | 12,362,752 | the `bzImage` |
| `/initrd` | 2,139,855 | the Android-x86 init ramdisk (gzip'd cpio) |
| `/ramdisk` | 1,159 | a directory-skeleton ramdisk (gzip'd cpio) |
| `/cmdline` | 94 | the kernel command line |

```bash
# Look at it all, including what is inside each ramdisk
uv run niulai-patch boot show
uv run niulai-patch boot initrd --list

# Write all four out as plain files
uv run niulai-patch boot extract --out /tmp/bootdump

# Evaluate and then write a replacement
uv run niulai-patch boot kernel  --image bzImage        # dry run
uv run niulai-patch boot kernel  --image bzImage --apply --yes
uv run niulai-patch boot cmdline --set 'root=/dev/ram0 console=ttyS0'
uv run niulai-patch boot cmdline --set '...' --apply --yes
uv run niulai-patch boot initrd  --image new-initrd.gz --apply --yes
```

The partition is 14,660,608 bytes and already holds 14,503,860 bytes of files —
**79,872 bytes free** — so whether a replacement is a file write or an
allocation is a real question, and `boot` answers it before writing:

* **fits in the blocks the file already owns** — written in place, allocating
  nothing. The free-block count cannot move, which is checkable and is checked.
* **larger than that** — the old blocks are freed first and new ones allocated,
  so what has to fit is the *growth*, not the whole file. If the growth exceeds
  the measured free space the write is refused with the numbers, and `--grow`
  is what opts into the risky alternative.

`/cmdline` is refused rather than written if it is empty or contains a newline
or a NUL: GRUB passes this file as a single command line (`kernel --use-cmdline`),
so a newline would be silently truncated and a NUL would cut the line short.
Editing it can stop the machine booting, so the old and new values are printed
side by side before anything is written.

**Re-packing a ramdisk is byte-for-byte reproducible.** The gzip framing is
reproduced exactly (`boot.initrd` writes the header by hand; neither
`gzip -9` nor `gzip.compress` matches this image's producer), so an edit that
changes nothing produces the identical file — the difference between an in-place
write and an allocation. The levels differ per file and are detected, not
assumed: `/initrd` is level 9 with `XFL=2`, `/ramdisk` is level 6 with `XFL=0`.

### Growing the partition

A file that does not fit at all needs the partition to grow, which moves `sda5`
and `sda6`. That is a command of its own — `boot grow` — with its own
confirmation, rather than something a kernel swap does quietly:

```bash
uv run niulai-patch boot grow --file kernel --image big-bzImage --apply --yes
```

Growing works because a move is not a rewrite: ext4 block numbers are relative
to the partition start and the superblock records no absolute sector, so shifting
a filesystem's start sector changes **nothing inside it**. Only the extended
partition's start and the EBR locations move.

That claim is checked rather than assumed. Growing `sda3` by 6 MiB on a copy of
the real image moves `sda6` by 12,288 sectors, and the 1,752,510,464 bytes of the
system partition come back **byte-identical** (SHA-256 `610be59b…` before and
after), as does the launcher APK inside it. Measured end to end: **5.4 s**, of
which the 1.76 GB move is the bulk.

The sequence is: verify the plan (no overlap, fits on disk) → move the volumes
back-to-front → write the EBRs → write the MBR **last**, so an interruption
leaves the old, self-consistent table → grow the ext2 inside the partition →
allocate blocks for the file, freeing the old ones first.

The ext2 grow is done in place by `extfs.grow_to`, which only ever *appends*:
it raises `s_blocks_count` and writes a bitmap, an inode bitmap and an inode
table for each new group, replicating the superblock and group descriptors at
each new group start as ext2 requires. Every existing group is left
byte-identical, so nothing already stored moves. The result is then re-read
through a fresh handle and its group descriptors checked.

After a grow the four boot files keep their exact inode numbers and sizes, free
space goes from 79,872 bytes to 4,258,816, and running `boot grow` again for the
same file correctly reports that it already fits instead of growing a second
time. Restoring from the pre-grow backup returns the image to exactly its
original SHA-256, so the whole operation is reversible.

One cosmetic difference is worth recording: `s_blocks_count` counts data blocks
and excludes `s_first_data_block`, so the grown filesystem ends one 1 KiB block
short of the partition it was given, whereas the factory image from `mke2fs` fits
exactly. The tail is zeroed, and the 4 MB growth margin means it is never the
difference between fitting and not.

A wrong partition table here is not a failed patch, it is an unbootable image,
so every step is checked and the plan is refused rather than approximated.

**A GKI kernel will not work here.** The [AOSP CI `kernel_x86_64`
builds](https://ci.android.com/builds/submitted/16528172/kernel_x86_64/latest)
produce an 18.4 MB `bzImage` for `aosp_kernel-common-android14-6.1`, and it has
no `virtio_blk`/`virtio_pci` in `modules.builtin` nor among its loadable
modules. This guest does not use virtio: its initrd's `init` hard-codes

```
SYSTEM_PARTITION="/dev/sda6"    VENDOR_PARTITION="/dev/sda7"
```

i.e. IDE/SATA-style `sdX` devices, and the ramdisk is an Android-x86 `init`
with `bin/busybox` and `bin/e2fsck` and no `.ko` files. A GKI kernel is the
wrong driver family for this machine.
