# The guest disk

The VDI container, its partitions, and the offline editing stack.

Beyond the Windows executables, MuMu ships an Android system image as a
VirtualBox disk at

```
nx_device/15.0/vms/MuMuPlayer-15.0-base/system.vdi
```

which the product config declares `Readonly` — it is shared by every instance of
that product. Two of its partitions matter:

| Partition | Size | Contents |
| --- | --- | --- |
| `sda3` | 14 MiB ext2 | `/kernel`, `/initrd`, `/ramdisk`, `/cmdline` (GRUB reads these) |
| `sda6` | 1.6 GiB ext4 | the Android system partition, including `/system/priv-app` |

`niulai-patch` edits these **offline**, in place, without VirtualBox and without
WSL. The Python is flat under `src/`, grouped by what it touches:

| Package | Modules | Responsibility |
| --- | --- | --- |
| `disk/` | `vdi`, `image`, `partition`, `filetype`, `extfs`, `images` | the container, the partition table and the filesystems on them |
| `boot/` | `kernel`, `initrd`, `image`, `grow` | the four files GRUB reads: `bzImage`, both ramdisks, the command line |
| `pe/` | `pe`, `sigscan`, `patcher`, `patches/*.toml` | Windows executables, and the declarative patch profiles |
| `rcc/` | `rcc`, `rccpatch` | Qt resource containers, and the images inside them |

The disk stack is four layers deep, each one knowing only the layer below it:

| Layer | Module | Unit | Responsibility |
| --- | --- | --- | --- |
| container | `disk/vdi.py` | 1 MiB VDI blocks | BAT, block allocation, read and write caches |
| disk | `disk/image.py` | sectors | which container this file is, and its partitions |
| partition | `disk/partition.py` | sectors | MBR/EBR parsing, offset rebase, bounds |
| filesystem | `disk/extfs.py` | fs blocks | ext2/ext3/ext4 |

`src/filesystems.py` is the entry point the rest of the project
uses; nothing above `disk/` opens a container or does offset arithmetic.

**Partitions are found by reading them, not by a constant.** Both were
hard-coded sector numbers once (`BOOT_PARTITION_LBA = 34304`,
`SYSTEM_PARTITION_LBA = 79068`) in a codebase that can *move* partitions when
it grows the boot partition — a constant that is right until the first resize
and silently wrong afterwards is worse than no constant. Now `sda3` is the ext
partition holding `/kernel` (the property GRUB's `(hd0,2)/kernel` actually
needs) and `sda6` is the largest ext4 partition, confirmed by the launcher's
SHA-256 before anything is written. The MBR labels both `0x83`, so the type
byte could never have distinguished them.

The launcher is smaller than the fork it replaces, so that edit stays in place
and the image does not grow. (The boot files are the ones that can need to
allocate; see [boot.md](boot.md).)

Start with `doctor`, which reports the helper binaries and cross-checks the
image header against MuMu's own `vbox-img.exe`:

```bash
uv run niulai-patch doctor
```

### No helper binaries to build

There is nothing to compile. Partition editing (`disk.partition`) and ext2/ext4
reading and writing (`disk.extfs`) are pure Python, and the only external
executable the disk path runs is `vbox-img.exe`, which ships with MuMu and is
therefore located rather than built.

The partition table edit in particular is in-process: `disk/partition.py`
contains no `subprocess` call and never shells out to `sgdisk`, `sfdisk` or
`fdisk`. `src/boot/grow.py`, the feature that most obviously *could* need an
external partition editor, calls `disk.partitions().plan_growth(...)` and
nothing else.
