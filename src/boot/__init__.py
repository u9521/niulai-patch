"""The boot partition: its kernel, its ramdisks and its command line.

Four files in a 14 MiB ext2 partition that GRUB reads by index:

* :mod:`boot.kernel` -- parse and validate a ``bzImage``;
* :mod:`boot.initrd` -- the gzip'd cpio ramdisks, read and re-packed faithfully;
* :mod:`boot.image` -- the partition as four named files: read, plan, replace;
* :mod:`boot.grow` -- the risky path, for when a file does not fit at all.

Kept apart from :mod:`disk` for the same reason the disk layer is kept apart
from the PE patcher: the failure modes differ in kind.  A wrong byte in a PE
patch is a bad patch result; a wrong byte here is a machine that does not boot,
and the partition these files live on is 99.5% full, so "it does not fit" is the
normal case rather than the exceptional one.
"""

from . import grow, image, initrd, kernel
from .image import (
    BOOT_FILE_NAMES,
    BOOT_FILES,
    BootError,
    BootFile,
    BootFileInfo,
    BootImage,
    BootInventory,
    ReplacementPlan,
    extract_all,
    plan_replacement,
    plan_sizes,
    read_file,
    read_inventory,
    replace_file,
    resolve,
)
from .initrd import (
    CpioEntry,
    InitrdError,
    cpio_entries,
    entry_names,
    extract_entry,
    pack_gzip,
    repack,
    unpack_gzip,
    validate_initrd,
)
from .kernel import BzImage, KernelError, parse_bzimage

__all__ = [
    "BOOT_FILES",
    "BOOT_FILE_NAMES",
    "BootError",
    "BootFile",
    "BootFileInfo",
    "BootImage",
    "BootInventory",
    "BzImage",
    "CpioEntry",
    "InitrdError",
    "KernelError",
    "ReplacementPlan",
    "cpio_entries",
    "entry_names",
    "extract_all",
    "extract_entry",
    "grow",
    "image",
    "initrd",
    "kernel",
    "pack_gzip",
    "parse_bzimage",
    "plan_replacement",
    "plan_sizes",
    "read_file",
    "read_inventory",
    "repack",
    "replace_file",
    "resolve",
    "unpack_gzip",
    "validate_initrd",
]
