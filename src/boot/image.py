"""The boot partition as four named files: kernel, initrd, ramdisk, cmdline.

One module rather than four, because the four files differ only in how you
*validate* them.  Reading, planning a write and performing one are identical
operations -- the same inode lookup, the same block accounting, the same
free-space guard, the same read-back verification -- and duplicating that per
file is precisely how the four drift apart.

The files
---------
======================  ===========  ==========================
name                    size         what it is
======================  ===========  ==========================
``kernel``              12,362,752   ``bzImage``, GRUB's ``kernel``
``initrd``              2,139,855    Android-x86 ``init`` ramdisk
``ramdisk``             1,159        directory-skeleton ramdisk
``cmdline``             94           kernel command line
======================  ===========  ==========================

Sizes are from the real image and are *not* constants here: they are read, and
:meth:`BootImage.inventory` reports them.

The size problem
----------------
The partition is 14,660,608 bytes and the four files plus the resize's metadata
leave **79,872 bytes** free (measured).  So a replacement that is larger than
what it replaces may or may not be writable, and the answer depends on how much
is free *right now* -- which is a property of the filesystem, not a constant.

Two strategies, chosen by size:

* **no larger than what is installed** -- :meth:`~disk.extfs.Ext2.replace_file_in_place`,
  which overwrites the blocks the inode already owns and allocates nothing.  The
  free-block count cannot move, which is checkable and is checked.
* **larger** -- :meth:`~disk.extfs.Ext2.replace_file_growing`, which frees the
  old blocks and allocates new ones.  This is only attempted when the *growth*
  fits the measured free space, because the writer frees before it allocates and
  therefore needs room for the difference, not for the whole file.  A shortfall
  is reported with the numbers rather than left to surface as a corrupt image.

Growth used to require growing the partition first (see :mod:`boot.grow`).  The
guard here is what makes the cheaper path safe: nothing allocates without the
free space being *read from the filesystem in the same operation*.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Literal

from disk import extfs
from disk.device import ceil_to
from disk.partition import Partition

from . import initrd as initrd_mod
from .kernel import BzImage, KernelError, parse_bzimage

if TYPE_CHECKING:
    from disk.image import Disk

#: The four files, in the order GRUB's config mentions them.
KERNEL_PATH = "/kernel"
INITRD_PATH = "/initrd"
RAMDISK_PATH = "/ramdisk"
CMDLINE_PATH = "/cmdline"


class BootError(Exception):
    """Raised when a boot file cannot be read, validated or replaced."""


@dataclass(frozen=True)
class BootFile:
    """A file on the boot partition, and how to check a replacement for it."""

    name: str
    path: str
    kind: str
    description: str

    @property
    def is_ramdisk(self) -> bool:
        return self.kind == "ramdisk"

    @property
    def is_text(self) -> bool:
        return self.kind == "text"


#: Lookup by the short name the CLI and callers use.
BOOT_FILES: dict[str, BootFile] = {
    "kernel": BootFile(
        "kernel",
        KERNEL_PATH,
        "bzImage",
        "the Linux kernel GRUB loads with `kernel --use-cmd-line`",
    ),
    "initrd": BootFile(
        "initrd",
        INITRD_PATH,
        "ramdisk",
        "the Android-x86 init ramdisk GRUB loads with `initrd`",
    ),
    "ramdisk": BootFile(
        "ramdisk",
        RAMDISK_PATH,
        "ramdisk",
        "the directory-skeleton ramdisk the first-stage init consumes",
    ),
    "cmdline": BootFile(
        "cmdline",
        CMDLINE_PATH,
        "text",
        "the kernel command line",
    ),
}

BOOT_FILE_NAMES: tuple[str, ...] = tuple(BOOT_FILES)


def resolve(name: str) -> BootFile:
    """Look up a boot file by name, with a message listing the valid ones."""
    try:
        return BOOT_FILES[name]
    except KeyError:
        raise BootError(
            f"unknown boot file {name!r}; expected one of {', '.join(BOOT_FILE_NAMES)}"
        ) from None


# --------------------------------------------------------------------------- #
# Inventory
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class BootFileInfo:
    """One file's size and the storage behind it."""

    file: BootFile
    size: int
    #: Blocks the inode currently owns.  Not ``size / block_size``: a file may
    #: have holes, and ``replace_file_growing`` allocates for the *whole* new
    #: size, so the honest number is what the inode maps.
    blocks: int
    inode: int
    block_size: int

    @property
    def capacity(self) -> int:
        return self.blocks * self.block_size

    @property
    def slack(self) -> int:
        """Bytes writable in place without allocating anything."""
        return self.capacity - self.size

    def describe(self) -> str:
        return f"{self.file.name} ({self.size:,} bytes, {self.blocks} blocks)"


@dataclass(frozen=True)
class BootInventory:
    """Everything the boot partition holds, read in one pass."""

    files: list[BootFileInfo]
    capacity: int
    free_bytes: int
    block_size: int
    cmdline: str
    kernel: BzImage | None
    partition: str

    def get(self, name: str) -> BootFileInfo:
        for info in self.files:
            if info.file.name == name:
                return info
        raise BootError(f"{name!r} is not present in the boot partition")

    @property
    def used_bytes(self) -> int:
        return sum(i.size for i in self.files)


# --------------------------------------------------------------------------- #
# The partition as a set of files
# --------------------------------------------------------------------------- #
class BootImage:
    """A read (and optionally write) view over the boot partition.

    Holds a :class:`~disk.partition.Partition` rather than a file handle, so it
    does not own the disk and does not have to know what container the disk came
    from.  The partition is resolved from the MBR by *content* (the one holding
    ``/kernel``), never by a sector number: growing the partition moves it.
    """

    #: The disk this was opened from, when it was opened via :meth:`open`.  Kept
    #: so ``close`` can release it; a caller that hands in a partition directly
    #: owns the disk itself and leaves this ``None``.
    _disk: Disk | None = None

    def __init__(self, partition: Partition, *, writable: bool = False) -> None:
        self.partition = partition
        self.writable = writable
        self.fs = extfs.Ext2(partition, writable=writable)

    @property
    def partition_name(self) -> str:
        """What to call the backing region in a report.

        A :class:`~disk.partition.Partition` knows its own name (``sda3``); a
        bare device -- which is what the tests hand in -- does not, so the
        fallback keeps the reporting code from assuming one.
        """
        return getattr(self.partition, "name", "boot filesystem")

    @classmethod
    def open(cls, image_path: Path, *, writable: bool = False) -> BootImage:
        """Open the boot partition of ``image_path``, resolving it from the MBR."""
        from disk import image as image_mod

        disk = image_mod.open_image(image_path, writable=writable)
        try:
            partition = disk.partitions().boot()
        except BaseException:
            disk.close()
            raise
        try:
            instance = cls(partition, writable=writable)
        except BaseException:
            disk.close()
            raise
        instance._disk = disk
        return instance

    def close(self) -> None:
        if self._disk is not None:
            self._disk.close()
            self._disk = None

    def __enter__(self) -> BootImage:
        return self

    # `Literal[False]` rather than `bool`: this never suppresses the
    # exception, and saying so is what lets a type checker see that values
    # assigned inside the `with` block are bound afterwards.
    def __exit__(self, *exc) -> Literal[False]:
        self.close()
        return False

    # -- reading -----------------------------------------------------------
    def inode_of(self, name: str) -> extfs.Inode:
        return self.fs.lookup(resolve(name).path)

    def size_of(self, name: str) -> int:
        return self.inode_of(name).size

    def read(self, name: str) -> bytes:
        """The file's bytes as installed."""
        spec = resolve(name)
        try:
            return self.fs.read_path(spec.path)
        except extfs.ExtError as exc:
            raise BootError(f"cannot read {spec.path}: {exc}") from exc

    def read_cmdline(self) -> str:
        """The command line as text.

        The stored file has **no** trailing NUL (measured: it ends at
        ``...bootconfig``), so nothing is stripped but surrounding whitespace.
        Adding a NUL here would change the file's length and force an allocation
        for what should be a no-op.
        """
        return self.read("cmdline").decode("utf-8", "replace").strip()

    def info(self, name: str) -> BootFileInfo:
        spec = resolve(name)
        inode = self.inode_of(name)
        blocks = [b for b in self.fs._block_list(inode) if b]
        return BootFileInfo(
            file=spec,
            size=inode.size,
            blocks=len(blocks),
            inode=inode.number,
            block_size=self.fs.block_size,
        )

    def inventory(self) -> BootInventory:
        """Read every file's size and the partition's capacity, once."""
        files: list[BootFileInfo] = []
        for name in BOOT_FILE_NAMES:
            try:
                files.append(self.info(name))
            except extfs.ExtError as exc:
                raise BootError(f"the boot partition has no {resolve(name).path}: {exc}") from exc

        kernel: BzImage | None = None
        try:
            kernel = parse_bzimage(self.read("kernel"))
        except KernelError:
            # A partition that holds /kernel but whose kernel does not parse is
            # reported by `plan`, not turned into a fatal error here: an
            # inventory of an unfamiliar image is still worth printing.
            kernel = None

        block = self.fs.block_size
        return BootInventory(
            files=files,
            capacity=self.fs.blocks_count * block,
            free_bytes=self.fs.free_blocks * block,
            block_size=block,
            cmdline=self.read_cmdline(),
            kernel=kernel,
            partition=self.partition_name,
        )

    def extract(self, name: str, dest: Path) -> Path:
        """Write one file out to ``dest`` (a path, or the directory to fill)."""
        data = self.read(name)
        target = Path(dest)
        if target.is_dir():
            target = target / name
        target.write_bytes(data)
        return target

    def extract_all(self, out_dir: Path) -> list[Path]:
        """Write all four files into ``out_dir``, creating it if needed."""
        out = Path(out_dir)
        out.mkdir(parents=True, exist_ok=True)
        return [self.extract(name, out) for name in BOOT_FILE_NAMES]

    # -- writing -----------------------------------------------------------
    def plan(self, name: str, data: bytes) -> ReplacementPlan:
        """Decide how (or whether) ``data`` can be written.  Read-only."""
        spec = resolve(name)
        installed = self.info(name)

        notes = self.validate(name, data)
        if spec.name == "kernel":
            notes.extend(self._kernel_notes(data))

        plan = plan_sizes(
            name=spec.name,
            installed_size=installed.size,
            replacement_size=len(data),
            block_size=installed.block_size,
            free_bytes=self.fs.free_blocks * installed.block_size,
        )
        if not plan.ok:
            notes.append(
                f"the partition has {plan.free_bytes:,} bytes free but the write "
                f"needs {plan.growth_bytes:,} more than it frees; the partition "
                f"must grow first (see `boot grow`)"
            )
        plan.notes = notes
        return plan

    def replace(self, name: str, data: bytes) -> int:
        """Write ``data`` over ``name``, allocating only if it must.

        Refuses anything the plan cannot fit.  The read-back check is the point:
        allocating carefully is pointless if the result is not verified, and a
        wrong byte here is a device that does not boot.
        """
        plan = self.plan(name, data)
        if not plan.ok:
            raise BootError(
                f"cannot write {plan.name}: it needs {plan.shortfall:,} bytes "
                f"more than the partition has free. " + " ".join(plan.notes)
            )

        spec = resolve(name)
        if plan.fits_in_place:
            self.fs.replace_file_in_place(spec.path, data)
        else:
            self.fs.replace_file_growing(spec.path, data)

        after = self.info(name)
        if after.size != len(data):
            raise BootError(
                f"verification failed: {spec.path} reads back "
                f"{after.size:,} bytes, expected {len(data):,}"
            )
        if self.read(name) != data:
            raise BootError(
                f"verification failed: the contents of {spec.path} do not match "
                f"what was written. Restore from backup before using this image."
            )
        return after.size

    # -- validation --------------------------------------------------------
    def validate(self, name: str, data: bytes) -> list[str]:
        """Check a candidate, returning notes and raising on a hard error.

        Soft findings come back as notes so they reach the caller's report;
        anything that would produce an unbootable image raises here, before a
        byte is written.
        """
        spec = resolve(name)
        notes: list[str] = []

        if spec.is_text:
            if not data:
                raise BootError(f"{spec.path} would be empty; the kernel needs its command line")
            if b"\x00" in data:
                raise BootError(
                    f"{spec.path} contains a NUL byte; GRUB reads this file as a "
                    f"C string and would see only the text before it"
                )
            if b"\n" in data or b"\r" in data:
                raise BootError(
                    f"{spec.path} contains a newline; GRUB passes this file as a "
                    f"single command line, so the rest would be silently dropped"
                )
        elif spec.is_ramdisk:
            problems = initrd_mod.validate_initrd(data, what=spec.path)
            if problems:
                raise BootError("; ".join(problems))
        elif spec.name == "kernel":
            try:
                parse_bzimage(data)
            except KernelError as exc:
                raise BootError(f"{spec.path}: {exc}") from exc
        return notes

    def _kernel_notes(self, data: bytes) -> list[str]:
        """Report an ABI change and the ramdisk pairing, as the old CLI did."""
        notes: list[str] = []
        try:
            replacement = parse_bzimage(data)
            installed = parse_bzimage(self.read("kernel"))
        except KernelError, BootError:
            return notes
        if replacement.family != installed.family:
            notes.append(
                f"WARNING: kernel version changes from {installed.family} to "
                f"{replacement.family}; kernel modules built for the old version "
                f"will not load"
            )
        initrd_size = self.info("initrd").size
        notes.append(
            f"initrd ({initrd_size:,} bytes) is paired with the kernel; this "
            f"image uses an Android-x86 init, not a GKI one"
        )
        return notes


@dataclass
class ReplacementPlan:
    """What replacing one boot file would involve."""

    name: str
    installed_size: int
    replacement_size: int
    fits_in_place: bool
    growth_bytes: int
    free_bytes: int
    ok: bool
    shortfall: int = 0
    notes: list[str] = field(default_factory=list)

    @property
    def delta(self) -> int:
        return self.replacement_size - self.installed_size

    def summary(self) -> str:
        lines = [
            f"installed   {self.installed_size:,} bytes",
            f"replacement {self.replacement_size:,} bytes ({self.delta:+,})",
        ]
        if self.fits_in_place:
            lines.append("fits in the space the current file occupies; no blocks are allocated")
        elif self.growth_bytes == 0:
            lines.append(
                "grown, but the extra bytes fit the last block the file already "
                "owns; no new blocks are allocated"
            )
        elif self.ok:
            lines.append(
                f"needs {self.growth_bytes:,} more bytes than it frees, and "
                f"{self.free_bytes:,} are free; the blocks will be allocated"
            )
        else:
            lines.append(
                f"needs {self.growth_bytes:,} more bytes than it frees but only "
                f"{self.free_bytes:,} are free (short by {self.shortfall:,})"
            )
        lines.extend(self.notes)
        return "\n".join(lines)


def plan_sizes(
    *,
    name: str,
    installed_size: int,
    replacement_size: int,
    block_size: int,
    free_bytes: int,
) -> ReplacementPlan:
    """The size arithmetic of a replacement, with no filesystem involved.

    Kept separate from :meth:`BootImage.plan` so the rule can be tested directly
    rather than through a fake filesystem: this is the decision that turns "a
    bigger file" into either an allocation or a refusal, and it is four lines of
    arithmetic whose off-by-one would be a corrupt filesystem.

    The rule
    --------
    Two *different* questions, and conflating them is a bug this module had:

    * **which writer** -- :meth:`~disk.extfs.Ext2.replace_file_in_place` refuses
      any increase at all, because it writes only into blocks the inode already
      owns and never allocates.  So ``fits_in_place`` means strictly
      ``replacement_size <= installed_size``; a file that grows by one byte
      takes the allocating writer even if it stays inside the same block.
    * **whether it is affordable** -- the allocating writer frees the old blocks
      before claiming new ones, so what must fit in the free space is the *net*
      new blocks: ``ceil(new) - ceil(old)``.  That difference is frequently
      **zero** for a file that grew (padding to the end of the last block costs
      nothing), and then the write is affordable with no free space at all.

    Both sides are rounded up to whole blocks, because that is what the
    allocator hands out.
    """
    if block_size <= 0:
        raise BootError(f"implausible block size {block_size}")
    if installed_size < 0 or replacement_size < 0:
        raise BootError("sizes cannot be negative")

    # Which writer: in-place refuses any increase, so this is not a rounding
    # question.
    fits_in_place = replacement_size <= installed_size

    if fits_in_place:
        growth = 0
    else:
        growth = max(
            0,
            ceil_to(replacement_size, block_size) - ceil_to(installed_size, block_size),
        )

    shortfall = max(0, growth - free_bytes)

    return ReplacementPlan(
        name=name,
        installed_size=installed_size,
        replacement_size=replacement_size,
        fits_in_place=fits_in_place,
        growth_bytes=growth,
        free_bytes=free_bytes,
        ok=shortfall == 0,
        shortfall=shortfall,
    )


# --------------------------------------------------------------------------- #
# Convenience: read-only, one-shot
# --------------------------------------------------------------------------- #
def read_inventory(image_path: Path) -> BootInventory:
    """Open, describe, close.  The read-only entry point for callers."""
    try:
        with BootImage.open(image_path) as img:
            return img.inventory()
    except extfs.ExtError as exc:
        raise BootError(f"cannot read the boot partition: {exc}") from exc


def read_file(image_path: Path, name: str) -> bytes:
    """One boot file's bytes."""
    with BootImage.open(image_path) as img:
        return img.read(name)


def extract_all(image_path: Path, out_dir: Path) -> list[Path]:
    """All four files, written out."""
    with BootImage.open(image_path) as img:
        return img.extract_all(out_dir)


def replace_file(image_path: Path, name: str, data: bytes) -> int:
    """Replace one boot file in place, with the free-space guard."""
    with BootImage.open(image_path, writable=True) as img:
        written = img.replace(name, data)
    return written


def plan_replacement(image_path: Path, name: str, data: bytes) -> ReplacementPlan:
    """What replacing one boot file would involve.  Read-only."""
    with BootImage.open(image_path) as img:
        return img.plan(name, data)
