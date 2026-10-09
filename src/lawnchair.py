"""Replace the Android system image's launcher inside ``system.vdi``.

The problem
-----------
MuMu 15 ships a NetEase fork of Lawnchair at

    /system/priv-app/Lawnchair/Lawnchair.apk      (43,330,672 bytes)

which is a 41 MiB build carrying ``com.mumu.core.*`` classes and reporting to
``sentry.netease.com``.  The replacement is 17.4 MiB and is a *universal* APK --
it contains ``lib/x86_64/``, which is the ABI this guest actually uses
(``ro.product.abi=x86_64``).

Why the replacement is a checked-in build
-----------------------------------------
It is **not** the published upstream release.  Upstream crashes on this
platform twice over (see :data:`BUNDLED_APK` and ``patches/README.md``): a
``VerifyError`` on ``PersistedTaskSnapshotData``, which the published release
does not fix, and a missing ``android.view.IRecentsAnimationRunner`` that only
the AIDL shim addresses.  Both fixes are source changes, so the APK is built
from a patched Lawnchair checkout, signed with the AOSP testkey, and committed
under ``prebuilts/``.

That is why this module no longer downloads anything.  Earlier revisions fetched
the pinned upstream release and tried to repair it with a dex field-type rewrite
(``dexpatch``); that approach was removed once the problem was understood to be
two *source-level* defects rather than one rewritable field.  Shipping the built
artifact is both simpler and reproducible -- the build recipe and the diffs live
in ``patches/``.

Why an APK swap is enough
-------------------------
The build and the fork share the application id ``app.lawnchair``, so this is a
drop-in replacement rather than a second launcher.  Three consequences drive
the implementation:

* the replacement is **smaller**, so no partition growth is needed -- it is
  written over the fork's own blocks;
* the fork ships pre-compiled ``oat/x86_64/Lawnchair.odex`` (80 MB) and
  ``Lawnchair.vdex`` (696 KB) that describe *the fork's* code.  Leaving them in
  place would have ART load stale compilation units against different bytecode,
  so they are removed;
* ``/system`` is mounted read-only by ``init``, so a wrong result is not
  conveniently fixable from inside the guest -- it has to be right offline.

Removing the odex/vdex is a *directory* edit, which is the one operation this
module performs that is not a fixed-size overwrite.  It is done by writing a
new directory entry block, then checking that the result parses back.
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Literal

from disk import extfs
from disk.device import ceil_to
from disk.extfs import FT_DIR
from disk.partition import Partition

if TYPE_CHECKING:
    from disk.image import Disk

#: Where the launcher lives inside the system partition.
LAUNCHER_DIR = "/system/priv-app/Lawnchair"
LAUNCHER_APK = f"{LAUNCHER_DIR}/Lawnchair.apk"
LAUNCHER_OAT_DIR = f"{LAUNCHER_DIR}/oat/x86_64"

#: The fork's known identity.  Checked before writing so that a different
#: image (an updated MuMu, say) is reported rather than silently altered.
FORK_SHA256 = "c1f3370c12ec636ddf83d3125bfd82ef56716ead7fa5c3a729732e40e5bfe277"
FORK_SIZE = 43_330_672

#: The replacement this project installs.
#:
#: This is a build from the patched Lawnchair source (see ``patches/``), not the
#: published upstream release -- that release is 17,314,003 bytes and crashes on
#: this platform.  Documented here rather than only in the file so the module
#: states which artifact it puts in the image.
BUNDLED_APK_NAME = "Lawnchair-15.0.0-beta3.0-mumu15.apk"
BUNDLED_APK_SHA256 = "d88613d2384f9ac846dc9140484e1b6efe5fd0752b9cddf72bc07d3cfef009e5"
BUNDLED_APK_SIZE = 17_456_572

#: Builds of the bundled APK, newest location first.
#:
#: Two are searched because the file travels beside the code rather than inside a
#: package: a checkout keeps it at ``<repo>/src/prebuilts/``, and an installed
#: wheel lands it in ``site-packages/prebuilts/``.  Resolving only one of the two
#: made the command fail with "the bundled APK is missing" in the other layout.
#:
#: Both are one level up from this file, which sits directly in ``src/`` or in
#: ``site-packages/`` -- there is no ``mumu_patch/`` directory in between.
_BUNDLED_APK_CANDIDATES = (
    Path(__file__).resolve().parent / "prebuilts" / BUNDLED_APK_NAME,
    Path(__file__).resolve().parent.parent / "prebuilts" / BUNDLED_APK_NAME,
)


def bundled_apk_path() -> Path:
    """Where the bundled build is, or where it would have been.

    Returns the first location that exists; failing that, the checkout path, so
    the error message names the place a developer should put the file.
    """
    for candidate in _BUNDLED_APK_CANDIDATES:
        if candidate.is_file():
            return candidate
    return _BUNDLED_APK_CANDIDATES[-1]


#: The resolved location, kept as a module attribute for callers and tests.
BUNDLED_APK = _BUNDLED_APK_CANDIDATES[-1]

#: ART compilation artefacts that describe the fork and must go with it.
STALE_OAT_FILES = ("Lawnchair.odex", "Lawnchair.vdex")

APK_MAGIC = b"PK\x03\x04"


class LawnchairError(Exception):
    """Raised when the launcher cannot be replaced safely."""


#: Block rounding shared with the boot-file writer, so the two compute "how many
#: blocks does this need that the current one did not have" the same way.
_ceil_to = ceil_to


@dataclass
class ApkCheck:
    """What we found at the launcher's slot, before touching anything."""

    path: str
    size: int
    sha256: str
    is_replacement: bool
    is_fork: bool

    def describe(self) -> str:
        if self.is_replacement:
            return f"this project's build ({self.size:,} bytes)"
        if self.is_fork:
            return f"NetEase fork ({self.size:,} bytes)"
        return f"unrecognised APK ({self.size:,} bytes, {self.sha256[:16]}...)"


@dataclass
class StaleOat:
    name: str
    size: int


class SystemImage:
    """A view over the Android system partition.

    Holds a :class:`~disk.partition.Partition` rather than a file
    handle, so it does not own the disk and does not have to know what container
    the disk came from.  The partition was a hard-coded sector number here until
    the device stack existed; it is now passed in, resolved from the MBR.
    """

    #: The disk this was opened from, when it was opened via :meth:`open`.  Kept
    #: so ``close`` can release it; a caller that hands in a partition directly
    #: owns the disk itself and leaves this ``None``.
    _disk: Disk | None = None

    def __init__(self, partition: Partition, *, writable: bool = False) -> None:
        self.partition = partition
        self.fs = extfs.Ext2(partition, writable=writable)

    @classmethod
    def open(cls, image_path: Path, *, writable: bool = False) -> SystemImage:
        """Open the system partition of ``image_path``, resolving it from the MBR."""
        from disk import image as image_mod

        # A context manager cannot outlive the with-block, and this object needs
        # the disk to stay open, so the disk handle is attached to the instance.
        disk = image_mod.open_image(image_path, writable=writable)
        try:
            partition = disk.partitions().system()
        except BaseException:
            disk.close()
            raise
        instance = cls(partition, writable=writable)
        instance._disk = disk
        return instance

    def close(self) -> None:
        if self._disk is not None:
            self._disk.close()
            self._disk = None

    def __enter__(self) -> SystemImage:
        return self

    # `Literal[False]` rather than `bool`: this never suppresses the
    # exception, and saying so is what lets a type checker see that values
    # assigned inside the `with` block are bound afterwards.
    def __exit__(self, *exc) -> Literal[False]:
        self.close()
        return False

    # -- inspection --------------------------------------------------------
    def check_launcher(self) -> ApkCheck:
        """Hash the installed launcher and identify it."""
        data = self.fs.read_path(LAUNCHER_APK)
        digest = hashlib.sha256(data).hexdigest()
        return ApkCheck(
            path=LAUNCHER_APK,
            size=len(data),
            sha256=digest,
            is_replacement=data[:4] == APK_MAGIC and digest == BUNDLED_APK_SHA256,
            is_fork=data[:4] == APK_MAGIC and digest == FORK_SHA256,
        )

    def stale_oat(self) -> list[StaleOat]:
        """ART artefacts left over from the fork, if present."""
        try:
            directory = self.fs.lookup(LAUNCHER_OAT_DIR)
        except extfs.ExtError:
            return []
        out: list[StaleOat] = []
        for entry in self.fs.list_dir(directory):
            if entry.name in STALE_OAT_FILES and entry.file_type != FT_DIR:
                inode = self.fs.read_inode(entry.inode)
                out.append(StaleOat(entry.name, inode.size))
        return out

    def free_space(self) -> int:
        return self.fs.free_blocks * self.fs.block_size

    # -- mutation ----------------------------------------------------------
    def replace_launcher(self, apk: bytes, *, expect_fork: bool = True) -> ApkCheck:
        """Overwrite the launcher APK with ``apk``.

        Refuses anything that would need more blocks than it frees: the
        replacement is smaller than the fork, so the write always fits, and
        requiring that keeps the failure mode "loud error" rather than
        "silently corrupt filesystem".
        """
        before = self.check_launcher()
        if expect_fork and not (before.is_fork or before.is_replacement):
            raise LawnchairError(
                f"the launcher at {LAUNCHER_APK} is not the known NetEase fork "
                f"or this project's build ({before.describe()}). Refusing to "
                f"overwrite an unrecognised build -- this image may be from a "
                f"different MuMu version. Pass --allow-unknown-installed to "
                f"overwrite it anyway, for example when it holds a build this "
                f"tool did not write."
            )

        self._validate_apk(apk)

        if len(apk) > before.size:
            # Larger than what is installed, so blocks must be allocated.  The
            # writer frees the old file's blocks before claiming new ones, so
            # what has to fit in the free space is the *growth*, not the whole
            # APK.  Round up to whole blocks on both sides to stay conservative.
            block = self.fs.block_size
            growth = _ceil_to(len(apk), block) - _ceil_to(before.size, block)
            free = self.fs.free_blocks * block
            if growth > free:
                raise LawnchairError(
                    f"the replacement is {len(apk):,} bytes against an installed "
                    f"{before.size:,}; it needs {growth:,} more bytes than "
                    f"freeing the old copy releases, but only {free:,} bytes are "
                    f"free in the partition"
                )
            self.fs.replace_file_growing(LAUNCHER_APK, apk)
        else:
            self.fs.replace_file_in_place(LAUNCHER_APK, apk)

        after = self.check_launcher()
        if after.size != len(apk) or after.sha256 != hashlib.sha256(apk).hexdigest():
            raise LawnchairError(
                "verification failed: the APK read back from the image does "
                "not match what was written"
            )
        return after

    @staticmethod
    def _validate_apk(apk: bytes) -> None:
        """Reject anything that is obviously not an installable APK."""
        if apk[:4] != APK_MAGIC:
            raise LawnchairError(
                f"the replacement does not start with a ZIP signature "
                f"(found {apk[:4]!r}); an APK is a ZIP archive"
            )
        if len(apk) < 1_000_000:
            raise LawnchairError(
                f"the replacement is only {len(apk):,} bytes, which is far too "
                f"small to be a launcher APK"
            )

    def remove_stale_oat(self) -> list[str]:
        """Delete the fork's ``.odex``/``.vdex`` by rewriting the directory.

        This is the only structural edit in the module.  ext2 directory entries
        live in data blocks owned by the directory inode, and deleting an entry
        is done by merging its record length into the previous entry's -- a
        change that keeps the block layout identical, so no blocks are freed
        and nothing else in the filesystem moves.
        """
        try:
            directory = self.fs.lookup(LAUNCHER_OAT_DIR)
        except extfs.ExtError:
            return []

        removed: list[str] = []
        for name in STALE_OAT_FILES:
            entries = self.fs.list_dir(directory)
            if not any(e.name == name for e in entries):
                continue
            self._drop_dir_entry(directory, name)
            removed.append(name)
        return removed

    def _drop_dir_entry(self, directory: extfs.Inode, name: str) -> None:
        """Remove one entry from a directory by extending its predecessor.

        Removing the name is only half of an unlink.  The file's inode still
        carries a link count of 1 and still owns its data blocks, so leaving it
        that way produces exactly what e2fsck reports as "Unattached inode N /
        Connect to /lost+found?" along with the inode's blocks still marked used
        in the bitmap.  The inode is therefore dropped as well.
        """
        blocks = self.fs._block_list(directory)
        if not blocks or blocks[0] == 0:
            raise LawnchairError(f"directory inode {directory.number} has no data")

        # Directories in this filesystem fit in one block for this path, but
        # handle several anyway by scanning block by block.
        target_found = False
        target_inode = 0
        for block in blocks:
            if block == 0:
                continue
            data = bytearray(self.fs.read_block(block))
            off = 0
            prev_off = None
            while off + 8 <= len(data):
                ino, rec_len, name_len, _ftype = struct.unpack_from("<IHBB", data, off)
                if rec_len == 0:
                    break
                entry_name = bytes(data[off + 8 : off + 8 + name_len]).decode("utf-8", "replace")
                if entry_name == name and ino != 0:
                    if prev_off is None:
                        raise LawnchairError(
                            f"cannot remove the first entry ({name!r}) of a "
                            f"directory by merging; refusing"
                        )
                    prev_len = struct.unpack_from("<H", data, prev_off + 4)[0]
                    struct.pack_into("<H", data, prev_off + 4, prev_len + rec_len)
                    self.fs.dev.write_at(self.fs.block_offset(block), bytes(data))
                    target_found = True
                    target_inode = ino
                    break
                if ino != 0:
                    prev_off = off
                off += rec_len
            if target_found:
                break

        if not target_found:
            raise LawnchairError(f"directory entry {name!r} was not found to remove")

        # Free the inode itself: drop its link count to zero and release the
        # blocks it owned, so the bitmap and the inode table agree again.
        self.fs.unlink_inode(target_inode)

        # Re-read: the removal must leave a directory that still parses.
        try:
            remaining = {e.name for e in self.fs.list_dir(directory)}
        except extfs.ExtError as exc:
            raise LawnchairError(
                f"the directory became unreadable after removing {name!r} "
                f"({exc}); the image is inconsistent"
            ) from exc
        if name in remaining:
            raise LawnchairError(f"{name!r} is still present after removal; the edit did not take")


def verify_apk_is_launcher(apk: bytes) -> list[str]:
    """Check an APK really is the Lawnchair launcher, returning findings.

    Cheap structural checks only -- this is a guard against handing the tool a
    random file, not a full package validation.
    """
    import io
    import zipfile

    problems: list[str] = []
    if apk[:4] != APK_MAGIC:
        return [f"not a ZIP archive (starts with {apk[:4]!r})"]
    try:
        with zipfile.ZipFile(io.BytesIO(apk)) as z:
            names = z.namelist()
            if "AndroidManifest.xml" not in names:
                problems.append("no AndroidManifest.xml: not an APK")
            if not any(n.startswith("classes") and n.endswith(".dex") for n in names):
                problems.append("no classes*.dex: nothing to run")
            # The guest is x86_64; a launcher without that ABI cannot start.
            abis = {n.split("/")[1] for n in names if n.startswith("lib/")}
            if abis and "x86_64" not in abis:
                problems.append(
                    f"no lib/x86_64 (found {sorted(abis)}); this guest reports "
                    f"ro.product.abi=x86_64, so the launcher would not start"
                )
            try:
                manifest = z.read("AndroidManifest.xml").decode("utf-16-le", "ignore")
            except KeyError:
                manifest = ""
            if "app.lawnchair" not in manifest:
                problems.append(
                    "the manifest does not declare app.lawnchair; this would "
                    "install as a different package rather than replacing the "
                    "launcher"
                )
    except zipfile.BadZipFile as exc:
        problems.append(f"the archive is corrupt: {exc}")
    return problems
