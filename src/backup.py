"""Backup, manifest and restore handling.

In-place patching is only acceptable because every modified file is captured
first, with a SHA-256 recorded in a manifest.  Restore re-verifies that hash
before writing anything back, so a corrupted backup is refused rather than
propagated over a working file.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import shutil
import tempfile
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Literal

MANIFEST_NAME = "manifest.json"


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path, chunk: int = 1 << 20) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        while block := fh.read(chunk):
            h.update(block)
    return h.hexdigest()


def default_backup_root() -> Path:
    """Backups live outside the repo so they survive a clean checkout."""
    base = os.environ.get("MUMU_PATCH_BACKUP_ROOT")
    if base:
        return Path(base)
    xdg = os.environ.get("XDG_DATA_HOME")
    root = Path(xdg) if xdg else Path.home() / ".local" / "share"
    return root / "mumu-patch" / "backups"


@dataclass
class FileRecord:
    """One backed-up file."""

    original_path: str
    backup_path: str
    size: int
    sha256: str
    applied_patches: list[str] = field(default_factory=list)


@dataclass
class Manifest:
    created: float
    product_version: str
    install_dir: str
    patch_ids: list[str] = field(default_factory=list)
    files: list[FileRecord] = field(default_factory=list)
    # Set when the run that produced this backup did not finish.  The files in
    # it are still valid and restorable -- they are copies of what was on disk
    # before the edit -- but the edit may have stopped partway.
    interrupted: bool = False

    @property
    def path(self) -> Path:
        return Path(self.install_dir)

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2, ensure_ascii=False)

    @classmethod
    def from_json(cls, text: str) -> Manifest:
        d = json.loads(text)
        d["files"] = [FileRecord(**f) for f in d.get("files", [])]
        return cls(**d)


class BackupSession:
    """A transaction over the install directory.

    Usage::

        with BackupSession(install_dir, version, patch_ids) as s:
            s.backup(path)          # capture before modifying
            ...
            s.save()                # marks the session complete

    The backup is written to a staging directory and only *promoted* to its
    final name once it is whole and hash-verified.  Staging means an
    interrupted copy never looks like a usable backup.

    The important property is what happens on **failure**: the files are kept,
    not deleted.  A backup is insurance against the very failure that is in
    progress, and a run that dies partway through is exactly when it is needed
    -- so this class never removes a backup that holds data.  It only removes a
    staging directory that never received a complete file, which is the one
    case where nothing of value is lost.

    Earlier versions removed the whole session directory whenever the block
    raised.  That deleted the backup the error message was telling the user to
    restore from, leaving a corrupt image and no way back.
    """

    def __init__(
        self,
        install_dir: Path,
        product_version: str,
        patch_ids: list[str],
        root: Path | None = None,
    ) -> None:
        self.install_dir = Path(install_dir)
        self.product_version = product_version
        self.patch_ids = list(patch_ids)
        self.root = Path(root) if root else default_backup_root()
        stamp = time.strftime("%Y%m%d-%H%M%S")
        self.dir = self.root / product_version / stamp
        # The staging directory sits next to the final one, so promoting it is
        # a same-filesystem rename.
        self._staging = self.dir.parent / f".{stamp}.incomplete"
        self.manifest = Manifest(
            created=time.time(),
            product_version=product_version,
            install_dir=str(self.install_dir),
            patch_ids=list(patch_ids),
        )
        self._saved = False
        self._entered = False
        self._complete = False

    def __enter__(self) -> BackupSession:
        self._staging.mkdir(parents=True, exist_ok=True)
        self._entered = True
        return self

    # `Literal[False]` rather than `bool`: this never suppresses the
    # exception, and saying so is what lets a type checker see that values
    # assigned inside the `with` block are bound afterwards.
    def __exit__(self, exc_type, exc, tb) -> Literal[False]:
        if exc_type is not None and not self._saved:
            # Promote whatever was captured before the failure.  A partial
            # backup is far better than none: restoring the files that *were*
            # captured is a legitimate repair, and the manifest records which
            # those are.
            self._promote(failed=True)
        return False

    def _promote(self, *, failed: bool = False) -> Path | None:
        """Move the staging directory to its final name.

        Returns the final directory, or ``None`` if there was nothing to keep.

        A manifest is always written, because ``backup_path`` cannot be known
        until the directory has its final name and a session without one is not
        discoverable by :func:`load_manifests`.
        """
        if not self._staging.is_dir():
            return None
        has_data = any(p for p in self._staging.iterdir() if p.name != MANIFEST_NAME)
        if not has_data:
            # Never captured a single file; nothing of value, so drop it rather
            # than leave an empty directory that looks like a backup.
            shutil.rmtree(self._staging, ignore_errors=True)
            return None
        target = self.dir
        n = 1
        while target.exists():
            target = self.dir.parent / f"{self.dir.name}-{n}"
            n += 1
        self.dir = target
        # Rewrite the paths for the final location *before* the rename, so the
        # manifest never briefly describes the staging directory.
        for rec in self.manifest.files:
            rec.backup_path = str(target / Path(rec.backup_path).name)
        if failed:
            self.manifest.interrupted = True
        (self._staging / MANIFEST_NAME).write_text(self.manifest.to_json(), encoding="utf-8")
        os.replace(self._staging, target)
        self._complete = True
        return target

    def backup(self, path: Path, applied_patches: list[str] | None = None) -> FileRecord:
        """Copy ``path`` into the session and record its hash."""
        path = Path(path)
        if not path.is_file():
            raise FileNotFoundError(path)
        if not self._entered:
            raise RuntimeError("BackupSession must be used as a context manager")
        digest = sha256_file(path)
        rel = path.name
        target = self._staging / rel
        n = 1
        while target.exists():
            target = self._staging / f"{path.stem}.{n}{path.suffix}"
            n += 1
        shutil.copy2(path, target)
        # Re-hash the copy: never trust that the write landed intact.
        copied = sha256_file(target)
        if copied != digest:
            raise OSError(f"backup verification failed for {path}: {digest} != {copied}")
        # Flush the copy to stable storage *before* anything is allowed to
        # modify the original.  Without this a power loss can leave a
        # manifest that names a file whose contents never reached the disk.
        with open(target, "rb+") as fh:
            os.fsync(fh.fileno())
        rec = FileRecord(
            original_path=str(path),
            backup_path=str(target),
            size=path.stat().st_size,
            sha256=digest,
            applied_patches=list(applied_patches or self.patch_ids),
        )
        self.manifest.files.append(rec)
        return rec

    def save(self) -> Path:
        """Finalise the backup: write the manifest and promote the directory."""
        if not self._entered:
            raise RuntimeError("BackupSession must be used as a context manager")
        if not self.manifest.files:
            raise OSError("nothing was backed up; refusing to record an empty session")
        final = self._promote()
        if final is None:
            raise OSError("nothing was backed up; refusing to record an empty session")
        # Flush the manifest, then the directory entry itself, so a crash cannot
        # leave a promoted directory whose manifest is not yet on disk.
        mpath = final / MANIFEST_NAME
        with open(mpath, "rb+") as fh:
            os.fsync(fh.fileno())
        try:
            dirfd = os.open(final, os.O_RDONLY)
            try:
                os.fsync(dirfd)
            finally:
                os.close(dirfd)
        except OSError:
            pass  # not supported on every platform/filesystem
        self._saved = True
        return mpath


def atomic_write(path: Path, data: bytes) -> None:
    """Write ``data`` to ``path`` via a same-directory temp file + replace.

    Same-directory matters: ``os.replace`` is only atomic within a filesystem,
    and this keeps the original intact if we die mid-write.
    """
    path = Path(path)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise


def load_manifests(root: Path | None = None) -> list[tuple[Path, Manifest]]:
    """All manifests found under the backup root, newest first.

    Staging directories (``.<stamp>.incomplete``) are skipped: an interrupted
    run may have left a manifest that names files it never finished copying,
    and offering that as a restore source would be worse than offering none.
    """
    root = Path(root) if root else default_backup_root()
    out: list[tuple[Path, Manifest]] = []
    if not root.is_dir():
        return out
    for mpath in root.glob(f"*/*/{MANIFEST_NAME}"):
        if any(part.startswith(".") for part in mpath.relative_to(root).parts):
            continue
        try:
            m = Manifest.from_json(mpath.read_text(encoding="utf-8"))
        except OSError, ValueError, TypeError:
            continue
        out.append((mpath, m))
    out.sort(key=lambda t: t[1].created, reverse=True)
    return out


def incomplete_sessions(root: Path | None = None) -> list[Path]:
    """Staging directories left behind by an interrupted run."""
    root = Path(root) if root else default_backup_root()
    if not root.is_dir():
        return []
    return sorted(p for p in root.glob("*/.??*.incomplete") if p.is_dir())


def verify_backup(manifest: Manifest) -> list[tuple[str, str]]:
    """Check every file a manifest names actually exists and hashes correctly.

    Returns ``(path, problem)`` pairs; an empty list means the backup is sound
    and can be restored.  This is what a write path should call *before*
    touching the original, so it never starts an edit it cannot undo.
    """
    problems: list[tuple[str, str]] = []
    for rec in manifest.files:
        src = Path(rec.backup_path)
        if not src.is_file():
            problems.append((str(src), "the backup file is missing"))
            continue
        try:
            size = src.stat().st_size
        except OSError as exc:
            problems.append((str(src), f"unreadable: {exc}"))
            continue
        if size != rec.size:
            problems.append((str(src), f"size is {size:,} bytes, the manifest says {rec.size:,}"))
            continue
        actual = sha256_file(src)
        if actual != rec.sha256:
            problems.append((str(src), f"hash is {actual}, the manifest says {rec.sha256}"))
    return problems


def restore_files(manifest: Manifest, *, dry_run: bool = False) -> list[tuple[str, str]]:
    """Restore every file in ``manifest``.

    Returns ``(path, status)`` pairs where status is ``restored``, ``unchanged``
    or ``missing``.  Raises if a backup fails its own hash check.
    """
    results: list[tuple[str, str]] = []
    for rec in manifest.files:
        src = Path(rec.backup_path)
        dst = Path(rec.original_path)
        if not src.is_file():
            results.append((str(dst), "missing"))
            continue
        actual = sha256_file(src)
        if actual != rec.sha256:
            raise OSError(
                f"backup hash mismatch for {src}: manifest says {rec.sha256}, "
                f"file is {actual}; refusing to restore"
            )
        if dst.is_file() and sha256_file(dst) == rec.sha256:
            results.append((str(dst), "unchanged"))
            continue
        if not dry_run:
            atomic_write(dst, src.read_bytes())
        results.append((str(dst), "restored"))
    return results
