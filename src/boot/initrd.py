"""The gzip'd cpio ramdisks that sit beside the kernel.

Two files on the boot partition are ramdisks, and they are not the same thing:

``/initrd``   2,139,855 bytes -- the real one, an Android-x86 ``init`` with
              ``bin/busybox`` and ``bin/e2fsck``.  GRUB loads it via
              ``initrd (hd0,2)/initrd``.
``/ramdisk``  1,159 bytes -- a skeleton of directory names that the Android
              first-stage init consumes.

Both are a single gzip member wrapping a ``newc`` cpio archive.

Why this module re-implements gzip rather than calling :mod:`gzip`
------------------------------------------------------------------
Because "re-compress and write it back" has to be a *no-op* when nothing
changed.  The standard library and the ``gzip`` tool both write a header this
image's producer did not:

======================  ==========  ==========
producer                /initrd     /ramdisk
======================  ==========  ==========
the original file       2,139,855   1,159
:func:`gzip.compress`   2,139,924   (not equal)
``gzip -9``             2,139,936   (not equal)
:func:`pack_gzip`       **equal**   **equal**
======================  ==========  ==========

The difference is the 10-byte header: the original stores ``XFL=2, OS=3`` for
``/initrd`` and ``XFL=0, OS=3`` for ``/ramdisk``, while the tool defaults differ
(``OS=255`` for ``gzip -n``, and neither sets ``XFL`` from the level the way
``gzip`` itself does).  So the header is written here by hand and
:func:`detect_level` recovers the level the original used by trying the levels
and comparing bytes.  Getting this wrong would not corrupt anything -- it would
silently make every ramdisk edit 69 bytes *bigger*, which matters on a
partition with 79,872 bytes free and is exactly the kind of drift that turns a
"fits in place" edit into one that allocates.

The cpio side is read-only parsing plus faithful re-emission of the fields that
were read, because the point of touching a ramdisk is usually to change *one*
file inside it, not to restyle the archive.
"""

from __future__ import annotations

import struct
import zlib
from dataclasses import dataclass
from pathlib import Path

#: gzip's own level -> XFL mapping: 9 is "maximum", 1 is "fastest", everything
#: else is 0 ("the compressor used neither of those two extremes").
_XFL_FOR_LEVEL = {9: 2, 1: 4}

#: The OS byte gzip writes on Unix.  The originals use it, so keeping it is part
#: of reproducing them byte for byte.
_OS_UNIX = 3

#: Levels tried by :func:`detect_level`, most likely first.  9 is what the
#: initrd uses and what a caller re-packing wants if recognition fails.
_LEVELS_TO_TRY = (9, 6, 1, 2, 3, 4, 5, 7, 8)


class InitrdError(Exception):
    """Raised when a ramdisk cannot be parsed, validated or re-packed."""


@dataclass(frozen=True)
class CpioEntry:
    """One ``newc`` archive member."""

    name: str
    mode: int
    size: int
    inode: int
    uid: int
    gid: int
    nlink: int
    mtime: int
    #: Byte offset of the member's payload inside the decompressed archive.
    data_offset: int

    @property
    def is_dir(self) -> bool:
        return (self.mode & 0o170000) == 0o040000

    @property
    def is_file(self) -> bool:
        return (self.mode & 0o170000) == 0o100000

    @property
    def is_symlink(self) -> bool:
        return (self.mode & 0o170000) == 0o120000


# --------------------------------------------------------------------------- #
# gzip
# --------------------------------------------------------------------------- #
def pack_gzip(data: bytes, *, level: int = 9, mtime: int = 0) -> bytes:
    """Compress ``data`` into the exact gzip framing this image was built with.

    A 10-byte header (no name, no comment, no extra field -- the originals set
    ``FLG=0``), then the raw deflate stream, then CRC-32 and the length.  The
    ``XFL`` byte follows gzip's own convention so that a caller asking for
    level 9 gets the same header byte the original ``/initrd`` has.
    """
    if not 1 <= level <= 9:
        raise InitrdError(f"compression level must be 1..9, got {level}")
    compressor = zlib.compressobj(level, zlib.DEFLATED, -15)
    body = compressor.compress(data) + compressor.flush()
    header = (
        b"\x1f\x8b\x08\x00"
        + struct.pack("<I", mtime & 0xFFFFFFFF)
        + bytes([_XFL_FOR_LEVEL.get(level, 0), _OS_UNIX])
    )
    return header + body + struct.pack("<II", zlib.crc32(data) & 0xFFFFFFFF, len(data) & 0xFFFFFFFF)


def unpack_gzip(blob: bytes) -> bytes:
    """Decompress a single gzip member, raising :class:`InitrdError` on failure.

    ``zlib`` rather than :mod:`gzip` so that trailing bytes are *data*, not a
    silent second member: a ramdisk is one member, and a file with junk after it
    is something a caller should be told about rather than have quietly
    ignored.
    """
    if blob[:2] != b"\x1f\x8b":
        raise InitrdError(f"not gzip: expected magic 1f 8b, found {blob[:2].hex() or '(empty)'}")
    try:
        decompressor = zlib.decompressobj(31)
        out = decompressor.decompress(blob)
        out += decompressor.flush()
    except zlib.error as exc:
        raise InitrdError(f"corrupt gzip stream: {exc}") from exc
    if not decompressor.eof:
        raise InitrdError("the gzip stream is truncated")
    return out


def detect_level(blob: bytes) -> int | None:
    """The compression level that reproduces ``blob`` byte for byte.

    ``None`` when no level does -- the producer used a different deflate
    implementation, a dictionary, or a level expressed differently.  A caller
    should then fall back to the first entry of ``_LEVELS_TO_TRY`` rather than
    pretend the file will round-trip.
    """
    try:
        raw = unpack_gzip(blob)
    except InitrdError:
        return None
    for level in _LEVELS_TO_TRY:
        if pack_gzip(raw, level=level) == blob:
            return level
    return None


def repack(original: bytes, payload: bytes) -> bytes:
    """Re-compress ``payload`` using the level the original was built with.

    ``payload`` is the *decompressed* archive.  Passing the original's own
    decompressed bytes back therefore returns the original file exactly, which
    is the property that makes an unchanged ramdisk cost nothing to write.
    """
    level = detect_level(original)
    return pack_gzip(payload, level=level if level is not None else 9)


# --------------------------------------------------------------------------- #
# cpio (newc)
# --------------------------------------------------------------------------- #
#: ``newc`` fixed header: 6 magic bytes then 13 eight-digit hex fields.
_NEWC_MAGIC = (b"070701", b"070702")
_HEADER_SIZE = 110
_FIELD_COUNT = 13
_TRAILER = "TRAILER!!!"


def _align4(value: int) -> int:
    return (value + 3) & ~3


def cpio_entries(raw: bytes, *, include_trailer: bool = False) -> list[CpioEntry]:
    """Walk a ``newc`` archive, returning its members.

    Stops at ``TRAILER!!!`` (which is not a member and is therefore excluded by
    default) and refuses to guess past a malformed header: a walk that keeps
    going after a bad magic produces a plausible-looking list of nonsense
    names, which is worse than an error.
    """
    entries: list[CpioEntry] = []
    pos = 0
    while pos + _HEADER_SIZE <= len(raw):
        if raw[pos : pos + 6] not in _NEWC_MAGIC:
            raise InitrdError(
                f"not a newc cpio archive: bad magic at offset {pos:#x} ({raw[pos : pos + 6]!r})"
            )
        try:
            fields = [
                int(raw[pos + 6 + i * 8 : pos + 6 + (i + 1) * 8], 16) for i in range(_FIELD_COUNT)
            ]
        except ValueError as exc:
            raise InitrdError(f"malformed newc header at offset {pos:#x}: {exc}") from exc
        (
            inode,
            mode,
            uid,
            gid,
            nlink,
            mtime,
            size,
            _devmajor,
            _devminor,
            _rdevmajor,
            _rdevminor,
            name_len,
            _check,
        ) = fields
        if name_len == 0:
            raise InitrdError(f"zero-length member name at offset {pos:#x}")
        name_at = pos + _HEADER_SIZE
        name_bytes = raw[name_at : name_at + name_len - 1]
        if len(name_bytes) != name_len - 1:
            raise InitrdError(f"member name runs past the end at offset {pos:#x}")
        name = name_bytes.decode("utf-8", "replace")
        data_at = _align4(name_at + name_len)
        if name == _TRAILER:
            if include_trailer:
                entries.append(CpioEntry(name, mode, size, inode, uid, gid, nlink, mtime, data_at))
            return entries
        entries.append(CpioEntry(name, mode, size, inode, uid, gid, nlink, mtime, data_at))
        pos = _align4(data_at + size)
    raise InitrdError("the cpio archive has no TRAILER!!! record")


def entry_names(raw: bytes) -> list[str]:
    """Just the member names, which is what ``kernel --initrd`` reports."""
    return [e.name for e in cpio_entries(raw)]


def extract_entry(raw: bytes, name: str) -> bytes:
    """One member's payload."""
    for entry in cpio_entries(raw):
        if entry.name == name:
            return raw[entry.data_offset : entry.data_offset + entry.size]
    raise InitrdError(f"no member named {name!r} in the ramdisk")


def validate_initrd(blob: bytes, *, what: str = "ramdisk") -> list[str]:
    """Check a candidate ramdisk, returning what is wrong with it.

    Returns findings rather than raising so a caller can print all of them at
    once.  The name check is the security-relevant one: these archives are
    unpacked by the guest's first-stage init as root, and a member called
    ``../../init`` would be written outside the initramfs root.
    """
    problems: list[str] = []
    try:
        raw = unpack_gzip(blob)
    except InitrdError as exc:
        return [f"{what} is not a usable gzip stream: {exc}"]

    try:
        entries = cpio_entries(raw)
    except InitrdError as exc:
        return [f"{what} is not a usable cpio archive: {exc}"]

    if not entries:
        problems.append(f"{what} contains no members")
    for entry in entries:
        if entry.name.startswith("/"):
            problems.append(f"{what} member {entry.name!r} has an absolute path")
        elif ".." in Path(entry.name).parts:
            problems.append(f"{what} member {entry.name!r} escapes the archive root")
    return problems
