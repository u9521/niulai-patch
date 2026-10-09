"""Identifying *which vendor build* a profile was authored against.

Why not just hash the file
--------------------------
A profile's target is the very file we modify, so any whole-file hash changes
the moment the first patch is applied.  A guard built on one would report
"different build" immediately after a successful run -- exactly backwards.

What is stable instead
----------------------
The patches in this project only ever write into ``.text`` (they rewrite
instructions and NOP call sites).  Every other section -- ``.rdata`` string
tables, ``.idata`` import names, ``.rsrc``, ``.reloc`` -- is left untouched, and
``strip_signature`` only truncates the trailing certificate blob and zeroes the
security directory.  So a digest over the *non-executable* sections is identical
before and after patching.  This is verified, not assumed: see
``tests/test_buildid.py::test_fingerprint_survives_our_own_patching``.

``TimeDateStamp`` and ``SizeOfImage`` come along as cheap corroboration.  Both
also survive patching, and both move when the vendor ships a new link.

What this is for
----------------
Diagnosis, not enforcement.  When the fingerprint does not match, the useful
message is "these profiles were authored against a different MuMu build", rather
than twenty-one separate signature failures that each look like a bug in the
signature.  The per-patch checks remain the real gate, and a mismatch is a
warning that never blocks a write.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from . import pe

# Sections whose contents a patch may legitimately rewrite.  Everything else
# feeds the fingerprint.  Matching on the flag rather than the name keeps this
# correct for a build that renames or merges sections.
_EXCLUDED_CHARACTERISTICS = 0x20000000  # IMAGE_SCN_MEM_EXECUTE


def _stable_sections(info: pe.PEInfo) -> list[pe.Section]:
    """Sections a patch never writes to, in file order."""
    return [
        s
        for s in info.sections
        if s.raw_size and not (s.characteristics & _EXCLUDED_CHARACTERISTICS)
    ]


def fingerprint(data: bytes) -> str:
    """A short, stable identity for the vendor build of ``data``.

    Returns 16 hex characters.  Two images with the same fingerprint are the
    same vendor build as far as this project is concerned -- that is, they agree
    on every section the patches do not touch, plus the linker timestamp and the
    image size.

    Deliberately short: this is compared by eye in a terminal and pasted into a
    TOML file, and a 64-character digest would be unreadable for no benefit.  It
    is an identity check between two builds of the same product, not a
    collision-resistant commitment.
    """
    info = pe.parse(data)
    digest = hashlib.sha256()
    # Bind the header facts first, so a section reshuffle cannot alias.
    digest.update(b"mumu-patch-buildid\x00")
    digest.update(info.timestamp.to_bytes(4, "little"))
    digest.update(info.size_of_image.to_bytes(4, "little"))
    digest.update(info.machine.to_bytes(2, "little"))
    for section in _stable_sections(info):
        # The name is included so that renaming a section changes the identity;
        # the sizes are included because a section that grew means the vendor
        # changed something we are not hashing directly.
        digest.update(section.name.encode("latin-1"))
        digest.update(b"\x00")
        digest.update(section.virtual_size.to_bytes(4, "little"))
        digest.update(section.raw_size.to_bytes(4, "little"))
        digest.update(data[section.raw_offset : section.raw_end])
    return digest.hexdigest()[:16]


@dataclass(frozen=True)
class BuildMismatch:
    """A profile's recorded build does not match the file on disk."""

    file: str
    expected: str
    actual: str

    def describe(self) -> str:
        return (
            f"{self.file}: profiles were authored against build "
            f"{self.expected}, this file is build {self.actual}"
        )


def check(data: bytes, file: str, expected: str | None) -> BuildMismatch | None:
    """Compare ``data``'s build identity against ``expected``.

    Returns ``None`` when there is nothing to check (no ``expected``) or when
    the build matches.  A profile that records no build is not a mismatch -- the
    field is optional so that a hand-written profile still loads.
    """
    if not expected:
        return None
    actual = fingerprint(data)
    if actual == expected:
        return None
    return BuildMismatch(file=file, expected=expected, actual=actual)
