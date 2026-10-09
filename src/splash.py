"""The startup images that ship with the project.

MuMu's device splash normally shows campaign artwork fetched from Netease and
cached under ``%APPDATA%``, refreshed on every launch -- so editing that cache
does not stick.  The durable copy is the bundled fallback inside

    nx_device/15.0/shell/rcc/NxDeviceResource.rcc

and ``niulai-patch splash`` is what replaces it.  This module supplies the
artwork that command uses when the caller does not pass ``--image``, so a fresh
checkout can set a splash without hunting for a picture first.

Layout
------
Two files, both encoded to fit the tightest of the nine resource slots
(571,620 bytes of JPEG payload -- see ``niulai-patch splash`` for the table):

    splash-3200x1800.jpg    16:9, the default for every slot
    splash-1800x3200.jpg    9:16, for portrait-oriented windows

All nine slots are 16:9 -- the six ``3200x1800`` ones and the three
``3836x2160`` ones alike -- so the landscape file is the one that matches what
the vendor ships and the one ``splash`` picks by default.  The portrait file is
a convenience: the application scales and centre-crops to the window, so a
16:9 source in a tall window is cropped, and handing it artwork already composed
for that shape gives a better result.

Regenerate either from a new source with ``tools/make_splash.py``.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

#: File names as they appear under ``prebuilts/splash/``.
LANDSCAPE_NAME = "splash-3200x1800.jpg"
PORTRAIT_NAME = "splash-1800x3200.jpg"

#: Every slot in ``NxDeviceResource.rcc`` is 16:9, so this is the default.
DEFAULT_NAME = LANDSCAPE_NAME

#: The largest JPEG payload any of the nine slots can hold.  A file at or under
#: this size fits all of them; ``niulai-patch splash`` enforces the same bound.
SLOT_BUDGET = 571_620

#: SHA-256 of the shipped files, so a corrupted or half-copied asset is caught
#: before it is written into a 14 MB resource container.
LANDSCAPE_SHA256 = "d716aec80de69304f9ced0b2d1e68af2864d21c2db07226d7d563c05f2a9aa47"
PORTRAIT_SHA256 = "af90bad2bb79e3798ea795f7dae4382f655ce4b79af54e8c3ee1295422464680"

#: Two locations are searched for the same reason as the bundled APK: a checkout
#: keeps these at ``<repo>/src/prebuilts/splash/``, while an installed wheel
#: carries them beside this module.  Both are one level up from ``src/``.
_CANDIDATE_ROOTS = (
    Path(__file__).resolve().parent / "prebuilts" / "splash",
    Path(__file__).resolve().parent.parent / "prebuilts" / "splash",
)


class SplashAssetError(Exception):
    """Raised when a bundled startup image is missing or does not verify."""


def asset_root() -> Path:
    """First candidate directory that exists, else the checkout path.

    Returning the checkout path when nothing exists makes the error message
    name the place a developer should put the file.
    """
    for root in _CANDIDATE_ROOTS:
        if root.is_dir():
            return root
    return _CANDIDATE_ROOTS[-1]


def asset_path(name: str = DEFAULT_NAME) -> Path:
    """Resolve one bundled startup image by file name."""
    if name not in (LANDSCAPE_NAME, PORTRAIT_NAME):
        raise SplashAssetError(
            f"unknown bundled splash {name!r}; expected {LANDSCAPE_NAME!r} or {PORTRAIT_NAME!r}"
        )
    return asset_root() / name


def _expected_sha256(name: str) -> str:
    return LANDSCAPE_SHA256 if name == LANDSCAPE_NAME else PORTRAIT_SHA256


def load(name: str = DEFAULT_NAME) -> bytes:
    """Read a bundled startup image, verifying its size and digest.

    The digest check matters more than it looks: the file is written straight
    into the resource container, so a truncated copy would produce a splash that
    renders as a partial image with no other symptom.
    """
    path = asset_path(name)
    if not path.is_file():
        raise SplashAssetError(
            f"bundled startup image is missing: {path}\n"
            f"regenerate it with: python tools/make_splash.py <source.jpg>"
        )
    data = path.read_bytes()
    if len(data) > SLOT_BUDGET:
        raise SplashAssetError(
            f"{path.name} is {len(data):,} bytes, over the {SLOT_BUDGET:,} "
            f"byte slot budget; re-encode it smaller"
        )
    want = _expected_sha256(name)
    if want != "PENDING":
        got = hashlib.sha256(data).hexdigest()
        if got != want:
            raise SplashAssetError(
                f"{path.name} does not match its recorded SHA-256\n"
                f"  expected {want}\n  got      {got}"
            )
    return data
