"""Replace the raw payload of a resource inside a Qt ``.rcc`` container.

Why this exists
---------------
The MuMu device window shows a promotional image while a device boots.  The
image is *not* in the executable: ``MuMuNxDevice.exe`` downloads campaign
artwork from Netease's servers into

    %APPDATA%/Netease/MuMuPlayer/data/startupImage/<campaignId>/

and rewrites ``imageManager.json`` on **every launch**, so editing anything in
that directory is overwritten the next time the emulator starts (observed
directly: the JSON was rewritten two seconds after the process launched).
Patching the carousel logic in the executable did not suppress the image
either, so neither route is durable.

What *is* durable is the bundled fallback artwork, which lives in

    nx_device/15.0/shell/rcc/NxDeviceResource.rcc

and is only read, never rewritten.  Replacing those payloads is therefore the
one approach the application cannot undo.

Format
------
A ``.rcc`` is a Qt resource container.  This module deliberately does the
narrowest possible job: it finds a resource's payload and overwrites it *in
place*, keeping every byte count identical.  It does not rebuild the container,
because the tree and name tables interleave offsets that must stay consistent,
and a half-correct rebuild corrupts the whole 14 MB bundle.

Two properties of the format make an in-place edit safe:

* resource records carry no explicit size -- a payload runs until the next
  resource's offset, so a size change would silently shift every later
  resource.  Keeping the length identical avoids that entirely;
* ``img_startup_*.jpeg`` payloads are stored *uncompressed* (flags == 0) as
  ``<u32 big-endian length><JPEG bytes>``, and the declared length plus four
  exactly equals the slot size in every one of the nine copies.

A JPEG decoder stops at the ``FF D9`` end-of-image marker, so a replacement
that is shorter than the slot can be padded with zero bytes and still render
correctly; a replacement that is *longer* than the slot cannot be used at all.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

from . import rcc

JPEG_SOI = b"\xff\xd8\xff"
JPEG_EOI = b"\xff\xd9"


class RccPatchError(Exception):
    """Raised when a resource cannot be replaced safely."""


@dataclass(frozen=True)
class ImageSlot:
    """One ``img_startup_*`` resource and the space available for it."""

    path: str
    payload_offset: int
    """Absolute file offset of the 4-byte length prefix."""
    capacity: int
    """Bytes available for ``4 + len(jpeg)`` -- fixed by the container."""
    declared: int
    """The length currently declared in the prefix."""

    @property
    def usable_jpeg_bytes(self) -> int:
        """Largest JPEG that fits, i.e. capacity minus the length prefix."""
        return self.capacity - 4


def _slot_for(container: rcc.Rcc, res: rcc.Resource) -> ImageSlot:
    """Work out the exact byte range a resource occupies.

    The size is not recorded anywhere, so it is derived from the next
    resource's offset -- the same rule the Qt loader uses.  Payloads are packed
    tightly in offset order, which is what makes that work.

    For the final payload the bound is the **names block**, not the end of the
    file: the container lays the sections out as header, payloads, names,
    tree, and the last payload in the real container ends exactly where the
    names begin (verified: ``0xda2bf1 + 4 + 160079 == names base``). Skipping
    this would make the last slot absorb the name and tree tables and report a
    wildly wrong capacity.
    """
    if res.flags:
        raise RccPatchError(
            f"{res.path}: flags={res.flags:#x}; only uncompressed payloads can be replaced in place"
        )

    offsets = sorted(r.offset for r in container.walk())
    later = [o for o in offsets if o > res.offset]
    start = container.payloads + res.offset
    end = container.payloads + later[0] if later else container.names
    capacity = end - start

    declared = struct.unpack_from(">I", container.data, start)[0]
    if declared + 4 != capacity:
        raise RccPatchError(
            f"{res.path}: declared length {declared} + 4 != slot {capacity}; "
            f"refusing to assume the layout"
        )
    return ImageSlot(res.path, start, capacity, declared)


def find_startup_images(data: bytes) -> list[ImageSlot]:
    """Every ``img_startup_*.jpeg`` resource, in file order."""
    container = rcc.Rcc(data)
    slots = [
        _slot_for(container, res)
        for res in container.walk()
        if res.path.endswith(".jpeg") and "img_startup" in res.path
    ]
    return sorted(slots, key=lambda s: s.payload_offset)


# The splash screen draws a MuMu logo *on top of* whatever image is shown, but
# that logo is a *feature flag*, not an asset this tool rewrites: the device
# window gates it on `feature.startup_middle_logo.enabled` (id 51), and the
# `splash-logo` patch in `src/pe/patches/device-ui.toml` takes the author's own
# "do not show" branch.  Replacing the SVG in the container was tried and
# dropped -- it changes artwork the user did not ask to change, it does not
# survive an overlay resource pack, and the flag is the honest control.
# `find_logos`/`validate_svg` are not supported; see
# doc/analysis/splash-artwork.md.


def replace_image(data: bytes, slot: ImageSlot, payload: bytes) -> bytes:
    """Return ``data`` with ``slot`` holding ``payload``.

    The replacement is padded with zero bytes to exactly fill the slot.  That
    is safe because the payload has already been validated to be self-
    terminating (a JPEG ends at ``FF D9``; an SVG at ``</svg>``) and decoders
    stop there.

    Raises rather than truncating when the payload does not fit: silently
    clipping an image produces a corrupt frame that is far harder to diagnose
    than a refusal.
    """
    if len(payload) > slot.usable_jpeg_bytes:
        raise RccPatchError(
            f"{slot.path}: replacement is {len(payload)} bytes but only "
            f"{slot.usable_jpeg_bytes} fit; re-encode it smaller"
        )
    blob = bytearray(data)
    padded = payload + b"\x00" * (slot.usable_jpeg_bytes - len(payload))
    blob[slot.payload_offset : slot.payload_offset + 4] = struct.pack(">I", len(padded))
    blob[slot.payload_offset + 4 : slot.payload_offset + 4 + len(padded)] = padded
    return bytes(blob)


def validate_jpeg(jpeg: bytes) -> None:
    """Reject anything that is not a complete JPEG stream."""
    if not jpeg.startswith(JPEG_SOI):
        raise RccPatchError("replacement does not start with a JPEG SOI marker")
    end = jpeg.rfind(JPEG_EOI)
    if end < 0:
        raise RccPatchError("replacement has no JPEG EOI marker")
    if end + 2 != len(jpeg):
        raise RccPatchError(
            f"replacement has {len(jpeg) - end - 2} trailing bytes after its "
            f"EOI marker; pass the exact JPEG (or let the caller pad)"
        )
