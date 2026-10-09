#!/usr/bin/env python3
"""Regenerate the bundled startup images from one source picture.

The MuMu device splash reads nine ``img_startup_*.jpeg`` resources out of

    nx_device/15.0/shell/rcc/NxDeviceResource.rcc

and every one of them is 16:9 (see ``doc/analysis/splash-artwork.md``).  Six are
3200x1800 and three are 3836x2160, but the *aspect* is identical, so a single
16:9 crop serves all nine -- what differs is only the byte budget each slot
allows, and the smallest of those is the binding constraint.

This script produces the two files that ship under ``src/prebuilts/splash/``:

    splash-3200x1800.jpg    16:9 landscape, the default for every slot
    splash-1800x3200.jpg    9:16 portrait, for portrait-oriented windows

Both are encoded to fit the smallest slot (571,620 bytes of JPEG payload), so
either can be handed to ``niulai-patch splash --image`` unchanged.

Usage:

    python tools/make_splash.py SOURCE.jpg [--outdir src/prebuilts/splash]

The source must be at least 1800 px on its short side to avoid upscaling the
portrait variant past the detail it actually carries.
"""

from __future__ import annotations

import argparse
import io
import sys
from pathlib import Path

try:
    from PIL import Image
except ImportError:  # pragma: no cover - dev-only helper
    sys.exit("Pillow is required: pip install pillow")


# The smallest `usable_jpeg_bytes` across the nine slots in NxDeviceResource.rcc.
# A file that fits this fits every slot; see `niulai-patch splash` for the table.
SLOT_BUDGET = 571_620

# The resolution the vendor ships for the six 3200x1800 slots.  Matching it
# means the application never has to upscale on the common path.
LANDSCAPE = (3200, 1800)

# 9:16 at the same pixel budget as the landscape variant.
PORTRAIT = (1800, 3200)


def crop_to_aspect(im: Image.Image, ratio: float) -> Image.Image:
    """Centre-crop to ``ratio`` (width / height), trimming the longer axis.

    Centred is right for this artwork: the subject sits on the vertical axis and
    the interesting light is spread across the middle band, so an even trim
    loses the least.
    """
    w, h = im.size
    if w / h > ratio:
        new_w = round(h * ratio)
        left = (w - new_w) // 2
        return im.crop((left, 0, left + new_w, h))
    new_h = round(w / ratio)
    top = (h - new_h) // 2
    return im.crop((0, top, w, top + new_h))


def cover_crop(im: Image.Image, size: tuple[int, int]) -> Image.Image:
    """Scale to cover ``size`` and centre-crop the overflow.

    This is what the application itself does when a window is narrower than the
    artwork's aspect, so doing it here just makes that crop deliberate instead
    of leaving it to Qt.  A letterbox-with-blur alternative was tried and
    rejected: the artwork is much brighter at the subject than at the edges, so
    the pasted band showed a visible seam no amount of feathering removed.
    """
    W, H = size
    scale = max(W / im.width, H / im.height)
    scaled = im.resize((round(im.width * scale), round(im.height * scale)), Image.LANCZOS)
    left = (scaled.width - W) // 2
    top = (scaled.height - H) // 2
    return scaled.crop((left, top, left + W, top + H))


def encode_within(im: Image.Image, budget: int) -> bytes:
    """Return the highest-quality JPEG of ``im`` that fits ``budget`` bytes.

    Chroma subsampling is tried at 4:4:4 before 4:2:0: for artwork this smooth
    the full-resolution chroma is worth more than the extra quality number, so
    a lower quality at 4:4:4 beats a higher one at 4:2:0.
    """
    best: tuple[int, int, bytes] | None = None
    for subsampling in (0, 2):
        for quality in range(95, 59, -1):
            buf = io.BytesIO()
            im.save(
                buf,
                "JPEG",
                quality=quality,
                subsampling=subsampling,
                optimize=True,
                progressive=True,
            )
            if buf.tell() <= budget:
                if (
                    best is None
                    or subsampling < best[0]
                    or (subsampling == best[0] and quality > best[1])
                ):
                    best = (subsampling, quality, buf.getvalue())
                break
    if best is None:
        raise SystemExit(f"cannot fit {im.size} into {budget} bytes even at q=60")
    return best[2]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("source", type=Path, help="source JPEG/PNG")
    ap.add_argument(
        "--outdir",
        type=Path,
        default=Path(__file__).resolve().parent.parent / "src" / "prebuilts" / "splash",
    )
    ap.add_argument(
        "--budget",
        type=int,
        default=SLOT_BUDGET,
        help=f"max JPEG bytes (default {SLOT_BUDGET:,}, the smallest slot)",
    )
    args = ap.parse_args()

    if not args.source.is_file():
        raise SystemExit(f"source not found: {args.source}")

    src = Image.open(args.source).convert("RGB")
    print(f"source : {args.source.name}  {src.width}x{src.height}  ({src.width / src.height:.4f})")

    if src.width < PORTRAIT[0]:
        print(
            f"warning: source is {src.width}px wide, portrait output is "
            f"{PORTRAIT[0]}px -- it will be upscaled",
            file=sys.stderr,
        )

    args.outdir.mkdir(parents=True, exist_ok=True)

    jobs = [
        ("splash-3200x1800.jpg", crop_to_aspect(src, 16 / 9).resize(LANDSCAPE, Image.LANCZOS)),
        ("splash-1800x3200.jpg", cover_crop(src, PORTRAIT)),
    ]
    for name, im in jobs:
        data = encode_within(im, args.budget)
        out = args.outdir / name
        out.write_bytes(data)
        print(
            f"  -> {name:<24} {im.width}x{im.height}  {len(data):,} bytes "
            f"({len(data) / args.budget * 100:.1f}% of budget)"
        )

    print(f"\nwrote {len(jobs)} file(s) to {args.outdir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
