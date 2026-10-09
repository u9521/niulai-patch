"""Qt resource containers (``.rcc``): reading them, and replacing images in them.

``rcc`` is the format; ``rccpatch`` is the surgical edit (startup images) that
keeps every surrounding byte count identical.  Both are re-exported here so a
caller writes ``rcc.load_rcc`` and ``rccpatch.find_startup_images``.
"""

from . import rcc, rccpatch
from .rcc import (
    FLAG_COMPRESSED,
    FLAG_COMPRESSED_ZSTD,
    FLAG_DIRECTORY,
    Rcc,
    RccError,
    Resource,
    StringHit,
    find_strings,
    load_rcc,
)
from .rccpatch import (
    RccPatchError,
    find_startup_images,
    replace_image,
    validate_jpeg,
)

__all__ = [
    "FLAG_COMPRESSED",
    "FLAG_COMPRESSED_ZSTD",
    "FLAG_DIRECTORY",
    "Rcc",
    "RccError",
    "RccPatchError",
    "Resource",
    "StringHit",
    "find_startup_images",
    "find_strings",
    "load_rcc",
    "rcc",
    "rccpatch",
    "replace_image",
    "validate_jpeg",
]
