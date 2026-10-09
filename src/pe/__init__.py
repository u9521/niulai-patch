"""Portable Executable parsing, signature scanning and declarative patching.

The submodules are re-exported here so that callers can keep writing
``pe.parse`` and ``rcc.Rcc`` rather than ``pe.pe.parse``.  The order matters:
``.pe`` is the leaf the other two import, so it is bound first and the
``from . import pe`` lines inside :mod:`sigscan` and :mod:`patcher` resolve
against a name that already exists.
"""

from . import (
    patcher,
    pe,
    sigscan,
)
from .pe import (
    PEError,
    PEInfo,
    Section,
    find_in_executable_sections,
    offset_to_rva,
    parse,
    pe_checksum,
    rva_to_offset,
    strip_signature,
    verify_structure,
)

__all__ = [
    "PEError",
    "PEInfo",
    "Section",
    "find_in_executable_sections",
    "offset_to_rva",
    "parse",
    "patcher",
    "pe",
    "pe_checksum",
    "rva_to_offset",
    "sigscan",
    "strip_signature",
    "verify_structure",
]
