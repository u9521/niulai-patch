"""PE file manipulation primitives.

Everything here operates on raw bytes so that patching stays byte-exact and
independent of any particular PE library's re-serialisation.

Two facts about the MuMu binaries shape this module (both verified on
MuMuNxMain.exe 6.8.2.0):

* ASLR is enabled (``DllCharacteristics`` = 0x8160, ``DYNAMIC_BASE`` set, and a
  ``.reloc`` section is present).  A runtime address observed in x64dbg is
  therefore *not* stable across runs -- only the RVA is.  All signatures and
  patch records are expressed as RVAs and converted here.
* The Authenticode signature is a standard ``WIN_CERTIFICATE``: ``dwLength``
  equals the security directory size exactly, ``wRevision`` = 0x0200 and
  ``wCertType`` = 2, followed by a plain PKCS#7 blob with no trailing padding.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

import pefile

IMAGE_DIRECTORY_ENTRY_IMPORT = 1
IMAGE_DIRECTORY_ENTRY_SECURITY = 4
# Size of IMAGE_OPTIONAL_HEADER's fixed portion before the data directories,
# for PE32+.  Field offsets below are relative to the optional header start.
_OPT_MAGIC_PE32 = 0x10B
_OPT_MAGIC_PE32_PLUS = 0x20B
_CHECKSUM_OFFSET = 64  # ULONG CheckSum, identical for PE32 and PE32+


class PEError(Exception):
    """Raised when a file is not a PE we can safely operate on."""


@dataclass(frozen=True)
class Section:
    name: str
    virtual_address: int
    virtual_size: int
    raw_offset: int
    raw_size: int
    characteristics: int

    @property
    def is_executable(self) -> bool:
        return bool(self.characteristics & 0x20000000)

    @property
    def raw_end(self) -> int:
        return self.raw_offset + self.raw_size


@dataclass(frozen=True)
class PEInfo:
    """Structural facts read straight from the headers."""

    machine: int
    num_sections: int
    checksum_offset: int
    checksum: int
    cert_offset: int
    cert_size: int
    file_size: int
    sections: tuple[Section, ...]
    # COFF TimeDateStamp and the optional header's SizeOfImage.  Neither is
    # touched by patching (verified: both survive `strip_signature` and every
    # profile), which is what makes them usable as build-identity inputs.
    timestamp: int = 0
    size_of_image: int = 0
    # Preferred load address from the optional header.  Only needed to convert
    # the absolute addresses pefile reports back into RVA space; nothing in the
    # patching path depends on it, because ASLR makes it meaningless at runtime.
    image_base: int = 0

    @property
    def is_64bit(self) -> bool:
        return self.machine == 0x8664

    @property
    def has_signature(self) -> bool:
        return self.cert_size > 0 and self.cert_offset > 0


def _u16(d: bytes, off: int) -> int:
    return struct.unpack_from("<H", d, off)[0]


def _u32(d: bytes, off: int) -> int:
    return struct.unpack_from("<I", d, off)[0]


def parse(data: bytes) -> PEInfo:
    """Read the header fields we depend on, without any rewriting."""
    if len(data) < 0x40 or data[:2] != b"MZ":
        raise PEError("not a PE file: missing MZ signature")
    pe_off = _u32(data, 0x3C)
    if pe_off + 24 > len(data) or data[pe_off : pe_off + 4] != b"PE\0\0":
        raise PEError("not a PE file: missing PE signature")

    machine = _u16(data, pe_off + 4)
    num_sections = _u16(data, pe_off + 6)
    timestamp = _u32(data, pe_off + 8)
    opt_size = _u16(data, pe_off + 20)
    opt = pe_off + 24
    if opt + opt_size > len(data):
        raise PEError("truncated optional header")

    magic = _u16(data, opt)
    if magic == _OPT_MAGIC_PE32_PLUS:
        num_dirs_off = opt + 108
        dirs_off = opt + 112
    elif magic == _OPT_MAGIC_PE32:
        num_dirs_off = opt + 92
        dirs_off = opt + 96
    else:
        raise PEError(f"unknown optional header magic {magic:#x}")

    # SizeOfImage is at optional-header offset 56 for both PE32 and PE32+.
    size_of_image = _u32(data, opt + 56)
    # ImageBase is at optional-header offset 24 (8 bytes for PE32+, 4 for PE32).
    image_base = (
        struct.unpack_from("<Q", data, opt + 24)[0]
        if magic == _OPT_MAGIC_PE32_PLUS
        else _u32(data, opt + 24)
    )

    checksum_off = opt + _CHECKSUM_OFFSET
    checksum = _u32(data, checksum_off)

    num_dirs = _u32(data, num_dirs_off)
    cert_offset = cert_size = 0
    if num_dirs > IMAGE_DIRECTORY_ENTRY_SECURITY:
        entry = dirs_off + IMAGE_DIRECTORY_ENTRY_SECURITY * 8
        cert_offset = _u32(data, entry)
        cert_size = _u32(data, entry + 4)

    sec_off = opt + opt_size
    sections: list[Section] = []
    for i in range(num_sections):
        o = sec_off + i * 40
        if o + 40 > len(data):
            raise PEError("truncated section table")
        name = data[o : o + 8].rstrip(b"\0").decode("latin-1")
        v_size, v_addr, r_size, r_off = struct.unpack_from("<IIII", data, o + 8)
        chars = _u32(data, o + 36)
        sections.append(Section(name, v_addr, v_size, r_off, r_size, chars))

    return PEInfo(
        machine=machine,
        num_sections=num_sections,
        checksum_offset=checksum_off,
        checksum=checksum,
        cert_offset=cert_offset,
        cert_size=cert_size,
        file_size=len(data),
        sections=tuple(sections),
        timestamp=timestamp,
        size_of_image=size_of_image,
        image_base=image_base,
    )


def rva_to_offset(info: PEInfo, rva: int) -> int | None:
    """Map an RVA to a file offset, or None if it is not backed by raw data."""
    for s in info.sections:
        span = max(s.virtual_size, s.raw_size)
        if s.virtual_address <= rva < s.virtual_address + span:
            delta = rva - s.virtual_address
            if delta >= s.raw_size:
                return None  # in virtual padding, not present in the file
            return s.raw_offset + delta
    return None


def offset_to_rva(info: PEInfo, offset: int) -> int | None:
    """Inverse of :func:`rva_to_offset` for header-free file offsets."""
    for s in info.sections:
        if s.raw_offset <= offset < s.raw_end:
            return s.virtual_address + (offset - s.raw_offset)
    return None


def pe_checksum(data: bytes, checksum_offset: int) -> int:
    """Reimplement Windows' ``CheckSumMappedFile``.

    The algorithm folds the file into a 16-bit ones-complement sum over
    16-bit words, skipping the 4-byte CheckSum field itself, then adds the
    total file length.
    """
    total = 0
    length = len(data)
    # Sum 16-bit words, excluding the checksum field (4 bytes at the offset).
    i = 0
    while i + 1 < length:
        if checksum_offset <= i < checksum_offset + 4:
            i += 2
            continue
        total += _u16(data, i)
        total = (total & 0xFFFF) + (total >> 16)
        i += 2
    if i < length:
        # Odd trailing byte is treated as the low half of a 16-bit word.
        total += data[i]
        total = (total & 0xFFFF) + (total >> 16)

    total = (total & 0xFFFF) + (total >> 16)
    total = total + (total >> 16)
    total &= 0xFFFF
    total += length
    return total & 0xFFFFFFFF


def strip_signature(data: bytes) -> tuple[bytes, bool]:
    """Remove the Authenticode signature and fix up the headers.

    Returns ``(new_data, changed)``.  Idempotent: an unsigned file yields
    ``changed=False`` and is returned unchanged.

    The security data directory is zeroed and the file truncated at the
    signature's start, so no orphaned blob remains.  Because the signature
    lives at the very end of the file, truncation cannot disturb any section.
    """
    info = parse(data)
    if not info.has_signature:
        return data, False

    end = info.cert_offset + info.cert_size
    if end > len(data):
        raise PEError(f"security directory runs past end of file ({end:#x} > {len(data):#x})")
    if end != len(data):
        # Not fatal, but worth surfacing: something follows the signature.
        # Truncating is still correct because the directory is authoritative.
        pass

    # Re-parse to locate the directory entry, then zero it.
    pe_off = _u32(data, 0x3C)
    opt = pe_off + 24
    magic = _u16(data, opt)
    dirs_off = opt + (112 if magic == _OPT_MAGIC_PE32_PLUS else 96)
    entry = dirs_off + IMAGE_DIRECTORY_ENTRY_SECURITY * 8

    buf = bytearray(data[: info.cert_offset])
    struct.pack_into("<II", buf, entry, 0, 0)

    # Recompute the checksum over the final bytes and write it in.
    new_checksum = pe_checksum(bytes(buf), info.checksum_offset)
    struct.pack_into("<I", buf, info.checksum_offset, new_checksum)
    return bytes(buf), True


def verify_structure(data: bytes) -> list[str]:
    """Sanity-check a patched image; returns a list of problems (empty = OK).

    Uses pefile as an independent parser so we are not merely validating our
    own arithmetic against itself.
    """
    problems: list[str] = []
    try:
        pe = pefile.PE(data=data, fast_load=True)
    except Exception as exc:  # pragma: no cover - defensive
        return [f"pefile could not parse image: {exc}"]
    try:
        if not pe.sections:
            problems.append("no sections parsed")
        for s in pe.sections:
            name = s.Name.rstrip(b"\0").decode("latin-1")
            if s.SizeOfRawData and s.PointerToRawData + s.SizeOfRawData > len(data):
                problems.append(f"section {name} raw data runs past EOF")
        # `OPTIONAL_HEADER` and its members are created dynamically by pefile
        # from the structure definition, so they carry no type information; the
        # attribute exists on every successfully parsed image.
        directories = pe.OPTIONAL_HEADER.DATA_DIRECTORY  # type: ignore[reportAttributeAccessIssue,reportOptionalMemberAccess]
        d = directories[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]]
        if d.Size and d.VirtualAddress + d.Size > len(data):
            problems.append("security directory points past EOF")
    finally:
        pe.close()
    return problems


def find_in_executable_sections(data: bytes, needle: bytes) -> list[int]:
    """Return file offsets of ``needle`` restricted to executable sections."""
    info = parse(data)
    hits: list[int] = []
    for s in info.sections:
        if not s.is_executable:
            continue
        blob = data[s.raw_offset : s.raw_end]
        start = 0
        while True:
            i = blob.find(needle, start)
            if i < 0:
                break
            hits.append(s.raw_offset + i)
            start = i + 1
    return hits
