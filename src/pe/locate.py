"""Semantic patch-site locators.

The problem this solves
-----------------------
A byte signature has to satisfy two goals at once: be *unique* in the image, and
*cover* the bytes the patch rewrites.  Those goals fight.  Covering the rewrites
means wildcarding the call displacement or the stack slot, which destroys the
very bytes that told one site from its identical neighbours -- so the author
falls back to ``locate_rva``, an absolute address that any rebuild invalidates.

Measured on the shipped profiles: 18 of 21 patches used ``locate_rva``, and a
mere 0x40-byte shift of the image broke 10 of the 13 MuMuNxMain patches.

The fix is to stop asking one pattern to do both jobs.  A *locator* answers
"where is the interesting code?" using facts that survive a rebuild -- a string
literal, an import name, a protocol constant -- and the signature is then used
only to *verify* the site the locator found.

The compound rule
-----------------
A locator produces **anchor references**, not answers.  Each reference is
expanded into **candidate sites** by scanning a bounded window for the patch's
signature.  The patch resolves if and only if the set of distinct candidate
sites is exactly one.

That conjunction is what makes otherwise-hopeless strings usable.  The literal
``avatarButton`` is referenced from six places and ``leftMuMuRemoteBtn`` from
three, so neither is unique on its own; but only one reference *of each* has the
patch's signature within its window.  Requiring anchor and signature to agree
collapses every one of them to a single site.

This is strictly *more* checking than ``locate_rva`` did, not less: the RVA path
verified a signature at one address, whereas this verifies that exactly one
(reference, site) pair exists across the whole image and refuses otherwise.
Every failure mode -- no reference, no site, several sites -- is fatal.
"""

from __future__ import annotations

import bisect
from dataclasses import dataclass
from typing import Any, ClassVar

from . import pe, sigscan

# capstone is an *optional* dependency.  Import failure is not swallowed: a
# profile that asks for a semantic locator and cannot have one must fail closed
# rather than quietly fall back to a weaker strategy that might resolve to the
# wrong site.  See `require_capstone`.
# Assigned only when capstone imports; `require_capstone()` runs before any use.
Cs: Any
CS_ARCH_X86: Any
CS_MODE_64: Any
X86_OP_MEM: Any
X86_REG_RIP: Any

try:  # pragma: no cover - exercised by tests/test_locate.py's skip logic
    from capstone import CS_ARCH_X86, CS_MODE_64, Cs
    from capstone.x86 import X86_OP_MEM, X86_REG_RIP

    HAVE_CAPSTONE = True
except ImportError:  # pragma: no cover
    HAVE_CAPSTONE = False


class LocatorError(sigscan.SignatureError):
    """A semantic locator could not resolve a site.

    Subclasses :class:`sigscan.SignatureError` so that every existing handler --
    ``patch``'s pre-flight, ``verify``, ``analyze`` -- already treats it as a
    fatal, fail-closed condition without needing to know about locators.
    """


class LocatorUnavailable(LocatorError):
    """capstone is not installed, so semantic location is impossible.

    Deliberately an error rather than a fallback.  Falling back to a bare
    signature scan would resolve a deliberately-ambiguous pattern to whichever
    site happened to come first, which is the exact failure this project treats
    as unacceptable.
    """


# Locator kinds this module knows how to evaluate.  The registry is a dict so
# that adding a kind is a local change; unknown kinds are rejected at load time
# rather than silently ignored.
KINDS = ("string-ref", "import-call")


@dataclass(frozen=True)
class Locator:
    """A declarative rule for finding candidate sites."""

    kind: str
    value: str
    #: How far, in bytes, a candidate site may sit from an anchor reference.
    window: int = 0x100

    def __post_init__(self) -> None:
        if self.kind not in KINDS:
            raise LocatorError(f"unknown locator kind {self.kind!r}; known: {', '.join(KINDS)}")
        if not self.value:
            raise LocatorError("locator needs a non-empty value")
        if self.window <= 0:
            raise LocatorError(f"locator window must be positive, got {self.window}")


def parse_locator(raw) -> Locator:
    """Build a Locator from the TOML ``locate = { ... }`` table."""
    if not isinstance(raw, dict):
        raise LocatorError(f"locate must be a table, not {type(raw).__name__}")
    try:
        kind = str(raw["kind"])
        value = str(raw["value"])
    except KeyError as exc:
        raise LocatorError(f"locate is missing key {exc}") from exc
    window = raw.get("window", 0x100)
    try:
        window = int(window, 0) if isinstance(window, str) else int(window)
    except (TypeError, ValueError) as exc:
        raise LocatorError(f"locate window is not an integer: {window!r}") from exc
    return Locator(kind=kind, value=value, window=window)


# --------------------------------------------------------------------------- #
# disassembly index
# --------------------------------------------------------------------------- #
def require_capstone() -> None:
    if not HAVE_CAPSTONE:
        raise LocatorUnavailable(
            "semantic locators need the optional 'capstone' dependency; "
            "install it with: pip install 'mumu-patch[semantic]'"
        )


class Index:
    """A per-image cache of the instruction facts the locators need.

    Building this disassembles every executable section, which measured at 0.83 s
    for a 30 MB MuMuNxMain.exe -- too slow to redo for each of twenty-one
    patches, so the result is cached against the image's identity.

    The cache keys on ``id(data)`` *and* holds a reference to ``data``, which is
    what makes the key sound: the buffer cannot be freed and its address reused
    while we are holding it.  Without that reference a later, different image
    could land on the same address and be served a stale index -- which silently
    returns another file's sites.  That is not hypothetical; it is what the
    first version of this cache did, and ``test_index_cache_does_not_alias``
    pins the fix.
    """

    _CACHE: ClassVar[dict[tuple[int, int], tuple[bytes, Index]]] = {}
    _CACHE_LIMIT = 4

    def __init__(self, data: bytes) -> None:
        self._info = pe.parse(data)
        self._base = self._info.image_base
        #: RVA of every `lea r64, [rip+disp]` whose target is a printable
        #: NUL-terminated string, paired with that string.
        self.string_refs: list[tuple[int, str]] = []
        #: Sorted RVAs of `string_refs`, for bisecting a window.
        self._string_keys: list[int] = []
        #: RVA of every `call qword ptr [rip+disp]` whose target is an IAT slot,
        #: paired with the imported symbol's name.
        self.import_calls: list[tuple[int, str]] = []
        self._build(data)

    @classmethod
    def for_data(cls, data: bytes) -> Index:
        key = (id(data), len(data))
        hit = cls._CACHE.get(key)
        if hit is not None and hit[0] is data:
            return hit[1]
        idx = cls(data)
        if len(cls._CACHE) >= cls._CACHE_LIMIT:
            cls._CACHE.clear()
        # The tuple holds a strong reference to `data`, keeping its address
        # unique for as long as the entry lives.
        cls._CACHE[key] = (data, idx)
        return idx

    # -- construction ------------------------------------------------------ #
    def _build(self, data: bytes) -> None:
        require_capstone()
        self._md = Cs(CS_ARCH_X86, CS_MODE_64)
        self._md.detail = True
        self._imports = _import_slots(data)

        for section in self._info.sections:
            if not section.is_executable or not section.raw_size:
                continue
            self._scan_section(data, section)

        self.string_refs.sort()
        self._string_keys = [r for r, _ in self.string_refs]
        self.import_calls.sort()

    def _scan_section(self, data: bytes, section: pe.Section) -> None:
        """Find string and import references in one executable section.

        Why this is a byte scan plus per-candidate decode, rather than one
        linear ``md.disasm`` pass
        ------------------------------------------------
        Linear disassembly from the section start desyncs as soon as it reaches
        data embedded in ``.text`` -- jump tables, vtables, string blobs -- and
        capstone then stops at the first byte it cannot decode.  On
        MuMuNxMain.exe that happened at RVA 0x40e1c, so a linear sweep saw 1057
        string references where the image actually contains tens of thousands,
        and silently missed every site this module exists to find.  (``skipdata``
        is not a fix either: it resynchronises one byte at a time and produced
        ten million bogus "instructions" for the same section.)

        Scanning for the handful of opcode shapes that can encode the references
        we care about, and decoding each hit individually, is immune to desync:
        a candidate that is really mid-instruction simply fails to decode or
        decodes to something that is not the shape we want, and is discarded.
        Decoding at a known offset is also self-validating in a way a linear
        sweep is not -- the bytes are only accepted if they form the instruction
        we are looking for.

        The cost is a bounded number of single-instruction decodes, which
        measured far cheaper than the sweep it replaces.
        """
        blob = data[section.raw_offset : section.raw_end]
        base = section.virtual_address
        n = len(blob)

        # `lea r64, [rip+disp32]` -- REX.W (0x48..0x4F with the W bit), 0x8D, and
        # a modrm with mod=00, rm=101 (rip-relative).  The reg field is free.
        i = 0
        while i < n - 6:
            if 0x48 <= blob[i] <= 0x4F and blob[i + 1] == 0x8D and (blob[i + 2] & 0xC7) == 0x05:
                insn = self._decode_one(blob, i, base)
                if insn is not None and insn.mnemonic == "lea":
                    target = _rip_target(insn)
                    if target is not None:
                        text = _string_at(self._info, data, target)
                        if text is not None:
                            self.string_refs.append((base + i, text))
                i += 7
                continue
            i += 1

        # `call qword ptr [rip+disp32]` -- FF /2 with mod=00, rm=101, i.e. the
        # modrm byte 0x15.  No REX prefix is needed for this form, so the pair
        # is simply FF 15.  (The reg field is 2 = "/2"; masking mod and rm with
        # 0xC7 yields 0x05, which is the rip-relative shape on its own.)
        i = 0
        while i < n - 5:
            if blob[i] == 0xFF and blob[i + 1] == 0x15:
                insn = self._decode_one(blob, i, base)
                if insn is not None and insn.mnemonic == "call":
                    target = _rip_target(insn)
                    if target is not None:
                        name = self._imports.get(target)
                        if name is not None:
                            self.import_calls.append((base + i, name))
                i += 6
                continue
            i += 1

    def _decode_one(self, blob: bytes, offset: int, base: int):
        """Decode exactly one instruction at ``offset``, or None.

        The address passed to capstone is the RVA, so that a rip-relative
        operand resolves directly into RVA space with no image-base arithmetic
        at the call sites.
        """
        try:
            return next(self._md.disasm(blob[offset : offset + 16], base + offset))
        except StopIteration:
            return None

    # -- queries ----------------------------------------------------------- #
    def anchors_for(self, locator: Locator) -> list[int]:
        """RVAs of every reference matching ``locator``, sorted."""
        if locator.kind == "string-ref":
            # Exact comparison, not a prefix test: "[GameToolsPresenter::
            # fetchGameToolsConfig]" is a prefix of several longer log strings,
            # and matching on the prefix would drag in unrelated anchors.
            return [rva for rva, text in self.string_refs if text == locator.value]
        if locator.kind == "import-call":
            return [rva for rva, name in self.import_calls if name == locator.value]
        raise LocatorError(f"unknown locator kind {locator.kind!r}")

    def nearest_string(self, rva: int, *, reach: int = 0x1000) -> str | None:
        """The closest string reference at or before ``rva``, for diagnostics.

        Used by ``rebase`` to describe an unresolved site in terms a human can
        act on, rather than as a bare address.
        """
        i = bisect.bisect_right(self._string_keys, rva)
        for j in range(i - 1, -1, -1):
            rva_j = self._string_keys[j]
            if rva - rva_j > reach:
                break
            return self.string_refs[j][1]
        return None


def _rip_target(insn) -> int | None:
    """RVA of a rip-relative memory operand, or None if there is not one.

    Returns the *target* address, which for a `lea` is the address of the data
    being loaded and for a `call [rip+disp]` is the IAT slot being read.
    """
    for op in insn.operands:
        if op.type == X86_OP_MEM and op.mem.base == X86_REG_RIP:
            return insn.address + insn.size + op.mem.disp
    return None


def _string_at(info: pe.PEInfo, data: bytes, rva: int, *, maxlen: int = 200) -> str | None:
    """The NUL-terminated printable ASCII string at ``rva``, or None.

    Rejects anything that is not cleanly printable so that a `lea` pointing into
    a jump table or a vtable is not mistaken for a string reference.
    """
    off = pe.rva_to_offset(info, rva)
    if off is None:
        return None
    end = data.find(b"\0", off, off + maxlen)
    if end < 0:
        return None
    raw = data[off:end]
    if len(raw) < 4:
        return None
    if any(c < 0x20 or c > 0x7E for c in raw):
        return None
    return raw.decode("ascii")


def _import_slots(data: bytes) -> dict[int, str]:
    """Map IAT slot RVA -> imported symbol name.

    Uses ``pefile``, which is already a hard dependency, so this costs nothing
    new.  ``pefile``'s ``imp.address`` is a VA, so the image base is subtracted
    to get back into the RVA space everything else here uses.
    """
    import pefile

    slots: dict[int, str] = {}
    try:
        pf = pefile.PE(data=data, fast_load=True)
    except Exception:  # pragma: no cover - defensive
        return slots
    try:
        pf.parse_data_directories(
            directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]]
        )
        # Created dynamically by pefile when the optional header is parsed, so
        # it is untyped but present on a successfully parsed image.
        base = pf.OPTIONAL_HEADER.ImageBase  # type: ignore[reportAttributeAccessIssue,reportOptionalMemberAccess]
        for entry in getattr(pf, "DIRECTORY_ENTRY_IMPORT", []) or []:
            for imp in entry.imports:
                if imp.name:
                    slots[imp.address - base] = imp.name.decode("ascii", "replace")
    except Exception:  # pragma: no cover - defensive
        pass
    finally:
        pf.close()
    return slots


# --------------------------------------------------------------------------- #
# resolution
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class Resolution:
    """Where a semantic locator landed, and what it had to rule out."""

    rva: int
    offset: int
    anchors: tuple[int, ...]
    candidates: tuple[int, ...]

    @property
    def description(self) -> str:
        return f"anchor(s) {', '.join(hex(a) for a in self.anchors)} -> site {self.rva:#x}"


def _candidate_sites(
    data: bytes, info: pe.PEInfo, anchor: int, window: int, sig: sigscan.Signature
) -> list[int]:
    """Every RVA in ``[anchor-window, anchor+window]`` satisfying ``sig``.

    The scan walks RVA space, not raw bytes.  That distinction is load-bearing:
    a window may straddle a section boundary, and a raw slice would then compare
    bytes from two sections that are not adjacent in memory -- producing both
    false positives and false negatives.  A candidate is accepted only when its
    whole extent maps to a contiguous run of file bytes.
    """
    hits: list[int] = []
    start = max(0, anchor - window)
    for cand in range(start, anchor + window + 1):
        off = pe.rva_to_offset(info, cand)
        if off is None:
            continue
        end_off = pe.rva_to_offset(info, cand + sig.length - 1)
        if end_off is None or end_off - off != sig.length - 1:
            continue
        if all(t is None or data[off + k] == t for k, t in enumerate(sig.tokens)):
            hits.append(cand)
    return hits


def resolve(data: bytes, locator: Locator, sig: sigscan.Signature) -> Resolution:
    """Locate the single site implied by ``locator`` and ``sig``.

    Raises :class:`LocatorError` unless exactly one distinct site is found, and
    says which of the three failure modes occurred, because they call for
    different responses:

    * no anchor reference  -> the vendor changed or removed the identifying
      string; this is a real behaviour change and needs a human;
    * anchors but no site  -> the anchor is there but the code around it moved
      beyond ``window``; widen the window or re-derive the signature;
    * several sites        -> the window is too wide, or the anchor no longer
      discriminates; narrow it.
    """
    index = Index.for_data(data)
    info = pe.parse(data)
    anchors = index.anchors_for(locator)

    if not anchors:
        raise LocatorError(
            f"{locator.kind} {locator.value!r} matched no reference in this "
            f"image, so the site cannot be found"
        )

    found: list[int] = []
    for anchor in anchors:
        for site in _candidate_sites(data, info, anchor, locator.window, sig):
            if site not in found:
                found.append(site)

    if not found:
        raise LocatorError(
            f"{locator.kind} {locator.value!r} matched {len(anchors)} reference(s) "
            f"({', '.join(hex(a) for a in anchors[:4])}) but the signature "
            f"matched nothing within {locator.window:#x} bytes of any of them"
        )
    if len(found) > 1:
        raise LocatorError(
            f"{locator.kind} {locator.value!r} left {len(found)} candidate "
            f"site(s) ({', '.join(hex(f) for f in sorted(found)[:8])}); narrow "
            f"the window or tighten the signature"
        )

    rva = found[0]
    offset = pe.rva_to_offset(info, rva)
    if offset is None:  # pragma: no cover - guarded by _candidate_sites
        raise LocatorError(f"site {rva:#x} is not backed by file bytes")
    return Resolution(rva=rva, offset=offset, anchors=tuple(anchors), candidates=(rva,))
