"""Byte-signature scanning.

Signatures are written as hex bytes with ``??`` wildcards, e.g.::

    48 8B 05 ?? ?? ?? ?? 85 C0 74

Matching is anchored on the *literal* runs between wildcards: we search for the
longest concrete run and then verify the rest.  That keeps scanning linear in
practice even over a 30 MB ``.text`` section.

Every match is reported as an **RVA**, never a file offset alone, because the
MuMu binaries are ASLR-enabled and only RVAs are stable between a static file
and a live x64dbg session.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from . import pe

# A wildcard may be written as "??" (canonical) or "?" (lenient alias, handy
# when copying hex dumps by hand).
_TOKEN_RE = re.compile(r"^(?:[0-9A-Fa-f]{2}|\?\?|\?)$")


class SignatureError(Exception):
    """Raised for malformed signatures or ambiguous matches."""


@dataclass(frozen=True)
class Signature:
    """A parsed byte pattern."""

    tokens: tuple[int | None, ...]  # None == wildcard
    source: str

    @property
    def length(self) -> int:
        return len(self.tokens)

    @property
    def literal_count(self) -> int:
        return sum(1 for t in self.tokens if t is not None)

    def describe(self) -> str:
        return " ".join("??" if t is None else f"{t:02X}" for t in self.tokens)


def parse_signature(text: str) -> Signature:
    """Parse a ``"48 8B ?? C3"`` style pattern."""
    raw = text.strip()
    if not raw:
        raise SignatureError("empty signature")
    # Allow compact forms like "488B??C3" as a convenience.
    if " " not in raw and len(raw) > 2 and len(raw) % 2 == 0:
        parts = [raw[i : i + 2] for i in range(0, len(raw), 2)]
    else:
        parts = raw.split()

    tokens: list[int | None] = []
    for p in parts:
        if not _TOKEN_RE.match(p):
            raise SignatureError(f"invalid signature token {p!r} in {text!r}")
        tokens.append(None if p.startswith("?") else int(p, 16))
    if not any(t is not None for t in tokens):
        raise SignatureError("signature is entirely wildcards")
    return Signature(tuple(tokens), raw)


@dataclass(frozen=True)
class Match:
    rva: int
    offset: int


def _longest_literal_run(tokens: tuple[int | None, ...]) -> tuple[bytes, int]:
    """Return (bytes, start_index) of the longest concrete run."""
    best = b""
    best_at = 0
    cur = bytearray()
    cur_at = 0
    for i, t in enumerate(tokens):
        if t is None:
            if len(cur) > len(best):
                best, best_at = bytes(cur), cur_at
            cur = bytearray()
        else:
            if not cur:
                cur_at = i
            cur.append(t)
    if len(cur) > len(best):
        best, best_at = bytes(cur), cur_at
    return best, best_at


def scan(
    data: bytes,
    sig: Signature,
    *,
    executable_only: bool = True,
    max_matches: int | None = None,
) -> list[Match]:
    """Find every match of ``sig``, returned as RVA + file offset.

    ``max_matches`` exists only to bound pathological scans and defaults to
    ``None`` (unlimited).  If a cap *is* supplied and reached, this raises
    rather than returning a partial list: a truncated result would make a
    present-but-later match look absent, which is exactly the kind of silent
    wrong answer that leads to patching the wrong place.
    """
    info = pe.parse(data)
    if sig.length > len(data):
        return []

    anchor, anchor_at = _longest_literal_run(sig.tokens)
    if not anchor:
        raise SignatureError("signature has no literal bytes to anchor on")

    regions: list[tuple[int, int]] = []
    for s in info.sections:
        if executable_only and not s.is_executable:
            continue
        if s.raw_size:
            regions.append((s.raw_offset, s.raw_end))

    tokens = sig.tokens
    matches: list[Match] = []
    for start, end in regions:
        blob = data[start:end]
        pos = 0
        while True:
            i = blob.find(anchor, pos)
            if i < 0:
                break
            pos = i + 1
            # Candidate start = anchor position minus its index in the pattern.
            cand = i - anchor_at
            if cand < 0 or cand + sig.length > len(blob):
                continue
            if all(t is None or blob[cand + k] == t for k, t in enumerate(tokens)):
                off = start + cand
                rva = pe.offset_to_rva(info, off)
                if rva is None:
                    continue
                matches.append(Match(rva=rva, offset=off))
                if max_matches is not None and len(matches) > max_matches:
                    raise SignatureError(
                        f"signature matched more than {max_matches} places "
                        f"(cap reached): {sig.describe()} -- raise max_matches "
                        f"or tighten the pattern"
                    )
    return matches


def scan_unique(data: bytes, sig: Signature, **kw) -> Match:
    """Require exactly one match.

    Deliberately strict: a signature that matches zero or several places means
    the target build differs from what the patch was written against, and
    silently picking the first hit is how you corrupt a binary.
    """
    hits = scan(data, sig, **kw)
    if not hits:
        raise SignatureError(f"signature not found (0 matches): {sig.describe()}")
    if len(hits) > 1:
        where = ", ".join(f"RVA {m.rva:#x}" for m in hits[:8])
        more = "" if len(hits) <= 8 else f" (+{len(hits) - 8} more)"
        raise SignatureError(
            f"ambiguous signature ({len(hits)} matches at {where}{more}): "
            f"{sig.describe()} -- tighten the pattern with more context"
        )
    return hits[0]
