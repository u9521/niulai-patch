"""Declarative patch definitions and the apply engine.

A patch is data, not code: it names a target file, a byte signature, the bytes
expected at the match, and the replacement bytes.  The engine refuses to guess
-- see :mod:`pe.sigscan` for why ambiguity is fatal.

Profiles are TOML files under ``src/pe/patches/``.
"""

from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from . import locate as locate_mod
from . import pe, sigscan


class PatchError(Exception):
    """Raised when a patch cannot be applied safely."""


PATCH_DIR = Path(__file__).parent / "patches"


@dataclass
class Patch:
    id: str
    description: str
    file: str
    signature: str
    replace: str
    # Optional literal bytes that must be present at the match site.  This is a
    # second, independent check on top of the signature.
    expect: str | None = None
    # A literal byte run that must appear immediately *before* the signature.
    # This is what keeps a signature unique when the patched bytes themselves
    # (e.g. a `lea` displacement) have to be wildcarded: the anchor supplies
    # the discriminating context, and it is never modified by the patch.
    anchor: str | None = None
    # RVAs the signature was authored against, kept as a human cross-check
    # against an x64dbg session.  Never used for the actual write.
    known_rvas: list[int] = field(default_factory=list)
    # Patch at this exact RVA instead of searching.  Needed when the compiler
    # emits byte-identical sequences for several adjacent widgets, where no
    # signature can be unique but the address is unambiguous.  The signature
    # is still verified at that address, so a wrong build is caught.
    #: Declared as the *normalised* type: ``__post_init__`` accepts the hex
    #: string TOML authors write (and tests pass for convenience) and converts
    #: it to ``int`` before anyone can observe the field.
    locate_rva: int | None = None
    # A declarative rule for finding the site from facts that survive a rebuild
    # (a string literal, an import name).  Preferred over `locate_rva` and
    # `anchor`, both of which pin build-specific numbers.  See pe.locate.
    locate: locate_mod.Locator | None = None
    disable_pe_checksum_fix: bool = False

    def __post_init__(self) -> None:
        # TOML authors write hex strings ("0x14afb2") for readability, while
        # callers constructing a Patch directly tend to pass ints.  Accept both
        # rather than making the type a trap at the point of use.
        if isinstance(self.locate_rva, str):
            self.locate_rva = int(self.locate_rva, 0)

    def parsed_signature(self) -> sigscan.Signature:
        return sigscan.parse_signature(self.signature)

    def resolver(self) -> str:
        """Which strategy will find this patch's site.

        Reported by ``analyze`` and ``rebase`` so that a profile drifting back
        toward a build-specific resolver is visible rather than silent.
        """
        if self.locate is not None:
            return f"locate:{self.locate.kind}"
        if self.locate_rva is not None:
            return "locate_rva"
        if self.anchor:
            return "anchor"
        return "signature"

    def is_build_specific(self) -> bool:
        """True if finding this site depends on a build-specific number.

        ``locate_rva`` and a byte ``anchor`` both encode the layout of one
        particular link; a semantic locator does not.  Used by the robustness
        tests and by ``analyze`` to keep the count visible.
        """
        return self.locate is None

    @property
    def target_rva(self) -> int | None:
        """The RVA this patch is expected to land on, whatever finds it.

        ``known_rvas`` is recorded for every patch, so this is the
        resolver-independent way to talk about *where* a patch applies -- which
        is what callers (tests, ``rebase``, ``dbg``) actually mean.  Returns
        None only for a hand-built patch that recorded nothing.
        """
        if self.locate_rva is not None:
            return self.locate_rva
        return self.known_rvas[0] if self.known_rvas else None

    def anchor_bytes(self) -> bytes | None:
        return parse_hex_bytes(self.anchor) if self.anchor else None

    def replacement_bytes(self) -> bytes:
        return parse_hex_bytes(self.replace)

    def validate(self) -> None:
        """Catch patch definitions that cannot work, at load time.

        The important one: if the signature pins a byte that the patch
        overwrites, the signature stops matching the moment it is applied, so
        ``verify`` reports the patch as lost and re-running reports the
        signature as missing.  Every overwritten byte must therefore be a
        wildcard.  Checking per-byte rather than "does it have any wildcard"
        matters: a signature can contain a wildcard and still pin other bytes
        that the replacement changes.
        """
        sig = self.parsed_signature()
        repl = self.replacement_bytes()
        if len(sig.tokens) != len(repl):
            raise PatchError(
                f"{self.id}: replacement is {len(repl)} bytes but signature is "
                f"{len(sig.tokens)} bytes; use a same-length patch"
            )
        pinned = [i for i, t in enumerate(sig.tokens) if t is not None and t != repl[i]]
        if pinned:
            raise PatchError(
                f"{self.id}: signature pins byte(s) at offset(s) "
                f"{', '.join(str(i) for i in pinned)} that the replacement "
                f"overwrites, so the patch would be undetectable after "
                f"applying. Replace those bytes with '??' in the signature."
            )


def parse_hex_bytes(text: str) -> bytes:
    cleaned = text.replace(" ", "").replace("\n", "").strip()
    if len(cleaned) % 2:
        raise PatchError(f"odd-length hex byte string: {text!r}")
    try:
        return bytes.fromhex(cleaned)
    except ValueError as exc:
        raise PatchError(f"invalid hex bytes {text!r}: {exc}") from exc


@dataclass
class Profile:
    name: str
    description: str
    patches: list[Patch]
    # Names of other profiles that must be applied alongside this one.  This
    # exists because of a real trap: patching MuMuNxMain.exe strips its
    # Authenticode blob, which arms a self-integrity check that burns CPU
    # forever.  `no-integrity-punish` defuses it, and "remember to also pass
    # -p no-integrity-punish" is not a mechanism.  Declaring the dependency in
    # data is.
    requires: list[str] = field(default_factory=list)
    # Fingerprint of the vendor build this profile was authored against, keyed
    # by the profile-relative target path.  A mapping rather than a single
    # string because one profile may in principle patch several files, and a
    # single field would then be ambiguous about which file it described.  See
    # pe.buildid: it is a diagnostic, never an enforcement, so a mismatch warns
    # and does not block a write.
    build: dict[str, str] = field(default_factory=dict)

    @property
    def files(self) -> list[str]:
        seen: list[str] = []
        for p in self.patches:
            if p.file not in seen:
                seen.append(p.file)
        return seen


def load_profiles(directory: Path | None = None) -> dict[str, Profile]:
    directory = Path(directory) if directory else PATCH_DIR
    profiles: dict[str, Profile] = {}
    if not directory.is_dir():
        return profiles
    for path in sorted(directory.glob("*.toml")):
        with open(path, "rb") as fh:
            doc = tomllib.load(fh)
        meta = doc.get("profile", {})
        name = meta.get("name", path.stem)
        patches = []
        for raw in doc.get("patch", []):
            try:
                patch = Patch(
                    id=raw["id"],
                    description=raw.get("description", ""),
                    file=raw["file"],
                    signature=raw["signature"],
                    replace=raw["replace"],
                    expect=raw.get("expect"),
                    anchor=raw.get("anchor"),
                    known_rvas=[int(x, 0) for x in raw.get("known_rvas", [])],
                    locate_rva=(
                        int(raw["locate_rva"], 0) if raw.get("locate_rva") is not None else None
                    ),
                    locate=(
                        locate_mod.parse_locator(raw["locate"])
                        if raw.get("locate") is not None
                        else None
                    ),
                    disable_pe_checksum_fix=raw.get("disable_pe_checksum_fix", False),
                )
            except KeyError as exc:
                raise PatchError(f"{path.name}: patch missing key {exc}") from exc
            patch.validate()
            patches.append(patch)
        profiles[name] = Profile(
            name=name,
            description=meta.get("description", ""),
            patches=patches,
            requires=[str(x) for x in meta.get("requires", [])],
            build=_parse_build(meta.get("build"), patches),
        )

    _check_requires(profiles)
    return profiles


def _parse_build(raw, patches: list[Patch]) -> dict[str, str]:
    """Normalise the profile's ``build`` field into a file -> fingerprint map.

    Two spellings are accepted, because one profile patching one file is the
    common case and deserves the short form:

        build = "8b142aee08fad65f"                 # every file in the profile
        build = { "nx_main/MuMuNxMain.exe" = "..." }   # per file
    """
    if raw is None:
        return {}
    if isinstance(raw, str):
        seen: list[str] = []
        for p in patches:
            if p.file not in seen:
                seen.append(p.file)
        return {f: raw for f in seen}
    if isinstance(raw, dict):
        return {str(k): str(v) for k, v in raw.items()}
    raise PatchError(f"profile build must be a string or a table, not {type(raw).__name__}")


def _check_requires(profiles: dict[str, Profile]) -> None:
    """Fail at load time if a profile depends on one that does not exist.

    Load time is the right place: the alternative is discovering it halfway
    through a multi-profile run, after files have already been written.
    """
    for prof in profiles.values():
        missing = [r for r in prof.requires if r not in profiles]
        if missing:
            raise PatchError(
                f"{prof.name}: requires profile(s) that do not exist: {', '.join(sorted(missing))}"
            )
        if prof.name in prof.requires:
            raise PatchError(f"{prof.name}: profile requires itself")


def resolve_requirements(profiles: dict[str, Profile], names: list[str]) -> list[str]:
    """Expand ``names`` with every profile they require, dependencies first.

    Order matters: the integrity-check patch has to be in place before (or at
    the same time as) the patch that arms it.  Since both are applied to the
    same file in one pass, the ordering here is about reporting and about
    keeping the ``--only`` interaction honest, but it is still the order a human
    would want to read.

    Unknown names are returned untouched so the caller can report them; a cycle
    raises rather than looping forever.
    """
    out: list[str] = []
    seen: set[str] = set()
    visiting: set[str] = set()

    def visit(name: str) -> None:
        if name in seen:
            return
        if name not in profiles:
            # Passed through rather than dropped: the caller reports it.  A
            # silently-discarded name is how a typo in --profile turns into a
            # run that quietly does less than it was asked to.
            seen.add(name)
            out.append(name)
            return
        if name in visiting:
            raise PatchError(f"profile requirement cycle at {name!r}")
        visiting.add(name)
        for dep in profiles[name].requires:
            visit(dep)
        visiting.discard(name)
        seen.add(name)
        out.append(name)

    for name in names:
        visit(name)
    return out


@dataclass
class FilePlan:
    """What would happen to one file."""

    file: str
    patches: list[Patch]
    strip_signature: bool


@dataclass
class PatchResult:
    patch_id: str
    file: str
    rva: int
    offset: int
    status: str  # applied | already-applied | skipped
    detail: str = ""


def plan(profile: Profile, install_dir: Path, names: list[str] | None = None) -> list[FilePlan]:
    """Group a profile's patches by file, in declaration order."""
    install_dir = Path(install_dir)
    wanted = [p for p in profile.patches if names is None or p.id in names]
    unknown = set(names or []) - {p.id for p in profile.patches}
    if unknown:
        raise PatchError(f"unknown patch id(s): {', '.join(sorted(unknown))}")
    grouped: dict[str, list[Patch]] = {}
    for p in wanted:
        grouped.setdefault(p.file, []).append(p)
    return [FilePlan(file=f, patches=ps, strip_signature=True) for f, ps in grouped.items()]


def plan_profiles(
    profiles: list[Profile],
    install_dir: Path,
    names: list[str] | None = None,
) -> list[FilePlan]:
    """Merge several profiles into one file-grouped plan.

    ``profiles`` is in application order -- dependencies first, as returned by
    :func:`resolve_requirements`.  The **last** entry is the one the user asked
    for, and it is the only one ``names`` (``--only``) filters: a required
    profile is a precondition, so silently dropping part of it because of a
    filter meant for another profile is exactly the failure ``requires`` exists
    to prevent.

    Patches that target the same file are concatenated in profile order, which
    keeps the integrity-check patch ahead of the patch that arms it.
    """
    install_dir = Path(install_dir)
    if not profiles:
        return []

    requested = profiles[-1]
    unknown = set(names or []) - {p.id for p in requested.patches}
    if unknown:
        raise PatchError(f"unknown patch id(s): {', '.join(sorted(unknown))}")

    grouped: dict[str, list[Patch]] = {}
    order: list[str] = []
    for index, prof in enumerate(profiles):
        is_requested = index == len(profiles) - 1
        for p in prof.patches:
            if is_requested and names is not None and p.id not in names:
                continue
            if p.file not in grouped:
                grouped[p.file] = []
                order.append(p.file)
            # Guard against the same patch id arriving from two profiles; that
            # would mean applying it twice and reporting nonsense.
            if any(existing.id == p.id for existing in grouped[p.file]):
                raise PatchError(f"patch {p.id!r} is declared by more than one profile in this run")
            grouped[p.file].append(p)

    return [FilePlan(file=f, patches=grouped[f], strip_signature=True) for f in order]


def locate(data: bytes, patch: Patch) -> sigscan.Match:
    """Find a patch's site. Public entry point; honours ``anchor``.

    Prefer this over :func:`sigscan.scan_unique` directly -- a patch whose
    signature is deliberately wildcarded will look ambiguous to a bare scan.
    """
    return _locate(data, patch)


def _locate(data: bytes, patch: Patch) -> sigscan.Match:
    """Find a patch's site.

    Four strategies, in order of preference.  The ordering is the whole point of
    this module: the first two survive a vendor rebuild, the last two do not.

    1. **Semantic locator** (``locate``).  Finds the site from a string literal
       or an import name, both of which are rebuilt identically.  The signature
       then *verifies* the site rather than having to *find* it.  See
       :mod:`pe.locate` for why that division of labour matters.
    2. **Unique signature**, when the pattern is already unambiguous.
    3. **Literal anchor** (``anchor``), for wildcarded signatures that need
       surrounding bytes to disambiguate.
    4. **RVA anchor** (``locate_rva``).  An absolute address: unambiguous, and
       invalidated by any rebuild.  Retained only for sites with no stable
       semantic handle -- currently the self-integrity check, whose predicate
       calls ``WinVerifyTrust`` through a dynamically resolved pointer, so there
       is no import name to anchor on.
    """
    sig = patch.parsed_signature()

    if patch.locate is not None:
        res = locate_mod.resolve(data, patch.locate, sig)
        return sigscan.Match(rva=res.rva, offset=res.offset)

    if patch.locate_rva is not None:
        match = _match_at_rva(data, patch.locate_rva, sig)
        if match is None:
            raise sigscan.SignatureError(
                f"{patch.id}: bytes at recorded RVA {patch.locate_rva:#x} do not "
                f"match the signature, so this is a different build: "
                f"{sig.describe()}"
            )
        return match

    anchor = patch.anchor_bytes()
    if anchor is None:
        return sigscan.scan_unique(data, sig)

    hits = sigscan.scan(data, sig)
    kept = []
    for m in hits:
        start = m.offset - len(anchor)
        if start >= 0 and data[start : m.offset] == anchor:
            kept.append(m)
    if not kept:
        raise sigscan.SignatureError(
            f"signature matched {len(hits)} place(s) but none was preceded by "
            f"anchor {anchor.hex(' ').upper()}: {sig.describe()}"
        )
    if len(kept) > 1:
        where = ", ".join(f"RVA {m.rva:#x}" for m in kept[:8])
        raise sigscan.SignatureError(
            f"anchor left {len(kept)} candidates ({where}): {sig.describe()}"
        )
    return kept[0]


def _match_at_rva(data: bytes, rva: int, sig: sigscan.Signature) -> sigscan.Match | None:
    """Return a Match at ``rva`` if the bytes there satisfy ``sig``.

    Unlike a plain scan this does not search: it checks one address, which is
    what makes it usable when several sites are byte-identical.
    """
    offset = pe.rva_to_offset(pe.parse(data), rva)
    if offset is None or offset + sig.length > len(data):
        return None
    for k, token in enumerate(sig.tokens):
        if token is None:
            continue
        if data[offset + k] != token:
            return None
    return sigscan.Match(rva=rva, offset=offset)


def apply_patch_to_bytes(data: bytes, patch: Patch) -> tuple[bytes, PatchResult]:
    """Apply one patch to an in-memory image.

    Returns the new bytes and a result.  Applying an already-applied patch is
    not an error -- it reports ``already-applied`` so re-runs stay idempotent.
    """
    sig = patch.parsed_signature()
    repl = patch.replacement_bytes()
    if len(repl) != sig.length:
        raise PatchError(
            f"{patch.id}: replacement is {len(repl)} bytes but signature is "
            f"{sig.length} bytes; use a same-length patch"
        )

    info = pe.parse(data)
    match = _locate(data, patch)

    original = data[match.offset : match.offset + sig.length]

    if patch.expect is not None:
        want = parse_hex_bytes(patch.expect)
        if len(want) != sig.length:
            raise PatchError(
                f"{patch.id}: expect is {len(want)} bytes but signature is {sig.length} bytes"
            )
        if original != want and original != repl:
            raise PatchError(
                f"{patch.id}: bytes at RVA {match.rva:#x} are "
                f"{original.hex(' ')} but expected {want.hex(' ')}"
            )

    if original == repl:
        return data, PatchResult(patch.id, patch.file, match.rva, match.offset, "already-applied")

    if patch.known_rvas and match.rva not in patch.known_rvas:
        # Not fatal: signatures are allowed to move between builds, but a
        # mismatch is worth reporting so a human can re-verify in x64dbg.
        note = f"matched RVA {match.rva:#x}, recorded {[hex(r) for r in patch.known_rvas]}"
    else:
        note = ""

    buf = bytearray(data)
    buf[match.offset : match.offset + sig.length] = repl
    out = bytes(buf)

    if not patch.disable_pe_checksum_fix:
        checksum = pe.pe_checksum(out, info.checksum_offset)
        buf = bytearray(out)
        import struct

        struct.pack_into("<I", buf, info.checksum_offset, checksum)
        out = bytes(buf)

    return out, PatchResult(patch.id, patch.file, match.rva, match.offset, "applied", note)


def verify_patch(data: bytes, patch: Patch) -> bool:
    """True if the patch's replacement bytes are already present."""
    try:
        m = _locate(data, patch)
    except sigscan.SignatureError:
        return False
    return data[m.offset : m.offset + patch.parsed_signature().length] == patch.replacement_bytes()
