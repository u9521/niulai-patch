"""Re-resolving patch profiles against a different build.

The workflow this supports
--------------------------
A MuMu update replaces ``MuMuNxMain.exe``.  Most patches now find their own
sites (see :mod:`pe.locate`), but some will not: the vendor may have moved a
site beyond a locator's window, renamed the string it anchors on, or changed the
code enough that the signature no longer matches.

``rebase`` answers, per patch, "where is this site in the new binary?" and
offers to record the answer.  It is deliberately report-first: the default is to
print, and ``--write`` has to be asked for.

What it will and will not do
----------------------------
It rewrites exactly three things: ``locate_rva``, ``known_rvas`` and the
``window`` inside a ``locate`` table.  It never touches a signature, a
replacement, a comment or a line ordering -- a TOML round-trip through
``tomllib`` would discard every comment in these files, and those comments are
the most valuable thing in them.  The edit is line-oriented for that reason.

When it cannot place a patch it says so and leaves the file alone.  A patch that
cannot be placed is not a failure of the tool; it is the honest signal that the
vendor changed behaviour, which needs a human with a debugger.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from . import locate, patcher, sigscan


@dataclass
class RebaseOutcome:
    """What happened to one patch while rebasing."""

    patch_id: str
    profile: str
    status: str  # unchanged | moved | found | needs-manual | ambiguous
    old_rva: int | None = None
    new_rva: int | None = None
    detail: str = ""

    @property
    def ok(self) -> bool:
        return self.status in ("unchanged", "moved", "found")

    def describe(self) -> str:
        if self.status == "unchanged":
            return f"unchanged ({self.new_rva:#x})" if self.new_rva else "unchanged"
        if self.status in ("moved", "found"):
            if self.old_rva is None:
                return f"found at {self.new_rva:#x}"
            return f"moved {self.old_rva:#x} -> {self.new_rva:#x}"
        return f"{self.status}: {self.detail}"


def rebase_patch(data: bytes, patch: patcher.Patch) -> RebaseOutcome:
    """Try to place one patch in ``data``.

    Order of attempts, and why:

    1. **The declared locator.**  If the profile already has one and it still
       resolves, nothing needs to change.  This is the common case and it must
       stay cheap.
    2. **The signature, searched anywhere.**  If the locator broke but the code
       is still there, a plain scan finds it.  A *unique* scan only -- an
       ambiguous one is reported as such, never resolved by guessing.
    3. **The literal anchor**, if the patch carries one and its signature is
       ambiguous.  This mirrors what the engine itself would do.
    """
    sig = patch.parsed_signature()

    if patch.locate is not None:
        try:
            res = locate.resolve(data, patch.locate, sig)
        except locate.LocatorError as exc:
            # Fall through to the signature search below, but remember why.
            locator_error = str(exc)
        else:
            old = patch.target_rva
            if old is None:
                return RebaseOutcome(patch.id, "", "found", None, res.rva)
            status = "unchanged" if res.rva == old else "moved"
            return RebaseOutcome(patch.id, "", status, old, res.rva)
    else:
        locator_error = ""

    # Try the signature on its own.
    try:
        hits = sigscan.scan(data, sig)
    except sigscan.SignatureError as exc:  # pragma: no cover - defensive
        return RebaseOutcome(patch.id, "", "needs-manual", patch.target_rva, None, str(exc))

    if len(hits) == 1:
        # Same RVA means nothing moved, even though the route to it differs
        # (a signature scan rather than the declared locator).  Reporting that
        # as "moved 0x... -> 0x..." would be noise that hides the real moves.
        old = patch.target_rva
        status = "unchanged" if old == hits[0].rva else "found"
        return RebaseOutcome(patch.id, "", status, old, hits[0].rva)

    if len(hits) > 1:
        # The patch's own anchor may still disambiguate.
        anchor = patch.anchor_bytes()
        if anchor:
            kept = [
                m
                for m in hits
                if m.offset - len(anchor) >= 0 and data[m.offset - len(anchor) : m.offset] == anchor
            ]
            if len(kept) == 1:
                old = patch.target_rva
                status = "unchanged" if old == kept[0].rva else "found"
                return RebaseOutcome(patch.id, "", status, old, kept[0].rva)
            if len(kept) > 1:
                return RebaseOutcome(
                    patch.id,
                    "",
                    "ambiguous",
                    patch.target_rva,
                    None,
                    f"{len(kept)} sites match the signature and anchor: "
                    + ", ".join(f"{m.rva:#x}" for m in kept[:6]),
                )
        where = ", ".join(f"{m.rva:#x}" for m in hits[:6])
        return RebaseOutcome(
            patch.id,
            "",
            "ambiguous",
            patch.target_rva,
            None,
            f"{len(hits)} sites match the signature: {where}",
        )

    detail = locator_error or "the signature is not present in this binary"
    # Add the nearest string, which is usually enough for a human to recognise
    # which site was meant even when the patch could not be placed.
    if patch.target_rva is not None and locate.HAVE_CAPSTONE:
        try:
            near = locate.Index.for_data(data).nearest_string(patch.target_rva)
        except Exception:  # pragma: no cover - diagnostics only
            near = None
        if near:
            detail += f"; nearest string near the old site: {near!r}"
    return RebaseOutcome(patch.id, "", "needs-manual", patch.target_rva, None, detail)


@dataclass
class RebaseReport:
    """Outcomes for a whole profile set, plus the TOML edits they imply."""

    outcomes: list[RebaseOutcome] = field(default_factory=list)
    #: (toml path, [(old line, new line)]) -- only for patches that moved.
    edits: dict[Path, list[tuple[str, str]]] = field(default_factory=dict)

    @property
    def placed(self) -> list[RebaseOutcome]:
        return [o for o in self.outcomes if o.ok]

    @property
    def unplaced(self) -> list[RebaseOutcome]:
        return [o for o in self.outcomes if not o.ok]


def _toml_path_for(profile_name: str) -> Path:
    return patcher.PATCH_DIR / f"{profile_name}.toml"


def rebase(
    new_data: bytes,
    file: str,
    profiles: dict[str, patcher.Profile] | None = None,
) -> RebaseReport:
    """Re-resolve every patch that targets ``file`` against ``new_data``."""
    profiles = profiles or patcher.load_profiles()
    report = RebaseReport()

    for prof in profiles.values():
        if not any(p.file == file for p in prof.patches):
            continue
        path = _toml_path_for(prof.name)
        for patch in prof.patches:
            if patch.file != file:
                continue
            outcome = rebase_patch(new_data, patch)
            outcome.profile = prof.name
            report.outcomes.append(outcome)

            # "moved" and "found" both mean the recorded RVA is now wrong and
            # needs updating; only "unchanged" is genuinely a no-op.  Keying the
            # edit on "moved" alone silently skipped every patch whose locator
            # broke but whose signature still scanned -- which is most of them.
            if (
                outcome.status in ("moved", "found")
                and outcome.new_rva is not None
                and path.is_file()
            ):
                report.edits.setdefault(path, []).extend(_edits_for(patch, outcome.new_rva, path))

    return report


_LOCATE_RVA_RE = re.compile(r'^(?P<indent>\s*)locate_rva\s*=\s*"(?P<val>0x[0-9a-fA-F]+)"')
_KNOWN_RVAS_RE = re.compile(r"^(?P<indent>\s*)known_rvas\s*=\s*\[(?P<val>[^\]]*)\]")
_WINDOW_RE = re.compile(r"(?P<pre>window\s*=\s*)(?P<val>0x[0-9a-fA-F]+|\d+)")


def _edits_for(patch: patcher.Patch, new_rva: int, path: Path) -> list[tuple[str, str]]:
    """The literal line replacements that move ``patch`` to ``new_rva``.

    Located by scanning the file for the patch's own block: from its ``[[patch]]``
    header to the next one.  Working on the text this way is what keeps the
    comments and the surrounding layout intact -- a ``tomllib`` round-trip would
    discard every one of them.
    """
    text = path.read_text(encoding="utf-8")
    lines = text.splitlines(keepends=True)
    block = _block_for(lines, patch.id)
    if block is None:
        return []

    out: list[tuple[str, str]] = []
    for line in block:
        m = _LOCATE_RVA_RE.match(line)
        if m:
            new = f'{m.group("indent")}locate_rva = "{new_rva:#x}"\n'
            if new != line:
                out.append((line, new))
            continue
        m = _KNOWN_RVAS_RE.match(line)
        if m:
            new = f'{m.group("indent")}known_rvas = ["{new_rva:#x}"]\n'
            if new != line:
                out.append((line, new))
            continue
    return out


def _block_for(lines: list[str], patch_id: str) -> list[str] | None:
    """The lines of one ``[[patch]]`` block, or None if it is not present.

    The id must be an ``id = "..."`` assignment at the start of its own line, not
    a mention inside a comment -- otherwise a patch whose id appears in a
    neighbouring comment would be edited by mistake.
    """
    exact = re.compile(rf'^id\s*=\s*"{re.escape(patch_id)}"\s*$')
    start = None
    end = len(lines)
    for i, line in enumerate(lines):
        if line.strip() == "[[patch]]":
            if start is not None:
                end = i
                break
            for j in range(i + 1, min(i + 6, len(lines))):
                if exact.match(lines[j].strip()):
                    start = i
                    break
    if start is None:
        return None
    return lines[start:end]


def apply_edits(report: RebaseReport, *, dry_run: bool = False) -> list[Path]:
    """Write the report's edits back to the TOML files.

    Each replacement is applied only if the old line is still present exactly
    once, so a file edited by hand between the report and the write is refused
    rather than silently mangled.
    """
    written: list[Path] = []
    for path, edits in report.edits.items():
        if not edits:
            continue
        text = path.read_text(encoding="utf-8")
        for old, new in edits:
            if text.count(old) != 1:
                raise patcher.PatchError(
                    f"{path.name}: refusing to rewrite {old.strip()!r}; it "
                    f"appears {text.count(old)} times (expected 1)"
                )
            text = text.replace(old, new)
        if not dry_run:
            path.write_text(text, encoding="utf-8")
        written.append(path)
    return written


def refresh_build(profile: patcher.Profile, data: bytes) -> list[tuple[str, str]]:
    """Line edits that record ``data``'s fingerprint as the profile's build."""
    from . import buildid

    path = _toml_path_for(profile.name)
    if not path.is_file():
        return []
    fp = buildid.fingerprint(data)
    lines = path.read_text(encoding="utf-8").splitlines(keepends=True)
    for line in lines:
        if line.startswith("build = ") or line.startswith("build="):
            new = f'build = "{fp}"\n'
            return [] if new == line else [(line, new)]
    return []
