"""Documentation structure and link integrity.

The docs are split across ``README.md`` and a ``doc/`` tree, with each file
linked from an index.  Nothing enforces that by default -- a split like this rots
by *moving a file and leaving a link behind*, which no other test would notice,
and which is invisible until a reader clicks it.

So the two things that can silently break are asserted here:

* every relative markdown link resolves to a file that exists;
* every markdown file under ``doc/`` is reachable from an index, so a new
  document cannot be added and then forgotten.

Links to external URLs and to in-page anchors (``#...``) are out of scope: the
former need the network, and the latter are checked by the heading they name
only in spirit.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
README = REPO_ROOT / "README.md"
DOC = REPO_ROOT / "doc"


#: Every markdown file in the repository whose relative links are checked.  The
#: suite's own docs are not the only ones that can rot: ``patches/README.md``
#: describes the Lawnchair build and links into ``doc/``.
def _checked_files() -> list[Path]:
    return [README, *(REPO_ROOT / "patches").glob("*.md"), *_markdown_files()]


#: ``[text](target)`` where target is not a URL and not a bare anchor.
_LINK = re.compile(r"\[[^\]]*\]\(([^)]+)\)")


def _markdown_files() -> list[Path]:
    return sorted(DOC.rglob("*.md"))


def _local_links(path: Path) -> list[str]:
    """Relative link targets in ``path``, with any fragment stripped."""
    targets = []
    for raw in _LINK.findall(path.read_text(encoding="utf-8")):
        target = raw.split("#", 1)[0].strip()
        if not target or "://" in target or target.startswith(("mailto:", "#")):
            continue
        targets.append(target)
    return targets


def test_the_old_single_file_layout_is_gone():
    """The docs are split now; ``docs/`` must not come back alongside ``doc/``."""
    assert not (REPO_ROOT / "docs").exists(), (
        "docs/ exists again -- the analysis was split into doc/analysis/, and two "
        "trees would let the two copies drift apart"
    )
    assert DOC.is_dir()


def test_every_markdown_file_under_doc_is_reachable_from_an_index():
    """A document that no index links to is a document nobody will find."""
    indexes = [README, DOC / "README.md", DOC / "analysis" / "README.md"]
    linked: set[Path] = set()
    for index in indexes:
        for target in _local_links(index):
            resolved = (index.parent / target).resolve()
            if resolved.suffix == ".md":
                linked.add(resolved)
            elif resolved.is_dir():
                # A directory link covers everything beneath it.
                linked.update(p.resolve() for p in resolved.rglob("*.md"))

    orphans = [p for p in _markdown_files() if p.resolve() not in linked]
    assert not orphans, "these documents are not linked from any index:\n  " + "\n  ".join(
        str(p.relative_to(REPO_ROOT)) for p in orphans
    )


@pytest.mark.parametrize(
    "path",
    _checked_files(),
    ids=lambda p: str(Path(p).relative_to(REPO_ROOT)),
)
def test_every_relative_markdown_link_resolves(path: Path):
    """A moved file must not leave a dangling link behind."""
    missing = []
    for target in _local_links(path):
        resolved = (Path(path).parent / target).resolve()
        if not resolved.exists():
            missing.append(target)
    assert not missing, (
        f"{Path(path).relative_to(REPO_ROOT)} links to targets that do not exist: "
        + ", ".join(missing)
    )


@pytest.mark.parametrize("path", _markdown_files(), ids=lambda p: p.name)
def test_each_document_has_exactly_one_title(path: Path):
    """One H1 per file, and it comes first.

    Section-number headings were stripped when the single long analysis was
    split, so the title is the only structural marker a reader can rely on.
    """
    lines = path.read_text(encoding="utf-8").splitlines()
    in_fence = False
    h1 = []
    for line in lines:
        if line.lstrip().startswith("```"):
            in_fence = not in_fence
            continue
        if not in_fence and line.startswith("# "):
            h1.append(line)
    assert len(h1) == 1, f"{path.name} has {len(h1)} level-1 headings; expected exactly one title"
    assert lines[0].startswith("# "), f"{path.name} must open with its title, not {lines[0]!r}"
