"""Tests for the Qt resource (rcc) reader.

The tree layout asserted here is not guesswork -- it was validated by
extracting the launcher's ``zh_hans`` translation and confirming every menu
label is present in it. These tests lock in the two details that were wrong on
the first attempt: the 22-byte node stride for version >= 2, and the
``<u16 len><u32 hash><utf16be>`` name record.
"""

from __future__ import annotations

import struct

import pytest

from rcc import rcc

REAL_RCC = "/mnt/c/Program Files/Netease/MuMu/nx_main/rcc/NxMainResource.rcc"


def _build_rcc(files: dict[str, bytes]) -> bytes:
    """Build a minimal single-directory rcc container.

    Only enough of the format to exercise the reader: one root node, one
    directory node, and one file node per entry. Layout matches Qt's
    qresource.cpp so the reader's assumptions are the thing under test.
    """
    node_size = 22
    names = bytearray()
    name_offsets: dict[str, int] = {}

    def add_name(text: str) -> int:
        if text in name_offsets:
            return name_offsets[text]
        off = len(names)
        encoded = text.encode("utf-16be")
        names.extend(struct.pack(">H", len(text)))
        names.extend(struct.pack(">I", 0))  # hash, unused by the reader
        names.extend(encoded)
        name_offsets[text] = off
        return off

    root_name = add_name("")
    dir_name = add_name("resources")
    file_names = {p: add_name(p.rsplit("/", 1)[-1]) for p in files}

    # Payloads are concatenated after the tree.
    n_nodes = 2 + len(files)
    payloads = bytearray()
    payload_offsets: dict[str, int] = {}
    for path, data in files.items():
        payload_offsets[path] = len(payloads)
        payloads.extend(data)

    tree = bytearray()

    def add_node(name_off: int, flags: int, children: int, child_off: int) -> None:
        # A tree record is 14 bytes of fields followed by 8 bytes of padding,
        # which is what makes the stride 22 for version >= 2. Omitting the
        # padding silently corrupts every node after the first.
        tree.extend(struct.pack(">IHII", name_off, flags, children, child_off))
        tree.extend(b"\x00" * 8)

    # node 0: synthetic root, one child which is node 1
    add_node(root_name, rcc.FLAG_DIRECTORY, 1, 1)
    # node 1: "resources" directory, children are the file nodes
    add_node(dir_name, rcc.FLAG_DIRECTORY, len(files), 2)
    # file nodes
    for path in files:
        add_node(file_names[path], 0, 0, payload_offsets[path])

    assert len(tree) == n_nodes * node_size, "tree size must match the stride"

    header_size = 20  # 'qres' (4) + version (4) + tree/data/names offsets (12)
    tree_off = header_size
    data_off = tree_off + len(tree)
    names_off = data_off + len(payloads)
    header = b"qres" + struct.pack(">I", 3)
    header += struct.pack(">III", tree_off, data_off, names_off)
    assert len(header) == header_size
    return header + bytes(tree) + bytes(payloads) + bytes(names)


def test_rejects_non_rcc():
    with pytest.raises(rcc.RccError, match="qres"):
        rcc.Rcc(b"not an rcc file")


def test_walk_finds_files():
    container = rcc.Rcc(_build_rcc({"a.qm": b"AAA", "b.svg": b"BBB"}))
    paths = sorted(r.path for r in container.walk())
    assert paths == ["resources/a.qm", "resources/b.svg"]


def test_find_by_suffix():
    container = rcc.Rcc(_build_rcc({"x.qm": b"1", "y.svg": b"2", "z.QM": b"3"}))
    assert len(container.find(".qm")) == 2  # case-insensitive
    assert len(container.find(".svg")) == 1


def test_payload_returns_bytes():
    container = rcc.Rcc(_build_rcc({"a.qm": b"HELLO"}))
    res = container.find(".qm")[0]
    assert res.compression == "none"
    assert container.payload(res).startswith(b"HELLO")


def test_directory_nodes_are_not_emitted_as_files():
    container = rcc.Rcc(_build_rcc({"a.qm": b"x"}))
    for r in container.walk():
        assert not r.is_directory
        assert not r.path.endswith("resources")


def test_find_strings_reports_every_occurrence():
    blob = "兑换中心".encode("utf-16be") + b"\x00" * 4 + "兑换中心".encode("utf-16be")
    hits = rcc.find_strings(blob, ["兑换中心"])["兑换中心"]
    assert len(hits) == 2
    assert hits[0].offset == 0
    assert hits[1].offset > 0


def test_find_strings_absent_returns_empty():
    assert rcc.find_strings(b"nothing here", ["兑换中心"])["兑换中心"] == []


def test_find_strings_matches_utf8_too():
    blob = "设置中心".encode()
    assert len(rcc.find_strings(blob, ["设置中心"])["设置中心"]) == 1


@pytest.mark.skipif(
    not __import__("pathlib").Path(REAL_RCC).is_file(),
    reason="real MuMu rcc not available",
)
def test_real_rcc_version_and_stride():
    container = rcc.load_rcc(REAL_RCC)
    assert container.version == 3
    # version >= 2 -> 22-byte nodes; getting this wrong makes the walk run off
    assert container.node_size == 22


@pytest.mark.skipif(
    not __import__("pathlib").Path(REAL_RCC).is_file(),
    reason="real MuMu rcc not available",
)
def test_real_rcc_finds_translations():
    container = rcc.load_rcc(REAL_RCC)
    qms = container.find(".qm")
    assert len(qms) >= 10
    assert any("zh_hans" in r.path for r in qms)
    # Compression is per-resource, not per-container.
    kinds = {r.compression for r in qms}
    assert "none" in kinds, "expected some uncompressed translations"


@pytest.mark.skipif(
    not __import__("pathlib").Path(REAL_RCC).is_file(),
    reason="real MuMu rcc not available",
)
def test_real_rcc_contains_the_menu_labels():
    """The finding this whole module exists for."""
    container = rcc.load_rcc(REAL_RCC)
    res = next(r for r in container.find(".qm") if "zh_hans" in r.path)
    blob = container.payload(res)

    labels = [
        "关于 MuMu",
        "设置中心",
        "消息中心",
        "下载掌上MuMu",
        "常见问题",
        "兑换中心",
    ]
    hits = rcc.find_strings(blob, labels)
    for label in labels:
        assert hits[label], f"{label!r} not found in the zh_hans translation"


@pytest.mark.skipif(
    not __import__("pathlib").Path(REAL_RCC).is_file(),
    reason="real MuMu rcc not available",
)
def test_real_rcc_zlib_payload_decodes():
    container = rcc.load_rcc(REAL_RCC)
    zlibs = [r for r in container.find(".qm") if r.compression == "zlib"]
    if not zlibs:
        pytest.skip("no zlib-compressed translations in this build")
    blob = container.payload(zlibs[0])
    assert len(blob) > 1000
    # A decoded .qm payload should not look like compressed noise.
    assert blob[4:10] == bytes.fromhex("3CB86418CAEF") or b"\x00" in blob[:64]
