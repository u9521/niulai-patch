"""Tests for the in-place rcc payload replacer.

The container is 14 MB of interleaved offsets, so the property that matters is
that a replacement changes *only* the bytes it is supposed to and leaves the
container structurally identical.  Most of these tests are about that.
"""

from __future__ import annotations

import struct
import zlib

import pytest

from rcc import rcc, rccpatch

JPEG_SOI = b"\xff\xd8\xff"


def _tiny_jpeg(payload: bytes = b"") -> bytes:
    """A minimal but structurally valid JPEG envelope.

    The replacer only inspects the SOI and EOI markers, so the body can be
    arbitrary -- which keeps these tests from depending on Pillow.
    """
    return JPEG_SOI + payload + b"\xff\xd9"


def _build_rcc(resources: list[tuple[str, bytes]]) -> bytes:
    """Build a minimal qres container matching the real section order.

    The real ``NxDeviceResource.rcc`` lays its sections out as::

        header (24 bytes)  qres | version | tree | payloads | names | 1
        payloads           at 0x18, immediately after the header
        names              after the payloads
        tree                at the end

    Every resource is a direct child of the root and its name record holds the
    full path, so the reader resolves paths without needing directory nodes.
    Payloads are packed tightly in offset order, exactly as the real container
    does -- which is what makes a resource's size equal to the distance to the
    next one.
    """
    HEADER = 24
    # The reader strides nodes by 22 bytes (the 14-byte v1 record plus 8 bytes
    # of v2 fields) but unpacks only the first 14, so the tail must be zeroed
    # rather than packed at the wrong stride.
    node_size = 22
    node_rec = struct.calcsize(">IHII")  # 14

    names = bytearray()
    name_offsets: list[int] = []
    for path, _ in resources:
        name_offsets.append(len(names))
        names += struct.pack(">H", len(path)) + b"\x00\x00\x00\x00" + path.encode("utf-16-be")

    payloads = bytearray()
    offsets: list[int] = []
    for _, blob in resources:
        offsets.append(len(payloads))
        payloads += blob

    tree_size = node_size * (1 + len(resources))
    tree = bytearray(tree_size)
    struct.pack_into(">IHII", tree, 0, 0, 2, len(resources), 1)
    for i in range(len(resources)):
        struct.pack_into(
            ">IHII",
            tree,
            (1 + i) * node_size,
            name_offsets[i],
            0,
            0,
            offsets[i],
        )
    assert node_rec <= node_size

    payloads_base = HEADER
    names_base = payloads_base + len(payloads)
    tree_base = names_base + len(names)

    header = bytearray(HEADER)
    header[0:4] = b"qres"
    struct.pack_into(">I", header, 4, 3)
    struct.pack_into(">I", header, 8, tree_base)
    struct.pack_into(">I", header, 12, payloads_base)
    struct.pack_into(">I", header, 16, names_base)
    struct.pack_into(">I", header, 20, 1)
    return bytes(header) + bytes(payloads) + bytes(names) + bytes(tree)


def _img_blob(jpeg: bytes, capacity: int) -> bytes:
    """A payload of exactly ``capacity``: <u32 len><jpeg><zero padding>."""
    body = jpeg + b"\x00" * (capacity - 4 - len(jpeg))
    return struct.pack(">I", len(body)) + body


# --------------------------------------------------------------------------- #
# slot discovery
# --------------------------------------------------------------------------- #
def test_finds_only_startup_images():
    a = _img_blob(_tiny_jpeg(b"a" * 40), 128)
    b = _img_blob(_tiny_jpeg(b"b" * 40), 128)
    other = b"not a startup image" + b"\x00" * 100
    # The real container packs payloads tightly in offset order, so a slot runs
    # exactly to the next resource.  Put the non-image first so both images are
    # bounded correctly, mirroring that layout.
    data = _build_rcc(
        [
            ("resources/images/icon/other.png", other),
            ("resources/images/nx/device/jpeg/img_startup_landscape.jpeg", a),
            ("resources/images/nx/device/jpeg/img_startup_vertical.jpeg", b),
        ]
    )
    slots = rccpatch.find_startup_images(data)
    assert [s.path.split("/")[-1] for s in slots] == [
        "img_startup_landscape.jpeg",
        "img_startup_vertical.jpeg",
    ]
    assert all(s.capacity == 128 for s in slots)
    assert all(s.declared == 124 for s in slots)


def test_slot_search_is_sorted_by_offset():
    blobs = [
        ("resources/images/img_startup_z.jpeg", _img_blob(_tiny_jpeg(b"z"), 96)),
        ("resources/images/img_startup_a.jpeg", _img_blob(_tiny_jpeg(b"a"), 96)),
    ]
    slots = rccpatch.find_startup_images(_build_rcc(blobs))
    assert [s.payload_offset for s in slots] == sorted(s.payload_offset for s in slots)


def test_flags_are_refused():
    """A compressed payload cannot be replaced in place.

    The compressed flag is checked *before* the length model, so the fixture
    just needs the flag set -- the declared length is made consistent so the
    flags check is the one that fires.
    """
    body = struct.pack(">II", 8, 40) + zlib.compress(b"x" * 40)
    blob = struct.pack(">I", len(body)) + body
    tail = b"tail" + b"\x00" * 32
    data = _build_rcc(
        [
            ("resources/images/img_startup_x.jpeg", blob),
            ("resources/images/zz_tail.bin", tail),
        ]
    )
    raw = bytearray(data)
    tree = struct.unpack_from(">I", raw, 8)[0]
    # A node packs as >IHII = (name offset, flags, children, child offset), so
    # the flags field is a 2-byte value at offset 4 -- writing 4 bytes here
    # would spill into the child count.
    struct.pack_into(">H", raw, tree + 22 + 4, rcc.FLAG_COMPRESSED)
    with pytest.raises(rccpatch.RccPatchError, match="uncompressed"):
        rccpatch.find_startup_images(bytes(raw))


def test_declared_length_must_fill_the_slot():
    """A mismatch means our model of the layout is wrong; refuse."""
    # declares 10 but occupies 104, with a following resource to bound it
    bad = struct.pack(">I", 10) + b"x" * 100
    tail = b"tail" + b"\x00" * 60
    data = _build_rcc(
        [
            ("resources/images/img_startup_x.jpeg", bad),
            ("resources/images/zz_tail.bin", tail),
        ]
    )
    with pytest.raises(rccpatch.RccPatchError, match="slot"):
        rccpatch.find_startup_images(data)


# --------------------------------------------------------------------------- #
# replacement
# --------------------------------------------------------------------------- #
def test_replace_changes_only_the_payload():
    original = _img_blob(_tiny_jpeg(b"ORIGINAL" * 8), 256)
    data = _build_rcc(
        [
            ("resources/images/img_startup_x.jpeg", original),
            ("resources/images/keep.png", b"keep me" + b"\x00" * 64),
        ]
    )
    slot = rccpatch.find_startup_images(data)[0]
    new = _tiny_jpeg(b"NEW")
    out = rccpatch.replace_image(data, slot, new)

    assert len(out) == len(data), "the container length must not change"
    start = slot.payload_offset
    end = start + slot.capacity
    # everything outside the slot is untouched
    assert out[:start] == data[:start]
    assert out[end:] == data[end:]
    # and inside it, the new image is present and declared correctly
    declared = struct.unpack_from(">I", out, start)[0]
    assert declared == slot.capacity - 4
    assert out[start + 4 : start + 4 + len(new)] == new


def test_round_trip_is_byte_identical():
    """Re-inserting a slot's own bytes must be a no-op.

    This is the strongest single guarantee that the offset arithmetic and the
    padding rule are right.
    """
    blobs = [
        ("resources/images/img_startup_a.jpeg", _img_blob(_tiny_jpeg(b"A" * 50), 192)),
        ("resources/images/img_startup_b.jpeg", _img_blob(_tiny_jpeg(b"B" * 30), 160)),
    ]
    data = _build_rcc(blobs)
    out = data
    for slot in rccpatch.find_startup_images(data):
        jpeg = data[slot.payload_offset + 4 : slot.payload_offset + 4 + slot.declared]
        out = rccpatch.replace_image(out, slot, jpeg)
    assert out == data


def test_replacement_is_padded_to_fill_the_slot():
    data = _build_rcc(
        [
            ("resources/images/img_startup_x.jpeg", _img_blob(_tiny_jpeg(b"o" * 20), 200)),
        ]
    )
    slot = rccpatch.find_startup_images(data)[0]
    new = _tiny_jpeg(b"hi")
    out = rccpatch.replace_image(data, slot, new)

    body = out[slot.payload_offset + 4 : slot.payload_offset + slot.capacity]
    assert len(body) == slot.usable_jpeg_bytes
    assert body.startswith(new)
    assert body[len(new) :] == b"\x00" * (len(body) - len(new))


def test_oversized_replacement_is_refused():
    """Too-large images must raise, not be silently truncated."""
    data = _build_rcc(
        [
            ("resources/images/img_startup_x.jpeg", _img_blob(_tiny_jpeg(b"o"), 64)),
        ]
    )
    slot = rccpatch.find_startup_images(data)[0]
    huge = _tiny_jpeg(b"x" * 500)
    with pytest.raises(rccpatch.RccPatchError, match="only"):
        rccpatch.replace_image(data, slot, huge)


def test_exact_fit_is_allowed():
    data = _build_rcc(
        [
            ("resources/images/img_startup_x.jpeg", _img_blob(_tiny_jpeg(b"o"), 64)),
        ]
    )
    slot = rccpatch.find_startup_images(data)[0]
    # usable_jpeg_bytes is the *total* JPEG size that fits (capacity - 4 for
    # the length prefix), so build one exactly that long.
    body = slot.usable_jpeg_bytes - len(JPEG_SOI) - 2
    exact = _tiny_jpeg(b"y" * body)
    assert len(exact) == slot.usable_jpeg_bytes
    out = rccpatch.replace_image(data, slot, exact)
    assert out[slot.payload_offset + 4 : slot.payload_offset + 4 + len(exact)] == exact


# --------------------------------------------------------------------------- #
# validation
# --------------------------------------------------------------------------- #
def test_validate_accepts_a_complete_jpeg():
    rccpatch.validate_jpeg(_tiny_jpeg(b"payload"))


def test_validate_rejects_missing_soi():
    with pytest.raises(rccpatch.RccPatchError, match="SOI"):
        rccpatch.validate_jpeg(b"not a jpeg\xff\xd9")


def test_validate_rejects_missing_eoi():
    with pytest.raises(rccpatch.RccPatchError, match="EOI"):
        rccpatch.validate_jpeg(JPEG_SOI + b"truncated")


def test_validate_rejects_trailing_bytes():
    """Trailing data would shift the declared length and break the slot."""
    with pytest.raises(rccpatch.RccPatchError, match="trailing"):
        rccpatch.validate_jpeg(_tiny_jpeg(b"body") + b"junk")
