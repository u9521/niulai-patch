"""Qt translation (``.qm``) inspection.

The MuMu launcher keeps its UI strings in ``nemu-nx-main_zh_hans.qm``, which is
stored *uncompressed* inside ``nx_main/rcc/NxMainResource.rcc``. That is why the
Chinese menu labels appear in no executable and in no plain-text file.

This module deliberately does **not** attempt to fully parse the ``.qm`` binary
format -- the section layout is fiddly and a half-correct parser is worse than
none. Instead it does two things that are easy to trust:

* :func:`find_rcc_resource` walks an rcc container correctly (22-byte tree
  nodes for version >= 2, ``<u16 len><u32 hash><utf16be>`` name records) and
  returns a resource's raw payload;
* :func:`find_strings` locates translations by direct byte search, reporting
  every occurrence with its offset and surrounding context.

Byte search on UTF-16BE is exactly how the menu labels were confirmed, and it
cannot be wrong about whether a string is present.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from pathlib import Path

# Qt resource tree nodes are 14 bytes, plus 8 more for version >= 2.
_NODE_SIZE_V1 = 14
_NODE_SIZE_V2 = 22

FLAG_COMPRESSED = 0x01
FLAG_DIRECTORY = 0x02
FLAG_COMPRESSED_ZSTD = 0x04

QM_MAGIC = bytes.fromhex("3CB86418CAEF")


class RccError(Exception):
    """Raised when an rcc container cannot be parsed."""


@dataclass(frozen=True)
class Resource:
    path: str
    offset: int
    size: int
    flags: int

    @property
    def compression(self) -> str:
        if self.flags & FLAG_COMPRESSED_ZSTD:
            return "zstd"
        if self.flags & FLAG_COMPRESSED:
            return "zlib"
        return "none"

    @property
    def is_directory(self) -> bool:
        return bool(self.flags & FLAG_DIRECTORY)


class Rcc:
    """Reader for Qt's binary resource container."""

    def __init__(self, data: bytes) -> None:
        if data[:4] != b"qres":
            raise RccError("not an rcc file: missing 'qres' magic")
        self.data = data
        self.version = struct.unpack_from(">I", data, 4)[0]
        self.tree, self.payloads, self.names = struct.unpack_from(">III", data, 8)
        self.node_size = _NODE_SIZE_V2 if self.version >= 2 else _NODE_SIZE_V1

    def _node(self, index: int) -> tuple[int, int, int, int]:
        off = self.tree + index * self.node_size
        if off + 14 > len(self.data):
            raise RccError(f"tree node {index} is out of range")
        return struct.unpack_from(">IHII", self.data, off)

    def _name(self, name_offset: int) -> str:
        # Name record: u16 length, u32 hash, then the UTF-16BE characters.
        base = self.names + name_offset
        if base < 0 or base + 6 > len(self.data):
            raise RccError(f"name offset {name_offset} is out of range")
        length = struct.unpack_from(">H", self.data, base)[0]
        start = base + 6
        if start + length * 2 > len(self.data):
            raise RccError(
                f"name at offset {name_offset} claims {length} chars, "
                f"which runs past the end of the file"
            )
        return self.data[start : start + length * 2].decode("utf-16be")

    def walk(self, max_depth: int = 16) -> list[Resource]:
        """Return every file (non-directory) resource in the container.

        Note the root node is a synthetic container: its single child is the
        ``resources`` directory, and the root itself contributes no path
        segment. Starting the path from the root's name would prefix every
        result with an extra ``resources/``.
        """
        out: list[Resource] = []
        seen: set[int] = set()

        def visit(index: int, path: list[str], depth: int) -> None:
            if index in seen or depth > max_depth:
                return
            seen.add(index)
            name_off, flags, children, child_off = self._node(index)

            if flags & FLAG_DIRECTORY:
                # The root's name is empty/synthetic, so entering it must not
                # add a segment.
                child_path = path
                if index != 0:
                    child_path = [*path, self._name(name_off)]
                for k in range(children):
                    visit(child_off + k, child_path, depth + 1)
            else:
                name = self._name(name_off)
                out.append(Resource("/".join([*path, name]), child_off, 0, flags))

        # Skip the synthetic root: descend into its children directly.
        _, _, root_children, root_child_off = self._node(0)
        for k in range(root_children):
            visit(root_child_off + k, [], 1)
        return out

    def find(self, suffix: str) -> list[Resource]:
        """Resources whose path ends with ``suffix`` (case-insensitive)."""
        suffix = suffix.lower()
        return [r for r in self.walk() if r.path.lower().endswith(suffix)]

    def payload(self, res: Resource) -> bytes:
        """Raw bytes for a resource, decompressing zlib payloads.

        Compression is per-resource, not per-container: in NxMainResource.rcc
        the ``zh_hans``/``ja``/``ko`` translations are stored raw while the
        others are deflated, presumably whichever came out smaller.

        A compressed payload is preceded by an 8-byte big-endian header::

            <u32 compressed_size><u32 uncompressed_size><zlib stream>

        Both fields were read off real payloads to check the interpretation --
        ``uncompressed_size`` matches the inflated length exactly (137605 for
        ``nemu-nx-main_de.qm``), and ``compressed_size`` matches the deflate
        stream length.

        zstd payloads are refused rather than guessed at: a zstd frame carries
        its own size, and truncating one wrongly yields corrupt data silently.
        """
        start = self.payloads + res.offset
        if res.compression == "none":
            return self.data[start:]
        if res.compression == "zlib":
            import zlib

            blob = self.data[start:]
            # Skip the 8-byte size header when it is present and consistent.
            if len(blob) > 8:
                # Only the uncompressed size is used; the compressed one
                # is implied by the rest of the blob.
                _comp, uncomp = struct.unpack_from(">II", blob, 0)
                if 0 < uncomp < 1 << 31 and blob[8:9] == b"\x78":
                    try:
                        out = zlib.decompress(blob[8:])
                    except zlib.error:
                        pass
                    else:
                        if len(out) == uncomp:
                            return out
            # Fall back to a bare stream, in case a build omits the header.
            try:
                return zlib.decompress(blob)
            except zlib.error:
                pass
            raise RccError(
                f"{res.path}: could not decompress zlib payload "
                f"(no recognised 8-byte header or bare zlib stream)"
            )
        raise RccError(
            f"{res.path}: payload uses {res.compression}, which this reader "
            f"does not decode; use the zstd library directly"
        )


@dataclass(frozen=True)
class StringHit:
    text: str
    offset: int
    context: str


def find_strings(
    blob: bytes, needles: list[str], *, context: int = 48
) -> dict[str, list[StringHit]]:
    """Find each needle as UTF-16BE, then again as UTF-8.

    Returns every hit rather than only the first: a ``.qm`` stores one record
    per (context, source) pair, so a label legitimately appears several times
    and hiding the duplicates would misrepresent the file.
    """
    results: dict[str, list[StringHit]] = {}
    for needle in needles:
        hits: list[StringHit] = []
        for enc in ("utf-16be", "utf-8"):
            encoded = needle.encode(enc)
            start = 0
            while True:
                i = blob.find(encoded, start)
                if i < 0:
                    break
                start = i + 1
                lo = max(0, i - context)
                hi = min(len(blob), i + len(encoded) + context)
                window = blob[lo:hi]
                try:
                    text = window.decode("utf-16be", errors="replace")
                except Exception:  # pragma: no cover - decode is total
                    text = ""
                hits.append(
                    StringHit(
                        text=needle,
                        offset=i,
                        context=text.replace("\x00", "."),
                    )
                )
        results[needle] = hits
    return results


def load_rcc(path: str | Path) -> Rcc:
    p = Path(path)
    return Rcc(p.read_bytes())
