"""Reading and validating the guest kernel image (``bzImage``).

Where the kernel lives
----------------------
Not in a file on the host and not in a ``boot.img``: the kernel is a plain file
inside a 14 MiB ext2 partition (``sda3``) on the guest disk::

    /cmdline    94 bytes      kernel command line
    /kernel     12,362,752    bzImage
    /initrd     2,139,855     gzip cpio ramdisk
    /ramdisk    1,159         small gzip blob

GRUB stage2 lives in the MBR gap and reads them by partition *index*::

    rootnoverify (hd0,0)
    kernel --use-cmd-line (hd0,2)/kernel
    initrd (hd0,2)/initrd

``(hd0,2)`` is the third partition entry, i.e. ``sda3``.  That is why editing
the partition table is only safe while the table *order* is preserved.

This module only *parses* a kernel.  Reading the partition, planning a write and
performing one are :mod:`boot.image`, because the same machinery serves all four
files and duplicating it per file is how the four drift apart.

What is checked before any write
--------------------------------
* the replacement is a real ``bzImage`` (``HdrS`` at 0x202);
* the kernel release is reported, so a mismatched ABI is visible;
* the paired ramdisks are called out, because they are Android-x86's and are not
  interchangeable with a GKI set.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass


class KernelError(Exception):
    """Raised when a kernel image cannot be parsed."""


@dataclass(frozen=True)
class BzImage:
    """The parts of a bzImage header that matter for a replacement."""

    size: int
    setup_sectors: int
    boot_protocol: int
    release: str
    init_size: int

    @property
    def setup_bytes(self) -> int:
        return (self.setup_sectors + 1) * 512

    def describe(self) -> str:
        return f"{self.release} ({self.size:,} bytes)"

    @property
    def family(self) -> str:
        """The release without its localversion, for ABI comparisons.

        ``6.1.90-perf+`` and ``6.1.90`` share modules; ``6.1.90`` and ``6.6.1``
        do not.
        """
        return self.release.split("-")[0]


BZIMAGE_MAGIC = b"HdrS"
HDRS_OFFSET = 0x202
SETUP_SECTS_OFFSET = 0x1F1
BOOT_PROTOCOL_OFFSET = 0x206
VERSION_OFFSET = 0x20E
INIT_SIZE_OFFSET = 0x260

#: A kernel is at least a setup header plus a payload; anything smaller is a
#: truncated file, and reading fields out of it would be reading zeros.
MINIMUM_SIZE = 0x300


def parse_bzimage(data: bytes) -> BzImage:
    """Validate and describe a kernel image.

    A wrong file here means a device that does not boot, so the magic is
    checked rather than assumed from the filename.
    """
    if len(data) < MINIMUM_SIZE:
        raise KernelError(f"too small to be a kernel image ({len(data)} bytes)")
    if data[HDRS_OFFSET : HDRS_OFFSET + 4] != BZIMAGE_MAGIC:
        found = data[HDRS_OFFSET : HDRS_OFFSET + 4]
        raise KernelError(
            f"not a bzImage: expected {BZIMAGE_MAGIC!r} at offset {HDRS_OFFSET:#x}, found {found!r}"
        )
    setup_sectors = data[SETUP_SECTS_OFFSET]
    boot_protocol = struct.unpack_from("<H", data, BOOT_PROTOCOL_OFFSET)[0]
    init_size = struct.unpack_from("<I", data, INIT_SIZE_OFFSET)[0]

    # The release string's offset is relative to the start of the setup header.
    version_off = struct.unpack_from("<H", data, VERSION_OFFSET)[0]
    if version_off:
        start = 0x200 + version_off
        raw = data[start : start + 256].split(b"\x00")[0]
        release = raw.decode("latin-1", "replace")
    else:
        release = "(no version string)"

    return BzImage(
        size=len(data),
        setup_sectors=setup_sectors,
        boot_protocol=boot_protocol,
        release=release,
        init_size=init_size,
    )
