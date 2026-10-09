"""Opening the guest's boot filesystem, and the edits that happen inside it.

This is the layer the rest of the project talks to.  It exists so that
:mod:`boot`, :mod:`lawnchair` and the CLI never open a container, never do
offset arithmetic, and never name a partition by a number they typed themselves.

Why the partition numbers are not constants
-------------------------------------------
This project used to identify its two working partitions with hard-coded sector
numbers -- ``BOOT_PARTITION_LBA = 34304`` and ``SYSTEM_PARTITION_LBA = 79068``
-- and it can also *move* partitions, because growing the boot partition pushes
the extended container (and therefore the 1.6 GiB system partition) later on the
disk.  A constant that is right until the first resize and silently wrong after
it is worse than no constant at all: the failure it produces is a write to the
wrong place, which is exactly what this whole layer is arranged to prevent.

So both are looked up from the MBR and confirmed by reading:

* :meth:`~disk.partition.PartitionTable.boot` is the ext partition holding
  ``/kernel`` -- the property GRUB's ``(hd0,2)/kernel`` actually needs;
* :meth:`~disk.partition.PartitionTable.system` is the largest ext4 partition,
  which the caller then confirms by hashing the installed launcher.

The second is a heuristic and the first is a fact, and the difference is
deliberate: the launcher's SHA-256 is the real guard on the system partition,
so a wrong answer there produces a clean refusal rather than a wrong write.

Writable views
--------------
:func:`open_boot_fs` is a context manager that hands back
``(partition, filesystem)``.  The partition is returned alongside the filesystem
because the caller usually needs both -- the filesystem to find things, the
partition to report its geometry or to extract it -- and because re-resolving it
would read the table twice.

The system partition has its own view with a shape that fits it better
(:class:`lawnchair.SystemImage`), because that edit is a single named file
rather than a set of four.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from disk import extfs, image
from disk.partition import Partition


class FilesystemError(Exception):
    """Raised when the expected filesystem cannot be found or opened."""


@contextmanager
def open_boot_fs(
    image_path: Path, *, writable: bool = False
) -> Iterator[tuple[Partition, extfs.Ext2]]:
    """Open the boot filesystem: the ext partition holding ``/kernel``.

    Yields ``(partition, filesystem)``.  When ``writable`` is false the whole
    stack is opened read-only, so a caller that only wants to inspect cannot
    accidentally modify anything even if the code below it tries.
    """
    disk = image.open_image(image_path, writable=writable)
    try:
        table = disk.partitions()
        try:
            part = table.boot()
        except Exception as exc:
            raise FilesystemError(f"cannot identify the boot partition: {exc}") from exc
        try:
            fs = extfs.Ext2(part, writable=writable)
        except extfs.ExtError as exc:
            raise FilesystemError(
                f"{part.name} does not hold a readable ext filesystem: {exc}"
            ) from exc
        yield part, fs
    finally:
        disk.close()
