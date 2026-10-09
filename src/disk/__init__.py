"""Offline access to the guest's virtual disk and the filesystems on it.

Everything that reads or writes *inside* the emulator's disk image lives here,
kept apart from the code that patches Windows executables.  The separation
matters because the failure modes are different in kind: a wrong byte in a PE
patch produces a bad patch result, while a wrong byte inside ``/system``
produces a device that will not boot.

The stack, from the container down to the files.  Each layer knows only the one
below it, and each declares the *unit* it transfers in:

``device``
    The interfaces.  :class:`~disk.device.Device` is a byte range
    with declared batched writes; :class:`~disk.device.SectorDevice`
    adds sector primitives and derives byte access from them, so a subclass has
    only one path to get right.

``vdi``
    The VirtualBox container: a flat virtual address space backed by 1 MiB
    blocks through a block allocation table, plus a dirty-page cache so a
    batch of small writes costs one positioned write per block.  Knows nothing
    about partitions.

``partition``
    The MBR and its extended-partition chain, and each partition as a device in
    its own right.  Rebased reads and writes, and a refusal for anything
    outside the partition's own extent -- which is what the hand-rolled offset
    adapters this replaced did not have.  Knows nothing about filesystems
    beyond naming them.

``filetype``
    What a partition holds, by reading it.  The MBR's type byte cannot
    distinguish MuMu's boot partition from its system partition, both ``0x83``.

``extfs``
    ext2/ext3/ext4: superblock, group descriptors, inodes, extent trees,
    allocation.  Talks to any object with ``read_at``/``write_at``, which is
    what makes it testable against a plain file.

``images``
    *Which* image on the host to open.  MuMu keeps one ``vms/<product>``
    directory per product, so this turns "the installation" into a concrete
    ``system.vdi``.  It knows nothing about what is inside the container, which
    is why it sits beside ``vdi`` rather than above it.

The layering is one-directional: ``extfs`` never imports ``vdi``, and ``vdi``
never imports ``extfs``.  ``partition.boot()`` imports ``extfs`` lazily, inside
the function, because identifying the boot partition means looking for
``/kernel`` in it -- a deliberate cycle broken at the one place it is needed.

Two properties are load-bearing throughout:

**Bounds are checked where they are known.**  A partition covering 28,634
sectors cannot be talked into writing sector 30,000.

**Batching is part of the interface.**  On the Windows 9p mount this project
runs against, one write costs ~17 ms whether it carries 4 KiB or 1 MiB.  The
fast path used to be reached through ``getattr(device, "write_blocks", None)``,
so a device that lost the method quietly went back to being 50x slower with
nothing to say so.

Reference for the container format: VirtualBox's ``src/VBox/Storage/VDICore.h``
and ``VDI.cpp``.  The header is ``#pragma pack(1)``, so it is packed rather
than aligned -- the 64-bit disk size sits at an unaligned offset, and guessing
otherwise shifts every following field.
"""

from . import extfs, filetype, image, images, partition, vdi
from .device import ByteDevice, Device, DeviceError, SectorDevice, WriteStats
from .image import Disk, ImageError, RawDisk, VdiDisk, open_image

__all__ = [
    "ByteDevice",
    "Device",
    "DeviceError",
    "Disk",
    "ImageError",
    "RawDisk",
    "SectorDevice",
    "VdiDisk",
    "WriteStats",
    "extfs",
    "filetype",
    "image",
    "images",
    "open_image",
    "partition",
    "vdi",
]
