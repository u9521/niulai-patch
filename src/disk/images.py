"""Locate the guest disk images that the disk-editing features operate on.

MuMu keeps one directory per product under ``nx_device/<version>/vms/``::

    nx_device/15.0/vms/MuMuPlayer-15.0-base/
        system.vdi     the Android system image (what we patch)
        data.vdi       user data
        data-lite.vdi  minimal user data
        ota.vdi        OTA payload space

``system.vdi`` holds the read-only /system partition, which is why patching it
is a one-time offline edit rather than something the guest can do to itself.
The same file is shared by every instance of that product and is declared
``Readonly`` in the product's ``.nemu`` file, so the edit has to be made while
the emulator is closed.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


class ImageError(Exception):
    """Raised when the expected disk image cannot be located."""


@dataclass(frozen=True)
class VmImages:
    """The images belonging to one emulator product."""

    directory: Path
    product: str

    @property
    def system(self) -> Path:
        return self.directory / "system.vdi"

    @property
    def data(self) -> Path:
        return self.directory / "data.vdi"

    def all_vdi(self) -> list[Path]:
        return sorted(self.directory.glob("*.vdi"))

    def summary(self) -> str:
        return f"{self.product} at {self.directory}"


def _install_roots(explicit: Path | None = None) -> list[Path]:
    roots: list[Path] = []
    if explicit:
        roots.append(Path(explicit))
    for var in ("MUMU_INSTALL_DIR",):
        env = os.environ.get(var)
        if env:
            roots.append(Path(env))
    roots.extend(
        Path(p)
        for p in (
            r"C:\Program Files\Netease\MuMu",
            r"C:\Program Files (x86)\Netease\MuMu",
            "/mnt/c/Program Files/Netease/MuMu",
            "/mnt/c/Program Files (x86)/Netease/MuMu",
        )
    )
    return roots


def find_vm_images(
    install_dir: Path | None = None,
    *,
    product: str | None = None,
) -> VmImages:
    """Find the ``vms/<product>`` directory holding ``system.vdi``.

    Prefers a product whose name contains the MuMu major version, then the
    first directory that actually has a ``system.vdi`` -- reporting the
    candidates when there is a choice, so a wrong guess is visible.
    """
    searched: list[str] = []

    for root in _install_roots(install_dir):
        vms = root / "nx_device"
        if not vms.is_dir():
            searched.append(str(vms))
            continue
        for version_dir in sorted(vms.iterdir(), reverse=True):
            product_root = version_dir / "vms"
            if not product_root.is_dir():
                continue
            for entry in sorted(product_root.iterdir()):
                if not entry.is_dir():
                    continue
                if not (entry / "system.vdi").is_file():
                    continue
                if product and product not in entry.name:
                    continue
                return VmImages(entry, entry.name)
        searched.append(str(vms))

    if product:
        raise ImageError(
            f"no VM image directory matching {product!r} found under:\n  "
            + "\n  ".join(searched or ["(nothing searched)"])
        )
    raise ImageError(
        "no system.vdi found in any MuMu installation; tried:\n  "
        + "\n  ".join(searched or ["(nothing searched)"])
        + "\nSet MUMU_INSTALL_DIR to point at the installation."
    )


def all_vm_images(install_dir: Path | None = None) -> list[VmImages]:
    """Every product's image directory, for a listing command."""
    out: list[VmImages] = []
    for root in _install_roots(install_dir):
        vms = root / "nx_device"
        if not vms.is_dir():
            continue
        for version_dir in sorted(vms.iterdir(), reverse=True):
            product_root = version_dir / "vms"
            if not product_root.is_dir():
                continue
            for entry in sorted(product_root.iterdir()):
                if entry.is_dir() and (entry / "system.vdi").is_file():
                    out.append(VmImages(entry, entry.name))
    return out
