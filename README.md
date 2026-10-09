# niulai-patch

A reversible patcher for the installed Netease **MuMu** emulator. It removes
unwanted behaviour — analytics and crash reporting, the tamper-detection CPU
burn, promotional UI — by locating code with **byte signatures** and **semantic
locators** rather than hard-coded addresses, and it backs up every file it
touches so any change can be undone byte-for-byte.

It also edits the emulator's guest disk **offline**: the Android system image is
a VirtualBox VDI, and the launcher APK, the boot kernel and the boot artwork all
live inside it. That path is pure Python — no WSL, no VirtualBox, no helper
binaries to build.

Managed with [uv](https://docs.astral.sh/uv/). Requires Python 3.14+.

## Install

```bash
uv sync
```

## Usage

```bash
# What is installed, and what would each profile do? (read-only)
uv run niulai-patch analyze

# Preview changes without writing anything
uv run niulai-patch patch --profile no-telemetry --dry-run

# Apply (backs up first)
uv run niulai-patch patch --profile no-telemetry

# Is the patch still in effect? (e.g. after a MuMu auto-update)
uv run niulai-patch verify

# Undo
uv run niulai-patch restore --latest
```

`--install-dir` overrides auto-detection (or set `MUMU_INSTALL_DIR`). Backups go
to `~/.local/share/mumu-patch/backups` unless `MUMU_PATCH_BACKUP_ROOT` is set.
Disk-image backups are large (1.8 GB), so they are kept beside the image instead,
under `<vms>/<product>/mumu-patch-backups/`. See
[doc/install.md](doc/install.md) for the rest of the commands and every override.

## Profiles

| Profile | What it changes |
| --- | --- |
| `no-integrity-punish` | disarms `MuMuNxMain.exe`'s self-integrity check, which otherwise pegs a core |
| `no-device-integrity-punish` | the same for `MuMuNxDevice.exe` |
| `no-telemetry` | retargets the launcher's reporting endpoints to an empty string |
| `no-device-telemetry` | the same for the device window, including the crack-detection event |
| `remove-components` | removes the account avatar button from the launcher's title bar |
| `device-ui` | strips side-panel menu entries and the startup ad from the device window |

Every profile that patches a binary **declares** the integrity profile for that
binary as a `requires` dependency, so patching either executable can never
silently arm its own anti-tamper punishment. See
[doc/profiles.md](doc/profiles.md) for what each patch does and what it costs.

## Documentation

Full documentation is under [doc/](doc/README.md):

* [doc/install.md](doc/install.md) — install, commands, environment overrides
* [doc/profiles.md](doc/profiles.md) — the profiles above, in detail
* [doc/patch-sites.md](doc/patch-sites.md) — how a patch site is located, and how it survives an update
* [doc/safety.md](doc/safety.md) — the guarantee behind each write path
* [doc/disk.md](doc/disk.md) — the VDI container, partitions and filesystems
* [doc/boot.md](doc/boot.md), [doc/lawnchair.md](doc/lawnchair.md), [doc/splash.md](doc/splash.md) — the disk-editing commands
* [doc/limits.md](doc/limits.md) — what the tool does not do
* [doc/analysis/](doc/analysis/README.md) — reverse-engineering notes on both binaries

## Development

```bash
uv run pytest -q          # tests
uv run pyright            # types
uv run ruff check         # lint
uv run ruff format --check
uv build                  # sdist + wheel into dist/
```

The suite needs no MuMu installation to run; the tests that read the real image
and the pristine vendor binaries skip cleanly when those are absent. See
[doc/development.md](doc/development.md) for the build configuration and for the
one sharp edge in the editable-install workflow.
