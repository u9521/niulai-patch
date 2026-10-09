# Install and usage

Installing the tool, the everyday commands, and the environment overrides.

Requires Python 3.14+ and [uv](https://docs.astral.sh/uv/).

## Install

```bash
uv sync
```

The command is `niulai-patch`; the *distribution* is still named `mumu-patch`, so
that is the name to use in requirements files and in extras such as
`mumu-patch[semantic]`. On-disk state keeps the old name too — backups live under
`~/.local/share/mumu-patch/backups` — deliberately, so existing backups and
scripts keep working across the rename.

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

Other commands: `list-patches`, and `dbg`, which converts patch RVAs to live
addresses for an x64dbg session:

```bash
uv run niulai-patch dbg --base 0x7ff6593f0000
```

`--install-dir` overrides auto-detection (or set `MUMU_INSTALL_DIR`). Backups
go to `~/.local/share/mumu-patch/backups` unless `MUMU_PATCH_BACKUP_ROOT` is set.

Disk-image backups are large (1.8 GB), so they are kept beside the image instead
— under `<vms>/<product>/mumu-patch-backups/` — which also keeps the copy on the
same filesystem. Override with `MUMU_PATCH_IMAGE_BACKUP_ROOT`. The one helper
binary needed, `vbox-img.exe`, ships with MuMu and is found automatically;
override with `MUMU_PATCH_TOOL_DIR` or `--tool-dir`.

**No other external tool is required.** Everything on the disk path is pure
Python: partition editing is `disk.partition`, ext2/ext4 reading and writing is
`disk.extfs`, and growing a filesystem after its partition grows is
`extfs.grow_to`. The assurance this gives up, and what carries it instead, is
recorded in [safety.md](safety.md) and
[analysis/disk-writer.md](analysis/disk-writer.md).

## Commands

| Command | Writes? | Purpose |
| --- | --- | --- |
| `analyze` | no | Report installation, PE facts, and per-patch match status |
| `list-patches` | no | Show profiles, signatures and descriptions |
| `patch` | yes | Apply a profile (supports `--dry-run`, `--only`, `--force`) |
| `rebase` | with `--write` | Re-resolve patch sites against a different build |
| `restore` | yes | Restore from a backup manifest |
| `verify` | no | Check whether applied patches are still in effect |
| `dbg` | no | Map RVAs to live addresses for a debugger |
| `splash` | yes | Replace the bundled startup images (`--image`, or `--bundled`) |
| `strings` | no | Search the launcher's Qt translations |
| `doctor` | no | Report the helper binary and the guest disk images |
| `lawnchair` | yes | Replace the built-in desktop with open-source Lawnchair |
| `boot` | yes | Inspect or replace the kernel, ramdisks and command line |
