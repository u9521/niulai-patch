# Documentation

The [README](../README.md) is the landing page. Everything else lives here.

## Using the tool

| File | Contents |
| --- | --- |
| [install.md](install.md) | install, everyday commands, environment overrides |
| [profiles.md](profiles.md) | what each patch profile changes, and what it costs |
| [patch-sites.md](patch-sites.md) | semantic locators, surviving a version update, adding a patch |
| [safety.md](safety.md) | the guarantee behind each write path |
| [limits.md](limits.md) | what the tool does not do, and what is unverified |

## The guest disk

| File | Contents |
| --- | --- |
| [disk.md](disk.md) | the VDI container, its partitions, and the offline editing stack |
| [boot.md](boot.md) | the four files GRUB reads, and growing their partition |
| [lawnchair.md](lawnchair.md) | replacing the built-in desktop |
| [splash.md](splash.md) | replacing the bundled boot artwork |

## Reverse-engineering notes

Static and live findings about the two Windows binaries, written up as reference
rather than as a log. Where a conclusion is uncertain it says so.

| File | Contents |
| --- | --- |
| [analysis/binaries.md](analysis/binaries.md) | installation layout, PE characteristics |
| [analysis/telemetry.md](analysis/telemetry.md) | every reporting endpoint and how it is redirected |
| [analysis/ui-and-flags.md](analysis/ui-and-flags.md) | the launcher UI, `GrayFeature`, and the `.qm` labels |
| [analysis/components.md](analysis/components.md) | removing UI components, and the safe lever for each |
| [analysis/device-window.md](analysis/device-window.md) | the per-device window, its side panel and the game-tools panel |
| [analysis/config-and-features.md](analysis/config-and-features.md) | the config system and `features.json` |
| [analysis/splash-artwork.md](analysis/splash-artwork.md) | the boot image, its container format, and the replacements |
| [analysis/version-drift.md](analysis/version-drift.md) | locators, build identity, declared dependencies |
| [analysis/disk-writer.md](analysis/disk-writer.md) | the ext2/ext4 writer's invariants and the bugs they came from |
| [analysis/debugging.md](analysis/debugging.md) | attaching a debugger and locating a widget site |

## Development

| File | Contents |
| --- | --- |
| [development.md](development.md) | running the tests, and what the disk-layer suite carries |
