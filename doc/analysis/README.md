# Reverse-engineering notes

Findings from static inspection plus live x64dbg sessions against
`MuMuNxMain.exe` and `MuMuNxDevice.exe` (MuMu 6.8.2.0 / nx 15.0). Everything
here was verified on this machine; where a conclusion is uncertain it is
labelled as such rather than asserted.

These are reference notes. For the tool's own documentation, start at
[../README.md](../README.md).

| File | Contents |
| --- | --- |
| [binaries.md](binaries.md) | installation layout, PE characteristics |
| [telemetry.md](telemetry.md) | every reporting endpoint and how it is redirected |
| [ui-and-flags.md](ui-and-flags.md) | the launcher UI, `GrayFeature`, and the `.qm` labels |
| [components.md](components.md) | removing UI components, and the safe lever for each |
| [device-window.md](device-window.md) | the per-device window, its side panel and the game-tools panel |
| [config-and-features.md](config-and-features.md) | the config system and `features.json` |
| [splash-artwork.md](splash-artwork.md) | the boot image, its container format, and the replacements |
| [version-drift.md](version-drift.md) | locators, build identity, declared dependencies |
| [disk-writer.md](disk-writer.md) | the ext2/ext4 writer's invariants and the bugs they came from |
| [debugging.md](debugging.md) | attaching a debugger and locating a widget site |
