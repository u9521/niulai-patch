# The configuration and feature-flag system

Every config file, its owner, and what features.json can and cannot replace.

## `features.json`: the complete feature-flag system (MuMuNxDevice.exe)

This file resolves the feature-flag picture end to end: the mechanism, the exact
file, and the full 85-entry catalogue. The `nx_main` side is in
[ui-and-flags.md](ui-and-flags.md).

### The controller

| address | function | role |
| --- | --- | --- |
| `0x140787280` | `Controller::init` | reads the feature file and builds the enabled set |
| `0x140784090` | `Controller::IsEnabled(id)` | reads one feature's file; **enabled iff the content is exactly `true`** |
| `0x140787fe0` | `Controller::isNotEnabled(id)` | logs `[Controller]: isNotEnabled(%1)` when not enabled |
| `0x1407843a0` | 85-way switch, id -> config directory | one directory per feature |
| `0x140011e96` | thunk to `isNotEnabled` | 208 call sites — this is the real gate |
| `0x141b51500` | feature-name table, 85 entries of `{ptr,len}` (16 bytes) | id 0..84 -> name |

`IsEnabled` is a strict whole-file comparison, not a JSON parse:

```c
v4(config, Buf1, "features.json", dir);          // read <dir>/features.json
if (memcmp(Buf1, "true", 4) == 0 && len == 4)    // exact "true", no newline
    return true;
return false;                                    // absent file => not enabled
```

### The file is bound per key, and is `features.json`

`CompiledKeyRegistry` (`mumu::service::config::CompiledKeyRegistry`, built by
`sub_140FC62B0`) registers every configuration key against a backing file. The
registration for the splash logo reads, in assembly:

```asm
lea rdx, xmmword_141B788A0   ; "feature.startup_middle_logo.enabled"   <- the key
lea rcx, [rsp+...]
call sub_140002E82           ; set key
lea rdx, qword_141B52540     ; "features.json"                        <- the file
lea rcx, [rsp+...]
call sub_140002E82           ; set file
```

The same pattern repeats for all 81 `feature.*.enabled` keys, so **every one of
them is stored in a file named `features.json`** — not `customer_config.json`, not
`nx_main.json`. That is why a hand-written `features.json` placed in `configs\main\` does
nothing: the key registry binds the file elsewhere.

`ConfigEngine` (`0x140fb6190`) composes the layers in this order:

```
MemoryLayer -> SystemLayer -> RegistryLayer -> NxDeviceEngineCommonRwLayer
            -> NxDeviceCommonRwLayer ("common_rw") -> VmIndexLayer
```

`NxDeviceCommonRwLayer` (`0x140fae0b0`) is the read/write layer and is what
composes `InstallDirNxDeviceConfigModuleLayer`, `InstallDirMainConfigModuleLayer`
and the shared per-VM layer. It is the layer that persists `features.json`.

The device process provably writes only two JSON files (from `JsonFileLayer`
`dirty_save_target` lines in `nx_main.log`):

```
C:\Program Files\Netease\MuMu\nx_device\15.0\configs\device\shell_config.json
C:\Program Files\Netease\MuMu\vms\MuMuPlayer-15.0-0\configs\customer_config.json
```

`features.json` is neither of them today because it does not exist yet; it is
created on demand by the read/write layer.

There is a second, unrelated `features.json`: `RuntimePlayer::getKeepAlived`
(`0x141476400`) reads `overlay\features.json` (key
`feature.nxmain_keep_alived.enabled`) under the install root's `overlay\`
directory, which is an optional OTA layer and is absent on this install. Do not
confuse the two.

### The 81 feature keys, in the binary's own registration order

`sub_140FC62B0` (`CompiledKeyRegistry`) registers each key against the file
`features.json` via `sub_1400294E2(registry, out, key, file)`. The keys are emitted
in a fixed order; this is that order, read out of the builder at the `lea r8`
sites in `0x140fcfc00`-`0x140fd2070`:

| # | key | # | key |
| --- | --- | --- | --- |
| 0 | `feature.customer_service.enabled` | 41 | `feature.volume.enabled` |
| 1 | `feature.tabbar.enabled` | 42 | `feature.apps.enabled` |
| 2 | `feature.topbar.enabled` | 43 | `feature.uu.enabled` |
| 3 | `feature.login.enabled` | 44 | `feature.uu_remote.enabled` |
| 4 | `feature.message_center.enabled` | 45 | `feature.game_tools.enabled` |
| 5 | `feature.main_menu.enabled` | 46 | `feature.quit_confirm.enabled` |
| 6 | `feature.user_account.enabled` | 47 | `feature.shortcut_manager.enabled` |
| 7 | `feature.setting_center.enabled` | 48 | `feature.startup_middle_logo.enabled` |
| 8 | `feature.diagnosis.enabled` | 49 | `feature.startup_show_normal.enabled` |
| 9 | `feature.feedback.enabled` | 50 | `feature.other_setting_in_setting_center.enabled` |
| 10 | `feature.restart.enabled` | 51 | `feature.network_setting_in_setting_center.enabled` |
| 11 | `feature.faq.enabled` | 52 | `feature.run_limitations_in_setting_center.enabled` |
| 12 | `feature.updater.enabled` | 53 | `feature.reboot_emulator.enabled` |
| 13 | `feature.about_us.enabled` | 54 | `feature.boss_key.enabled` |
| 14 | `feature.tool_menu.enabled` | 55 | `feature.fixed_window_info.enabled` |
| 15 | `feature.android_item.enabled` | 56 | `feature.auto_selected_pre_tab_item.enabled` |
| 16 | `feature.multi_task.enabled` | 57 | `feature.top_notice.enabled` |
| 17 | `feature.go_home.enabled` | 58 | `feature.sub_win.enabled` |
| 18 | `feature.go_back.enabled` | 59 | `feature.auto_mute_when_hidden.enabled` |
| 19 | `feature.win_manager.enabled` | 60 | `feature.startup_topmost_emulator.enabled` |
| 20 | `feature.top_window.enabled` | 61 | `feature.service.enabled` |
| 21 | `feature.mini_window.enabled` | 62 | `feature.hidden_multi_run_entrance_in_main_menu.enabled` |
| 22 | `feature.rotate.enabled` | 63 | `feature.hidden_device_tab.enabled` |
| 23 | `feature.restore_win_size.enabled` | 64 | `feature.not_launch_device_first_run.enabled` |
| 24 | `feature.full_screen.enabled` | 65 | `feature.hidden_novice_guide_first_run.enabled` |
| 25 | `feature.key_mapper.enabled` | 66 | `feature.feature_hidden_member_expiration_reminder.enabled` |
| 26 | `feature.operation_recorder.enabled` | 67 | `feature.main_menu_button.enabled` |
| 27 | `feature.multi_player.enabled` | 68 | `feature.main_setting_center.enabled` |
| 28 | `feature.synchronizer.enabled` | 69 | `feature.main_update_button.enabled` |
| 29 | `feature.start_or_stop_sync.enabled` | 70 | `feature.not_main_theme_dark_default.enabled` |
| 30 | `feature.pause_or_resume_sync.enabled` | 71 | `feature.privacy_window_show.enabled` |
| 31 | `feature.multi_tag_in_setting_center.enabled` | 72 | `feature.not_title_use_game_icon.enabled` |
| 32 | `feature.screenshot.enabled` | 73 | `feature.not_mini_title_use_game_icon.enabled` |
| 33 | `feature.screen_recorder.enabled` | 74 | `feature.fast_start.enabled` |
| 34 | `feature.apk_installer.enabled` | 75 | `feature.device_menu_guide.enabled` |
| 35 | `feature.associate_apk.enabled` | 76 | `feature.help_center_frequently_questions.enabled` |
| 36 | `feature.share_folder.enabled` | 77 | `feature.help_center_feedback.enabled` |
| 37 | `feature.file_transporter.enabled` | 78 | `feature.game_utils.enabled` |
| 38 | `feature.more_tools.enabled` | 79 | `feature.not_passive_start.enabled` |
| 39 | `feature.shake.enabled` | 80 | `feature.nxmain_auto_start.enabled` |
| 40 | `feature.gps.enabled` | | |

**Caution about the id -> key mapping.** The 85-entry name table at
`off_141B51500` and this 81-entry key list are two *independent* lists. They agree
in spirit but are not index-aligned, and four names (`PhoneModel`,
`kLineupAssistant`, `GameToolCollection`, `RedemptionCenter`) have no key at all.
Two mappings are confirmed directly from code and must be trusted over any
positional reasoning:

| id | name | key | confirmed by |
| --- | --- | --- | --- |
| 51 (0x33) | `StartupMiddleLogo` | `feature.startup_middle_logo.enabled` | gate at `0x1402a1e22` in `ShellWindow::updateStartupImage` |
| 52 (0x34) | `StartupShowNormal` | `feature.startup_show_normal.enabled` | gates at `0x14029398d` / `0x140293c93` |

The remaining pairs should be read out of `sub_1407843A0` (the 85-way switch that
maps an id to its config directory) rather than inferred from list position; that
switch is a jump table at `0x140784406` with per-case bodies from `0x14078441d`
onwards. Doing that exhaustively is mechanical but was not completed here, so the
table above is authoritative for the *keys* and only partly authoritative for the
*ids*.

Only 61 of the 85 ids appear as immediate operands at `isNotEnabled` call sites:

```
1,3,4,5,7,8,11,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,31,32,33,34,36,37,
38,39,40,41,42,43,44,45,46,47,48,49,50,51,52,53,54,55,56,58,59,60,61,62,64,65,
71,72,73,74,75,77,81
```

The other 24 reach the same gate through a register rather than an immediate, or
are consulted through the DI-resolved `IsEnabled` accessor, so their absence from
that list does not mean they are unused.

### The gate is inverted

This is the single most important detail, and it is the opposite of the obvious
reading. `isNotEnabled(id)` returns true when the feature is **not** enabled, and
the call sites are written so that the *feature's own UI is built when it is NOT
enabled*. Two verified examples:

**Splash middle logo** — `ShellWindow::updateStartupImage` (`0x1402a1ac0`), site
`0x1402a1e70`:

```c
if ( isNotEnabled(controller, 51 /* StartupMiddleLogo */)
  && *(a1 + 568)
  && ( !sub_1400293AC() || ( !sub_140010992(...) && !sub_140032803(...) ) )
  && !*(a1 + 280) )
{
    // new QHBoxLayout(*(a1 + 272)); setSpacing(0); setMargin(0);
    // sub_140021F6C(...)  -> builds the overlay widget, cached at *(a1 + 280)
    // addWidget(...)
}
```

`*(a1 + 280)` caches the widget, so it is constructed at most once. The overlay is
the 80x80 `ic_logo.svg` `NemuSvgWidget` seen over the splash art.

**Window show mode** — `ShellWindow::showView` (`0x140293830`), site `0x14029398d`:

```c
if ( v9 && isNotEnabled(v9, 52 /* StartupShowNormal */) )
    QWidget::show(v2);            // normal size
else
    QWidget::showMaximized(v2);   // maximized
```

So `StartupShowNormal` set to `false` (i.e. "not enabled") makes the window open
at normal size rather than maximized.

### Consequence for this project

The feature-flag system is a strictly better mechanism than binary patching for
everything it covers, because:

* it survives MuMu updates that would invalidate every signature in
  `patches/*.toml`;
* it needs no backup of a 30 MB executable and no checksum or Authenticode work;
* it is MuMu's own supported switch, so it cannot be "wrong" about intent.

It does **not** replace the existing patches for the left nav rail, the tray
兑换中心 item, or the device menu entries: those specific widgets are not gated by
any feature id (`nav-remote`, `nav-cloudphone`, `nav-feedback`,
`tray-redemption-center` have no corresponding entry in the table above), so the
byte patches in `remove-components.toml` remain the only way to remove them.

The remaining unknown is the exact directory that the `features.json` lookup is
resolved against for feature 51. Resolving it requires either a write test against
the install (rejected during this session) or a debugger breakpoint on
`0x140784090`. The candidates, in the order the layer composition suggests, are the
per-VM config directory (`vms\MuMuPlayer-15.0-0\configs\`) and the device config
directory (`nx_device\15.0\configs\device\`).

---

## The configuration system: every file, its owner, and whether it gets overwritten

Analysed from `MuMuNxMain.exe.i64` (full symbols + RTTI), cross-checked against the
live logs in `%APPDATA%\Netease\MuMuPlayer\logs\` and the on-disk config tree.
`MuMuNxMain.exe` and `MuMuNxDevice.exe` share the same framework
(`mumu::service::config`), so everything here applies to both processes.

### The engine

| symbol | address | role |
| --- | --- | --- |
| `ConfigEngine` ctor | `0x140C515B0` | holds the ordered layer vector; calls `setParent` (vfn+112) on each |
| layer push | `0x140C838F0` (`sub_140011AB8`) | appends to the vector at `+72`, **newest last** |
| `LegacyCommonRwLayer` ctor | `0x140C7F1D0` | builds the nx_main / nx_device layer stack |
| `NxDeviceCommonRwLayer` ctor | `0x140C80B90` | adds the device-only module layers |
| `NxDeviceEngineCommonRwLayer` ctor | `0x140C81070` | engine-scoped layers |
| `NxMainCommonRwLayer` ctor | `0x140C814A0` | nx_main-scoped layers |
| `JsonFileLayer` ctor | `0x140BDB060` | binds one JSON file; takes a cross-process mutex |
| key → file binding | `0x140C98D90` + `sub_140FC62B0` | `CompiledKeyRegistry`: every key names its backing file |
| set / dirty-save | `0x140BEBC50` | writes one key, records it in the dirty set |
| JSON load | `0x140BE08C0` | Poco `JSONConfiguration`, per-file |
| temp-write failure path | `0x1414DC470` | `write_temp_failed` |
| `overlay\features.json` reader | `0x1406BD610` | `RuntimePlayer::getKeepAlived` |

Layer precedence is **registration order, last wins**. Each layer is pushed onto the
vector and immediately handed the config built by all previous layers.

### The file catalogue

Resolved from the string table plus the xref sets around `sub_140C98D90`.

**Install-dir files (`<install>\configs\...`)**

| file | resolved path | writer |
| --- | --- | --- |
| `nx_main.json` | `configs\main\nx_main.json` | **yes** — dirty-saved at exit |
| `shell_config.json` | `configs\main\shell_config.json` | **yes** |
| `nx_remote.json` | `configs\main\nx_remote.json` | installed on demand |
| `nx_updater_config.json` | `configs\main\` | updater |
| `clipboard_text_config.json` | `configs\main\` | on clipboard use |
| `run_limitation_config.json` | `configs\main\` | rarely |
| `report_app_data_config.json` | `configs\main\` | telemetry counters |
| `rom_common_data_config.json` | `configs\main\` | rarely |
| `install_config.json` | `configs\install_config.json` | **installer only** — never rewritten at runtime |
| `vm_config.json` | `configs\main\` | installer |
| `vms_config.json` / `vm_config_shared.json` | `configs\main\` | installer |
| `window_arrange_settings.json` | `configs\main\multi-window-arrange\` | on window arrange |
| `customer_config.json` | `configs\main\multi-advanced\` | on setting change |

**Device files (`<install>\nx_device\15.0\...`)**

| file | resolved path | writer |
| --- | --- | --- |
| `shell_config.json` | `nx_device\15.0\configs\device\shell_config.json` | **yes** — GPU detection results |
| `vm_config.json` | `nx_device\15.0\configs\device\` | installer |
| `vms_config.json` | `nx_device\15.0\configs\device\` | installer |
| `hypervisor_config.json` | `nx_device\15.0\configs\device\` | installer |
| `updater_config.json` | `nx_device\15.0\configs\` | updater |
| `extra_config.json` | engine-relative | per-VM |
| `features.json` | **see 22.4** | read-only in practice |

**Per-VM (`<install>\vms\MuMuPlayer-15.0-0\configs\`)**

`customer_config.json`, `extra_config.json`, `shell_config.json`,
`top_notice_config.json`, `vm_config.json` — written on VM setting change.

**Preset / overlay layers** — `preset\configs\customer_config.json` and
`overlay\features.json` are *documented* layer roots, but neither directory exists
in this install. They are the officially-supported override hook, added by the
installer when a channel/preset ships one.

### What actually gets overwritten (confirmed empirically)

The device log contains the complete write history, and it is remarkably narrow:

```
[JsonFileLayer] dirty_save_begin dirty_key_count=1 path=...\configs\main\nx_main.json
[JsonFileLayer] dirty_save_begin dirty_key_count=2 path=...\nx_device\15.0\configs\device\shell_config.json
[JsonFileLayer] dirty_save_target operation=set key=nxmain.quit_status version=3        -> configs\main\nx_main.json
[JsonFileLayer] dirty_save_target operation=set key=renderer.detector.gpu_level_gl ...   -> device\shell_config.json
[JsonFileLayer] dirty_save_target operation=set key=renderer.detector.gpu_level_vk ...   -> device\shell_config.json
[JsonFileLayer] Saved config to: ...\configs\main\nx_main.json
[JsonFileLayer] Saved config to: ...\nx_device\15.0\configs\device\shell_config.json
```

So at runtime only **two** files are ever rewritten:

1. `configs\main\nx_main.json` — on exit (`nxmain.quit_status`), plus report timestamps.
2. `nx_device\15.0\configs\device\shell_config.json` — on GPU detection (`renderer.detector.*`).

Every other JSON is read-only at runtime. `install_config.json` is never touched
after install — which is why it still carries the `mtime` of the installer run.

The save is **atomic and merge-based**, not a blind overwrite:

* `JsonFileLayer` takes a named **cross-process mutex** per file
  (`0x140BDB060`). If it cannot, it logs
  `Cross-process mutex creation failed for: <path>, stable_name: <name>` and then
  sets a flag so it can `Refusing future saves to avoid lost updates.`
  — i.e. it declines to write rather than clobber.
* Saves are tracked as a **dirty-key set** (`dirty_key_count=`), so only the keys
  this process actually changed are written.
* Before writing it re-reads the file from disk (`read base before set`,
  `refresh before set`) and merges, so concurrent edits by another process survive.
* Writes go to a temp file then `Atomic replace`; a corrupt file is *quarantined*
  (`Atomic quarantine-replace`) rather than discarded.
* If a key is absent on disk but present in memory, the merge keeps the memory value
  (`Reload dirty memory decision`).

### `features.json` — where it is actually read

Section 21 established the gate but not the directory. The layer composition
answers it: the lookup goes through the `NxDeviceConfigModuleLayer` /
`NxDeviceEngineCommonRwLayer` chain, whose read-only base layer is
`InstallDirNxDeviceConfigModuleReadonlyLayer` (`0x140C80B90`, name literal at
`0x140027601`). That layer is rooted at the **engine config directory**,
`nx_device\15.0\configs\`, with the per-VM directory layered on top.

This is why the earlier experiment — dropping `features.json` into
`configs\main\` — did nothing: `configs\main\` is the *nx_main* module root, a
sibling of the device root, and the device process never looks there.

Two consequences worth recording:

* `features.json` is **never written** by the runtime (no `dirty_save_target` line
  ever names it), so a hand-placed file is stable.
* It is a *whole-file* read of the literal text `true` (see "The controller"
  above), so it is not a key/value JSON document despite the extension. A file
  containing `true` and nothing else enables that key.

### The one true `features.json` variant

There are two distinct files with that name, and they are unrelated:

| path | reader | semantics |
| --- | --- | --- |
| `<nx_device config dir>\features.json` | `Controller::IsEnabled` | whole file equals `true` ⇒ feature on |
| `overlay\features.json` | `RuntimePlayer::getKeepAlived` (`0x1406BD610`) | real JSON, key `feature.nxmain_keep_alived.enabled`, value `"true"` |

The second one *is* parsed as JSON and lives under `overlay\`, which does not exist
here. It is the only genuine key/value `features.json`, and the only one reachable
without a binary patch if an `overlay\` directory is created.

---

## Can the config files replace the binary patches?

Short answer: **no, not for any of the components this project removes.** The
config system is real and well-built, but it does not expose a switch for the
avatar button, the title-bar dropdown items, the left nav rail, the tray item,
or the device side-panel entries.

### What I checked

Three independent lines of evidence, all agreeing:

**(a) The main process has the SAME feature-flag machinery as the device process.**
*A string-only scan misses this, because the key bank is reached through `lea`
references rather than as a contiguous blob; the reading below is from the
on-disk image.*

`MuMuNxMain.exe` contains:

* the **same 82 `feature.*.enabled` key strings** as `MuMuNxDevice.exe`
  (`feature.uu.enabled`, `feature.uu_remote.enabled`,
  `feature.startup_middle_logo.enabled`, `feature.startup_show_normal.enabled`, …);
* the **same registry builder** (`call 0x140002900`), registering all
  142 key/file pairs (81 `feature.*.enabled` + 61 `url.link.*`) against
  `features.json`;
* the `[Controller]: isNotEnabled(%1)` log format and the
  `enabled all features` string;
* one genuine `isNotEnabled` call site at RVA `0x4dd1d0` (log string at
  `0x1699580`) — the `HiddenDeviceTab` gate, which the live log confirms firing;
* `overlay\features.json`, read by `RuntimePlayer::getKeepAlived`
  (`0x1406BD610`) for `feature.nxmain_keep_alived.enabled`.

The 85-id *device* catalogue above is `MuMuNxDevice.exe`'s own, but the
*mechanism* — keyed lookup, whole-file `true` comparison, absent file ⇒ all on —
is shared by both binaries.

**(b) The log confirms BOTH processes gate features.** *(Corrected: the earlier
claim had this backwards.)*

* `nx_main.log` (the launcher process) prints
  `[Controller]: isNotEnabled(HiddenDeviceTab)`.
* `shell.log` (the device process) prints `[Controller]: isNotEnabled(Apps)`
  three times at startup.

So neither process is feature-flag-free; both consult the same `features.json`
semantics.

**(c) The components are not feature-gated anyway.** Section 21.5 already recorded
this; re-verified here. The widgets this project removes are built unconditionally:

| component | gating |
| --- | --- |
| avatar button | none — added to the title-bar layout directly |
| 消息中心 / 兑换中心 / 常见问题 / 下载掌上MuMu | factory call sites, ungated (the "feature test" seen nearby is the compiled-out `mov al,1; ret` stub bank) |
| 远控 / 云手机 / 反馈 (nav rail) | none — 5 unconditional `QBoxLayout::addWidget` calls |
| tray 兑换中心 | guarded, but by a runtime state check, not a feature id |
| 远程控制 / 加速服务 (device menu) | **call to a stub in the `0x155180` bank, each called from exactly one site** — this is the one place a flag conceptually exists, and it is compiled out |

That stub bank is the closest thing to a config switch in the whole picture, and it
is *not* wired to any file: it is a literal `mov al,1; ret`. There is no key to set.

### What the config files CAN do

Not nothing — just not the removals. Real, working keys:

| file | key | effect |
| --- | --- | --- |
| `vms\<vm>\configs\shell_config.json` | `player.advanced.show_fps.enabled` | show/hide the FPS overlay |
| ″ | `player.advanced.adb_debug.mode` | ADB debug mode |
| ″ | `renderer.advanced.hight_fps.enabled` / `.input` | high frame rate |
| ″ | `renderer.advanced.light.enabled` / `.input` | brightness |
| ″ | `renderer.force_dedicated_gpu` | force the dGPU |
| ″ | `renderer.fps_limit` / `fps_limit_real` / `fps_limit_low` | frame caps |
| ″ | `renderer.gpu_id` | pick the GPU |
| ″ | `renderer.audio_out_hardware_off` | audio device handling |
| `vms\<vm>\configs\customer_config.json` | `customer.app_keptlive` | keep process alive |
| ″ | `customer.memory_optimization_opened` | memory optimisation |
| ″ | `customer.network_*` | bridged networking |
| ″ | `customer.quit_directly` | skip the quit confirmation |
| ″ | `customer.default_location_latitute` / `longtitute` | default GPS |
| `configs\main\nx_main.json` | `nxmain.view.mode` | main window view mode |
| `overlay\features.json` | `feature.nxmain_keep_alived.enabled` | keep-alive (needs an `overlay\` dir to exist) |

These are genuine preferences, not component removal. Notably **none** of them
hides a menu item or a nav button.

### One thing worth knowing: the GrayFeature channel

The main EXE has its own lighter-weight remote-config channel, visible in the log:

```
[ControllerPresenter::updateSharedMemory_] Updated all GrayFeatures in shared memory
[ControllerPresenter::updateSharedMemory_] Updated GrayFeature CloseStartupAdButton to 1 in shared memory
```

`CloseStartupAdButton` is a **server-pushed** gray feature, delivered through shared
memory and flipped by the backend. It is not a local file — there is nothing to
edit, and it is not in the `features.json` system. This is the mechanism behind
"the startup ad can't be turned off locally" (see [splash-artwork.md](splash-artwork.md)),
and it reconfirms
that the ad is server-controlled.

### Verdict

For everything this project removes, **binary patching remains the only route**.
The config system is genuinely useful for *preferences* (the table in 23.2), and the
`features.json` gate described above is a real switch — but it governs only the
`MuMuNxDevice.exe` behaviours listed there (startup logo, window show mode, hidden
device tab, …), not the launcher chrome.

The practical recommendation stands: use `features.json` where it applies because it
survives updates and needs no patching; keep `patches/*.toml` for the launcher
chrome, which has no config equivalent.

---

## `features.json` — verified mechanism, and what it can replace

This section supersedes the exploratory parts of 21 and the "no" verdict of 23.3
for the four specific targets the project patches in `MuMuNxDevice.exe`.

### The mechanism, confirmed end to end

Symbols (names applied in IDA to `MuMuNxDevice.exe.i64`):

| address | name | role |
| --- | --- | --- |
| `0x140011E96` | `Controller_IsFeatureEnabled(id)` | the live gate; **TRUE = enabled = build the UI** |
| `0x140784090` | `Controller_IsFeatureEnabledById` | reads `<configDir>\features.json`, returns `value == "true"` |
| `0x1407843A0` | `Controller_GetFeatureKeyById` | `switch(id)` → the `feature.xxx.enabled` key |
| `0x140787280` | `Controller_LoadEnabledFeatures` | startup load, logs `enabled features:` / `enabled all features` |
| `0x140787FE0` | `Controller_LogDisabledFeature` | logs `isNotEnabled(<Name>)` |
| `0x141B51500` | `g_FeatureIdNames[85]` | id → name |
| `0x141B52280` | `g_AllFeatureIds[85]` | `{0..84}` |
| `0x140155100`… | `FeatureGuard_stub_true_*` | `mov al,1; ret` — vendor-compiled-out guards |

Read path, per key:

```
key  = Controller_GetFeatureKeyById(id)      // e.g. "feature.uu.enabled"
data = layer->read("<configDir>\\features.json", key)
on   = (data == b"true")                     // whole-file, exact, no JSON parse
```

Consequences that matter operationally:

* Only the exact 4 bytes `true` enable a feature. `"true\n"`, `True`, `1`, or a
  real JSON object such as `{"feature.uu.enabled":"true"}` all read as **off**.
* The file is **not** a JSON document despite the name and the `.json` suffix.
* **If the file is absent, every feature is ON** except the four that are
  hidden-by-default: `HiddenDeviceTab` (80), `NotLaunchDeviceFirstRun` (81),
  `HiddenNoviceGuideFirstRun` (82), `HiddenMemberExpirationReminder` (83).
* Four ids have **no key at all** and are therefore permanently off:
  `PhoneModel` (46), `kLineupAssistant` (47), `GameToolCollection` (65),
  `RedemptionCenter` (84).

Live call sites in the image: **179**, covering **59 distinct ids**. The
`BuildDeviceSidePanelMenu` function (`0x1402514A0`) alone contains 51 of them.
`ShortcutManager` (49) appears 23× — it gates the shortcut *hint text*, not the
entry.

### The four requested targets

| target | can `features.json` do it? | key | evidence |
| --- | --- | --- | --- |
| **开屏 logo 显示** (splash middle logo) | **YES** | `feature.startup_middle_logo.enabled` (id 51) | `0x1402a1e1d mov edx,33h; call Controller_IsFeatureEnabled; test al,al; jz loc_1402A1F61` — FALSE skips the logo |
| **开屏 logo 尺寸/正常窗口** | **YES** | `feature.startup_show_normal.enabled` (id 52) | `0x14029398d` / `0x140293c93`: `call IsFeatureEnabled; test al,al; jz +; call QWidget::show` |
| **去开屏广告** (startup campaign image) | **NO** | — | no `feature.*` key exists for it. Two patches cover it: `splash-ad-download` stops the fetch (`0x102379a`) and `splash-carousel` stops the paint (`0x2a79f4`). `CloseStartupAdButton` is a **server-pushed GrayFeature** over shared memory (23.3), not a local file. |
| **远程控制** (device menu) | **NO** | — | no guard around the item at all; the stub at `0x254fa5` only gates a click handler |
| **加速服务** (device menu) | *in principle* | `feature.uu.enabled` (id 43) | live gate at `0x255030`; but the key governs the UU accelerator broadly, so the patch (`menu-acceleration`, forcing that gate's `je`) is the surgical choice |

So of the four: **the two splash/logo behaviours are config-replaceable; the ad
carousel and the two menu entries are not.**

### Why the two menu entries resist config

**加速服务 is feature-gated; 远程控制 is not.** The two must not be conflated:

* **加速服务** is gated by a *live* check -- `mov edx, 2bh` (id 43 = UU) /
  `call Controller_IsFeatureEnabled` at `0x255030` / `je 0x2555f1`. In principle
  `feature.uu.enabled` controls it, but the vendor's own stub at `0x155330`
  (called from `0x25556f`) only gates an optional click handler, and the outer
  guard's `je` is what the PE patch forces. So config *could* work here, but the
  key also governs the UU accelerator generally, which is broader than "hide one
  menu row"; the patch is the surgical choice.
* **远程控制 has no guard at all.** The only call in its block is the stub at
  `0x254fa5`, whose `je` lands at `0x254fd1` -- *before* the item factory at
  `0x254fe2` -- so it only decides whether a click handler is attached. The item
  is built unconditionally and no config key reaches it.

Fifteen further side-panel guards in the same function are also stubs
(`0x155160`, `0x155190`, `0x1551d0`, `0x1551f0`, `0x155200`, `0x155250`,
`0x1552c0`, `0x155330`, `0x155360`, `0x155410`, `0x155420`, `0x155440`,
`0x155490`, `0x1554a0`, `0x155550`), while the entries that *do* have live gates
(AndroidItem, WinManager, Gps, KeyMapper, Screenshot, ApkInstaller, GameTools,
SettingCenter, …) are config-controllable.

Note the stub for `Gps` (`0x155160`, called from `0x25599f`) **overrides** the live
`feature.gps.enabled` check that exists elsewhere, so the Gps entry is always
built even with `feature.gps.enabled` off. Stubs win over live checks where both
exist.

### The live toolbar lever that *is* config-driven

The device window's icon strip is governed by a separate, fully live mechanism
(`SettingCenter::getToolbarTopmostItems` / `…ShownItems`, visible in `shell.log`):

```
[SettingCenter::getToolbarTopmostItems]: items: kUnknown,kKeymap,kVolume,kBack
[SettingCenter::getToolbarTopmostShownItems]: items: kMuMuRemote
```

These map to `vms\<vm>\configs\customer_config.json`:

```json
"setting.toolbar.shown_item"   : "kMuMuRemote",
"setting.toolbar.topmost_items": "kUnknown,kKeymap,kVolume,kBack"
```

Valid item names are the enum at `0x141a9c058`:
`kUnknown kHome kBack kWinTopmost kMiniMode kScreenRotation kFullScreen kKeymap
kOperationRecorder kMultiPlayer kSync kCloneApp kGameTools kUURemote kScreenShot
kScreenRecorder kApkInstall kFileTransfer kShake kGps kVolume kLogin
kMessageCenter kToolMenu kMainMenu kSegLine kWinMini kWinMax kWinClose
kAdsUURemote kMultiTask kSettingCenter kReboot kDiagnosis kRevert
kRestoreWinSize kPhoneModel kLineupAssistant kMuMuRemote kGameToolCollection`.

This is a **preference**, not a removal: it changes which items occupy the toolbar
and the topmost slot, and it can drop `kMuMuRemote` from the topmost strip — but
it does not delete the side-panel `远程控制` entry, which is what the PE patch
removes.

### Where `features.json` goes

`Controller_IsFeatureEnabledById` builds `<dir>\features.json`, where `<dir>` is
the config layer root. `shell.log` names it directly:

```
[ThemeMonitor::reloadCurrentTheme]: app_config_dir=C:\Program Files\Netease\MuMu\nx_device\15.0\configs\
```

That directory exists and currently contains only `device\`. It is the
highest-precedence writable layer (per-VM overlays sit above it, install-dir
presets below). No `features.json` exists anywhere in the installation today,
which is exactly why the log shows the all-on default.

### Verdict for the four targets

* **Splash middle logo** — set `feature.startup_middle_logo.enabled` to exactly
  `true` to show it, or omit/negate it to hide it. No patching.
* **Startup window sizing** — `feature.startup_show_normal.enabled`. No patching.
* **Startup campaign ad** — no config key; two PE patches cover it:
  `splash-ad-download` (stops the API fetch, so nothing is written to
  `data/startupImage`) and `splash-carousel` (stops the paint). See
  [device-window.md](device-window.md).
* **远程控制 / 加速服务** — no config key; keep the PE patches
  (`menu-remote-control`, `menu-acceleration`).

A useful side effect: because the absent-file default is all-on, creating a
`features.json` that lists only the keys you want is itself a way to *disable*
everything else — a single file can prune most of the device window without
touching the executable.

---
