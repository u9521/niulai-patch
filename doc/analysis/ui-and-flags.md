# The launcher UI and its feature flags

Why the title-bar menu is not native code, and what actually gates it.

## The screenshot menu is not in native code

This is the most important negative result, and it bounds what binary patching
can achieve here.

The menu items — 消息中心, 兑换中心, 设置中心, 常见问题, 下载掌上MuMu, 关于 MuMu —
could not be found as literals in **any** of:

| Searched | Encoding | Result |
| --- | --- | --- |
| `MuMuNxMain.exe`, `MuMuNxDevice.exe`, `NemuShell.exe` | UTF-16LE, UTF-8 | absent |
| `nemu-ui-lib.dll`, `mumu-qt-extensions.dll`, `QCefView.dll` | UTF-16LE, UTF-8 | absent |
| `resources/dist/**` (all 449 web files) | UTF-8 | only 消息中心 present |
| `NxMainResource.rcc`, `NxDeviceResource.rcc`, `NxLauncherResource.rcc` | raw + all 251 decompressed zlib streams | absent |
| `CefView/locales/zh-CN.pak` | UTF-16LE, UTF-8 | absent |
| Live process memory (all 122 modules) | UTF-8 | absent |

Supporting evidence that this is a web UI, not native widgets:

* `%LOCALAPPDATA%\MuMuNxDevice\QtWebEngine\Default\` exists (Chromium profile,
  cookies, GPUCache), and `nx_device\...\shell\CefView\` ships a full
  `libcef.dll` (172 MB) with `resources.pak` and locale `.pak` files.
* `nx_device\...\shell\resources\dist\` is a Vue SPA: `index.html` loads
  `src/js/app.b148c111.js` and `static/js/qwebchannel.js`, the latter being the
  Qt↔JavaScript bridge. `NxDeviceResource.rcc` embeds those assets (its name
  table contains `dist/`, `app.`, `message_center` as UTF-16 strings).
* `nx_main\resources\dist\message_center\` is the *live* copy the launcher
  actually loads (319 files); the binary hard-codes the relative path
  `resources/dist/message_center/index.html` at RVA `0x165b800`. The two trees
  share the same bundle hash `app.b148c111.js`.
* The active bundle does contain 消息中心, which is why it appeared in the
  search — but the other five labels do not exist on disk anywhere.

**Resolution (confirmed by a live run).** Launching the GUI and inspecting the
process tree and logs settled this:

```
MuMuNxMain.exe (PID 31676)
├─ CefViewWing.exe  --type=gpu-process
├─ CefViewWing.exe  --type=utility  (network.mojom.NetworkService)
├─ CefViewWing.exe  --type=utility  (storage.mojom.StorageService)
├─ CefViewWing.exe  --type=renderer (renderer-client-id=7)
└─ CefViewWing.exe  --type=renderer (renderer-client-id=8)
```

The CEF runtime lives in **`nx_main\CefView\`** (not `nx_device`), and the
browser process is `MuMuNxMain.exe` itself. The embedded web views are named in
the binary: **`AccountQCefView`, `MsgCenterQCefView`, `LuaEditorQCefView`,
`FeedbackQCefView`, `CloudPhoneQCefView`** — note there is *no* "main launcher"
CEF view, so the device list and title-bar dropdown are native Qt widgets.

The labels are therefore **not** in any file as plain text because they do not
live in a string table at all — they live in a **Qt `.qm` translation file**
inside `NxMainResource.rcc`. Section 7 has the details.

## Feature flags: the real control surface for the menu

This is the most useful finding of the whole investigation, and it supersedes
binary patching for the menu items entirely.

`MuMuNxMain.exe` contains a `GrayFeature` enum — 27 named UI feature gates:

| Enum name | Controls |
| --- | --- |
| `RedemptionCenter` | **兑换中心** |
| `HelpCenterFrequentlyQuestions` | **常见问题** |
| `HelpCenterFeedback` | **反馈** |
| `MainSettingCenter` | **设置中心** |
| `MainUpdateButton` | the update button |
| `MainMenuButton` | the title-bar hamburger menu |
| `HiddenDeviceTab` | the 设备 tab |
| `HiddenMultiRunEntranceInMainMenu` | 多开入口 |
| `GameUtils` / `GameToolCollection` | game tools |
| `PrivacyWindowShow` | the privacy dialog |
| `CloseStartupAdButton` | the startup ad close button |
| `HiddenNoviceGuideFirstRun`, `NotLaunchDeviceFirstRun`, `HiddenMemberExpirationReminder`, `DeviceMenuGuide`, `RunLimitationInSettingCenter`, `FastStart`, `PassiveStart`, `MainAutoStart`, `NotMainThemeDarkDefault`, `NotTitleUseGameIcon`, `NotMiniTitleUseGameIcon`, `Service` | assorted first-run/UI toggles |

The tray menu additionally registers `trayShowMainWindowMenuItem`,
`trayExitClawMenuItem`, `trayExitPlayerMenuItem` and
**`trayRedemptionCenterMenuItem`**, with icons
`ic_white_redemption_center` / `ic_black_redemption_center`.

### How the flags are resolved

`nx_main.log` shows the mechanism directly:

```
[Controller]: isNotEnabled(HiddenDeviceTab)
[FastStartFeatureGrayManager::requestFeatureStatus] errorCode: 200,
    content: {"enabled": "1"}
[RemoveCampaignFeatureGrayRequester::handleResponse] Enabled features count: 2
    Feature enabled: launcher_launching_campaign
    Feature enabled: launcher_popup
[ControllerPresenter::updateSharedMemory_] Updated GrayFeature CloseStartupAdButton to 1
[ControllerPresenter::updateSharedMemory_] Updated all GrayFeatures in shared memory
[RpcManagePresenterImpl::fireAccountUpdateNotification] action=GrayFeatureUpdate ...
```

So the flow is:

1. `ControllerPresenter` reads a local `features.json`; when it is absent (it is
   absent on this install) it logs `[Controller]: enabled all features`.
2. A **`GrayFeatureRequester` fetches feature status over HTTP** — a real
   `errorCode: 200` with a JSON body — and is the dynamic override.
3. Results are cached in **shared memory**, because multiple processes need the
   same view.
4. Updates are broadcast to the UI as an RPC notification, `GrayFeatureUpdate`,
   which the menu subscribes to and re-renders from.

### Consequence for patching

The menu items are gated by **server-supplied flags**, so:

* They cannot be removed by patching bytes in `MuMuNxMain.exe` — the code that
  hides them already exists and is simply being told not to run.
* There is no local `features.json` to edit today, but creating one is the
  intended override path and is what the binary looks for first.
* Because shared memory is involved, a *runtime* patch is viable: force
  `isGrayFeatureEnabled`/`isNotEnabled` to return "not enabled" in the browser
  process, and the already-present hide paths do the rest. That is a far
  smaller and more robust change than hunting strings.

Left as an open avenue rather than implemented, because the `features.json`
location could not be confirmed without write access to the install directory.

The `no-telemetry` profile in this repo is unaffected by all of the above: those
three sites are confirmed native code in `MuMuNxMain.exe`.

## Other observations

* `configs/main/nx_main.json` holds UI state (guide-shown flags, message id
  lists, view mode) — useful for research but contains no feature kill-switch.
* `nx_device\15.0\vms\MuMuPlayer-15.0-base\products\` and `install_apk\` are
  empty; the VM payload lives in `system.vdi`.
* The `plugin` directories under both `nx_main` and the root are empty.
* `sentry.dll` is present, and the reason no `lea` to a DSN string was found is
  now clear from the live command line: **the DSN is passed as a process
  argument**, not built in code.

  ```
  CefViewWing.exe --type=renderer ...
    --mumu-sentry-dsn=https://f1d7e15afb244685bd7c9e9fb6e911b6@sentry.netease.com/394
    --mumu-sentry-environment=production
    --mumu-cef-child-sentry-dsn=https://f1d7e15afb244685bd7c9e9fb6e911b6@sentry.netease.com/394
    --mumu-sentry-handler-path="...\crashpad_handler.exe"
  ```

  Every CEF child inherits these switches, so Sentry is configured per-process
  on the command line. Blocking it is a matter of intercepting the child spawn
  (or the DSN argument) rather than patching a call site — noted, not patched.
* The CEF bridge is named `CallBridge` (`--bridge-obj-name=CallBridge`), and
  `MuMuNxMain.exe` embeds JavaScript shims that it injects into each web view.
  One installs `window.__mumuMsgCenterExtraShimInstalled`, rewrites
  `navigator.onLine` to always report `true`, and forwards `mumu://` and
  `mumu_sdk://` links to native code:

  ```js
  CallBridge.invoke("directInvoke", "cppJs", "messageCenterOpenUri",
                    JSON.stringify([String(uri)]));
  ```

  The native side handles these in `MsgCenterQCefView::handleOpenUri_`, whose
  action vocabulary includes `open_about_us`.

## Where the menu labels actually live: the `.qm` translation file

This closes the question definitively. The launcher log names the file it loads:

```
[LanguageManager::getQmFilePath]: get qm file for key: zh_hans
[LanguageManager::getQmFilePath]: return qm file:
    :/resources/language-qm/nx-main/nemu-nx-main_zh_hans.qm
[LanguageManager::installQm]: load qm file success
[LanguageManager::installQm]: install translator success
```

So the Chinese strings come from a Qt translation (`.qm`) shipped inside
`nx_main\rcc\NxMainResource.rcc`. That is why searching the exe, the DLLs, the
web bundles and the locale `.pak` files all came up empty.

### Locating it

The rcc container had to be decoded first. Two corrections mattered:

* **Tree node stride is 22 bytes, not 14.** Per
  [qresource.cpp](https://codebrowser.dev/qt5/qtbase/src/corelib/io/qresource.cpp.html),
  `findOffset` is `node * (14 + (version >= 0x02 ? 8 : 0))`, and this bundle
  reports version 3.
* **The name record is `<u16 length><u32 hash><utf16be chars>`.** The hash sits
  between the length and the characters, which is why naive parsing produced
  readable-but-shifted names.

With those fixed, the tree walk yields:

```
: /resources/language-qm/nx-main/nemu-nx-main_zh_hans.qm
  flags = 0x0   -> UNCOMPRESSED (neither zlib 0x01 nor zstd 0x04)
  payload file offset = 0x566a3ce
                        = rcc data section (0x18) + 90612658
```

The `zh_hans` payload is uncompressed, which is another reason naive searches
fail: hunting for a zlib or zstd stream (`zstd.dll` is loaded, so zstd is a
reasonable guess) finds nothing when the file is stored raw.

`src/rcc/rcc.py` implements just enough of the container format to walk the
resource tree and extract payloads, and `niulai-patch strings` exposes it:

```console
$ uv run niulai-patch strings
resource resources/language-qm/nx-main/nemu-nx-main_zh_hans.qm  (none)
┏━━━━━━━━━━━━━━┳━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ string       ┃ hits ┃ offsets in payload                      ┃
┡━━━━━━━━━━━━━━╇━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ 关于 MuMu    │ 2    │ 0x1f6d, 0xcb9e                          │
│ 设置中心     │ 5    │ 0x81b9, 0x885f, 0xc194, 0xf161, 0x10c66 │
│ 消息中心     │ 3    │ 0xa19d, 0xa1d9, 0xe858                  │
│ 下载掌上MuMu │ 2    │ 0xdeda, 0x109aa                         │
│ 常见问题     │ 1    │ 0xe020                                  │
│ 兑换中心     │ 2    │ 0xee6c, 0x131f5                         │
└──────────────┴──────┴─────────────────────────────────────────┘
```

The offsets differ by four bytes from the table further down, which is expected:
that one is measured inside the extracted `.qm` payload, this one inside the
container's resource data.

Compression is **per-resource, not per-container**. Of the 13 translations in
this rcc, `zh_hans`, `zh_Hant`, `ja` and `ko` are raw and the other nine are
deflated — presumably whichever encoding came out smaller. A compressed payload
turns out to carry its own 8-byte big-endian header::

    <u32 compressed_size><u32 uncompressed_size><zlib stream>

Both fields were checked against real data rather than assumed: for
`nemu-nx-main_de.qm` the second field is 137605, which is exactly the inflated
length, and the first is 37898 against a 37894-byte deflate stream.

### The labels, confirmed

Searching the extracted `.qm` for UTF-16BE text finds every menu item:

| Label | Offsets within the `.qm` |
| --- | --- |
| 关于 MuMu | `0x1f69`, `0xcb9a` |
| 设置中心 | `0x81b5`, `0x885b`, `0xc190`, `0xf15d`, `0x10c62` |
| 消息中心 | `0xa199`, `0xa1d5`, `0xe854` |
| 下载掌上MuMu | `0xded6`, `0x109a6` |
| 常见问题 | `0xe01c` |
| 兑换中心 | `0xee68`, `0x131f1` |

Most appear more than once, which is normal for `.qm` files: a translation is
stored per (context, source) pair, and the same English text can appear in
several contexts.

### Each record carries its source string

Reading the bytes around a label shows the standard Qt message layout — the
translation, then the length/context/comment fields whose ASCII bytes appear
byte-swapped when read as UTF-16BE:

| Translation | Source (context) | Comment |
| --- | --- | --- |
| `关于 MuMu` | `About` | `AboutWin` |
| `兑换中心` | `RedemptionCenter` | `NxMainWindow` |
| `常见问题` | `FAQ` | `NxMainWindow` |
| `设置中心` | `MuMu Settings Center` | `MainSettingCenterWindow` |
| `下载掌上MuMu` | `DownloadApp` | `NxMainWindow` |

Note that the source strings are exactly the `GrayFeature` enum names listed
above (`RedemptionCenter`, `MainSettingCenter`, `FAQ`). The two mechanisms line
up: the feature flag decides whether an entry is shown, and the `.qm` supplies
its text.

### Consequence for patching

This adds a second dimension to the feature flags above. There are now two
independent, reversible levers, and neither requires touching executable code:

1. **Edit the `.qm`** to blank or rename the labels. The file is uncompressed
   inside the rcc, so the bytes are directly editable. Because a `.qm` is
   length-prefixed per string, a same-length replacement (or reusing the
   existing NUL padding) keeps the file structurally valid.
2. **Override the theme rcc.** The log shows the app looks for an *overlay*
   first:

   ```
   [ApplicationImpl::loadOverlayResource]: NxMainResource.rcc path:
       C:\Program Files\Netease\MuMu\overlay\nx_main\rcc\NxMainResource.rcc
   [RccConfig::loadOverlayRcc]: overlay rcc file is not exist
   ```

   `C:\Program Files\Netease\MuMu\overlay\` **does not exist on this install**,
   so this designed override hook is unused and untested. If Qt's
   `resourceSearchPaths` precedence applies as documented, placing a modified
   `.qm` (as an rcc) there would take effect without touching any shipped file
   — the cleanest option of all.

Left as avenues rather than implemented: both need further verification, and
option 2 in particular rests on the assumption that the overlay rcc wins over
the built-in one, which has not been tested.
