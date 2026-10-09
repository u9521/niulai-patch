# The device window

MuMuNxDevice.exe: the side panel, the startup ad, and the game-tools panel.

## The per-device window

Everything up to here concerns `MuMuNxMain.exe`, the *launcher* (device list,
title bar, dropdown, tray). The window shown while a device is running is a
different executable:

```
nx_device/15.0/shell/MuMuNxDevice.exe   36,382,712 bytes, x64, signed
```

Same PE family and the same Qt idioms, so the techniques transfer — but the
addresses are unrelated, and a patch written for one binary means nothing in
the other. The two are therefore separate profiles (`remove-components` and
`device-ui`).

### The side-panel menu

The slide-out menu is built like the launcher's dropdown: one block per item,
each keyed by a `mainMenu*MenuItem` identifier. Fifteen exist:

| Identifier | Label | Block ref |
| --- | --- | --- |
| `mainMenuAndroidMenuItem` | 安卓导航键 | `0x251f49` |
| `mainMenuWindowManagerMenuItem` | 窗口管理 | `0x252d43` |
| `mainMenuKeymapMenuItem` | 键鼠/手柄 | `0x254387` |
| `mainMenuOperationRecorderMenuItem` | 操作录制 | `0x2547be` |
| `mainMenuSynchronizerMenuItem` | 同步器 | `0x254bf8` |
| `mainMenuMumuRemoteMenuItem` | 远程控制 | `0x254f75` |
| `mainMenuGameAccelerationMenuItem` | 加速服务 | `0x25553f` |
| `mainMenuGpsMenuItem` | 虚拟定位 | `0x25596f` |
| `mainMenuMultiPlayerMenuItem` | 多开 | `0x255db4` |
| `mainMenuGameToolsMenuItem` | 游戏中心 | `0x2561e9` |
| `mainMenuMoreToolsMenuItem` | 更多工具 | `0x2564e3` |
| `mainMenuDeviceSettingMenuItem` | 设备设置 | `0x2589c2` |
| `mainMenuHelpCenterMenuItem` | 帮助中心 | `0x258cea` |
| `mainMenuRebootDeviceMenuItem` | 重启设备 | `0x259aba` |
| `mainMenuToolbarVisibilityMenuItem` | *(toolbar)* | `0x1a85430` |

The literal order matches the on-screen order, which is a useful
cross-check when mapping a screenshot to a block.

Every block is guarded by the same construct:

```
lea  rcx, [rbp+X]        ; the item's data
call <predicate>         ; returns bool in al
test al, al
je   <skip>              ; when false the item is never added
...build the item...
```

**The two entries are NOT guarded the same way.** This is the key correction:
only 加速服务 has a live feature gate. 远程控制 has none at all.

| item | guard around its construction | consequence |
| --- | --- | --- |
| 远程控制 | **none.** The stub at `0x254fa5` is the only call in its block, and its `je` lands at `0x254fd1` -- *before* the factory at `0x254fe2` | always built; no config key exists; the block must be skipped |
| 加速服务 | **live**: `mov edx, 2bh` (id 43 = UU) / `call Controller_IsFeatureEnabled` at `0x255030` / `je 0x2555f1` | config-controllable in principle; the patch forces the skip |

**The stub only guards optional data -- not the item.** The first attempt at
removing these entries patched the predicate call itself (replacing `E8 <rel32>`
with `xor al,al` + three NOPs), on the assumption that the guard wrapped the
whole block. It did not, and the entries stayed visible. The real shape of the
远程控制 block is:

```
lea  rdx, <mainMenuMumuRemoteMenuItem>
call QString::operator=          ; name the item
mov  r9, [r14+0x858]             ; the parent menu
lea  rcx, [rbp+0x7a0]
call 0x155180                    ; <-- the first attempt patched HERE (stub)
test al, al
je   0x254fd1                    ; ...but this target is only 0x23 bytes on
lea  rax, [<lambda>]             ; optional: attach a click handler
mov  [rbp+0x21c0], rax
lea  r8, [rbp+0x21c0]            ; <- both paths converge here
lea  rdx, [rbp+0x1430]
mov  rcx, r9
call 0x140003238                 ; item factory: allocates and adds the item
mov  dword ptr [rbx+0x30], 0x27  ; kind 0x27 = the remote entry
mov  rcx, [r14+0x458]            ; <- 0x25501b: the NEXT item's guard begins
```

So the early `je` only skips an optional lambda assignment and rejoins
immediately; the item is still created by `call 0x140003238`. Disabling the
predicate therefore changed nothing visible, which is exactly what was
observed.

**The factory cannot simply be NOPed.** `call 0x140003238` returns the new item
in `rax`, and the very next instructions use it (`mov rbx, rax` then
`mov dword ptr [rbx+0x30], 0x27`), so removing the call would leave `rbx`
stale and crash.

**What works, per item:**

* 远程控制 -- jump over the block. The block's opening 16 bytes are replaced
  with a `jmp rel32` to `0x25501b` plus 11 NOPs, so the name assignment, the
  stub guard, the optional data, the factory and all the item setup are skipped
  together, before anything is allocated.
* 加速服务 -- force its own guard. The `je rel32` at `0x255037` becomes a
  `jmp rel32` to the same target (`0x2555f1`) plus one NOP, which is an edge the
  compiler already emitted rather than one we invented.

**The destination matters.** Jumping from `0x254f9e` to `0x2555f1` for 远程控制
and from `0x255568` to `0x255a21` for 加速服务 would land *past* the following
item's guard:

* `0x2555f1` is beyond the 加速服务 guard at `0x255030`, so the 远程控制 patch
  also removed 加速服务.
* `0x255a21` is beyond the 虚拟定位 guard at `0x255606`, so the 加速服务 patch
  also removed 虚拟定位.

Applied together the net result looked correct only because the first jump
landed exactly on `0x2555f1`, re-entering before the 虚拟定位 guard -- the
second patch's site was already dead code. Each patch was individually wrong and
the pair was accidentally right. The corrected pair stops each item at its own
boundary.

Because all 16 overwritten bytes are wildcards, the 远程控制 signature carries a
12-byte literal tail from just past the jump so it still identifies the right
block (and the block's `lea` prologue is identical across items, so without
that tail it would not be unique).

### The startup splash ad

The splash shown while a device boots is not purely local art. The binary
carries a `StartupImageManager` that downloads campaign images and caches them
under the VM's `data/startup` directory, and a `StartupBkWidget` that rotates
them as a carousel. That is what puts a changing promotional image (a game
banner, with a 去广告 button) on screen at 38% boot.

The log strings spell the design out:

```
[ShellWindow::updateStartupImage]: create startup dir success
[StartupImagePresenter::startupImageInitAsync]: init startup image
[StartupBkWidget::updateCarouselBkImages]: image info is empty
[StartupBkWidget::continueCarouselBkImages] display not allowed
[StartupBkWidget::continueCarouselBkImages] campaign is empty
```

**Patching `continueCarouselBkImages` has no effect.** NOPing the `[this+0x89]`
test at `0x2a5406`, inside `continueCarouselBkImages`, leaves the ad on screen,
and the reason is visible in a real `shell.log`:

```
[StartupBkWidget::stopCarouselBkImages]  stop carousel bk images by shell window   (1x)
[StartupBkWidget::updateCarouselBkImages] image info is empty                      (2x)
[StartupBkWidget::updateClickableAreaInfo] ...                                     (3x)
[StartupBkWidget::continueCarouselBkImages] display not allowed                    (0x)
[StartupBkWidget::continueCarouselBkImages] continue carousel bk images            (0x)
```

`continueCarouselBkImages` is only reachable from `ShellWindow::gotoStartingPage`
(which *hides* the splash) and from Qt connection tables. It never runs while the
ad is on screen. The function that actually paints the campaign is
**`updateCarouselBkImages`** at `0x2a79b0`, reached as:

```
ShellWindow::updateStartupImage  (0x2a1ac0)
  -> thunk 0x8cba -> updateCarouselBkImages (0x2a79b0)
```

Its own first decision is the useful lever:

```
0x2a79ec  call QListData::isEmpty        ; the candidate campaign image list
0x2a79f2  test al, al
0x2a79f4  jnz  loc_1402A7BDD             ; <-- replaced with jmp + NOP
0x2a79fa  ...                            ; non-empty: measure and paint
```

and `loc_1402A7BDD` is the author's "nothing to show" tail: it drops the list
(`QListData::shared_null`), calls `sub_14001DABB(a1, 1)` and `sub_1400072BB(a1)`
to fall back to the built-in art, and logs `image info is empty`.

Forcing that branch means the downloaded campaign is discarded before it is ever
measured or painted, while the bundled default splash still renders. The jump
target is unchanged (`0x2a7bdd`), the length is preserved (6 bytes → 5-byte `jmp`
+ 1 NOP), and the flag itself is untouched.

This stops the campaign image. The bundled static frames under
`resources/images/nx/device/jpeg/img_startup_*.jpeg` are separate and are left
alone — `niulai-patch splash` is the tool for those.

### Stopping the download too

`splash-carousel` only stops the image being *painted*. The request itself still
happens on every launch, and the results are written under
`%APPDATA%\Netease\MuMuPlayer\data\startupImage\<campaignId>\`. A second patch,
`splash-ad-download`, removes the request.

The chain is:

```
QMetaObject::invokeMethodImpl (queued, from the startup presenter)
  -> lambda 0x140e094f0 -> 0x140b93930
    -> fetch initiator 0x141023750        <-- patched here
      -> HTTP GET  api/v2/campaign/launcher/launching
        -> sub_14101fe70 parses the JSON
          -> sub_1410256a0 downloadImages_ fetches Normal/Hover/Pressed.jpeg
```

`0x141023750` is the single entry point: it appends
`v2/campaign/launcher/launching` to the configured API host, logs
`[StartupImageManager::fetchImageInfos_]: url: %s`, and only then issues the
request. Both of its callers (`0x140005f83` and `0x141025280`) are thunks into
it, so one patch covers every path. It already opens with a null-context guard:

```
0x102379a  cmp  [rcx+0F0h], r14     ; r14 = 0
0x10237a1  jz   loc_141024C62       ; <-- replaced with jmp + NOP
0x10237a7  xorps xmm0, xmm0         ; build the request...
```

and `loc_141024C62` is the plain epilogue (stack-cookie check, restore, return).
Nothing has been allocated at that point, so the early return cannot leak, and it
is the same exit every other failure path takes. Forcing it makes the fetch a
no-op: no request, no JSON parse, no image downloads, no `imageManager.json`
rewrite.

The two patches are deliberately independent — `splash-carousel` alone keeps the
download but never shows it; both together leave no trace.

### What is not covered

The `data/startupImage` cache directory is not deleted, and an already-cached
campaign stays on disk. With `splash-ad-download` applied nothing refreshes it
and `splash-carousel` stops it being painted, so it is inert; removing the
directory is a manual step if the files themselves matter.

## The 游戏中心 panel: auto-popup and config fetch

The game-tools panel (游戏中心) is server-driven, and two of its behaviours can be
removed independently.  The patches live in `src/pe/patches/device-ui.toml` as
`gametools-no-autopopup` and `gametools-no-config-fetch`.

> **A third lever, `gametools-dynamics-tab`, must not be used: it crashes the
> process on startup.** The id it disables turns out to be the 游戏中心 *toolbar
> button*, and an unchecked null lookup makes the app die within 120 ms of
> launch. See "The removed patch, and why id 13 is not a tab" below.

### Where the data comes from

The panel is populated per game from a server endpoint:

```
[GameToolsManager::getRequestParam_]: url: https://api.mumu.nie.netease.com/api/sidebar
[GameToolsManager::handleQueryResult_]: errcode=%1
[GameToolsManager::handleQueryResult_]: url: %1, md5: %2, width: %3, display_type: %4
```

`sub_14102BDC0` parses the response and fills a per-tab record: `url`, `md5`,
`width`, `display_type`, `tabIds`, `isNoMoreRemind` and `displayCount`.  The
last two are the auto-popup controls — `displayCount` is how many times the
panel may appear unprompted, and `isNoMoreRemind` is the "don't ask again"
flag.  A cached copy is written to
`%APPDATA%\Netease\MuMuPlayer\data\GameToolsData\GameToolsData.json` by
`GameToolsConfig::loadGameToolsConfig_` (`sub_1412EF990`).

The request itself is issued by `sub_14102A160`, whose only caller is
`GameToolsPresenter::fetchGameToolsConfig` (`sub_140BCBFF0`).

### The two levers

**(a) The auto-popup.** On game launch the shell raises a `GameToolsDisplay`
signal.  The handler is `sub_14059EC10`:

```
0x59ec5e  call sub_140019097       ; SubShellWindow::showGameTools
0x59ec63  test al, al
0x59ec65  jz   loc_14059ED92       ; <-- forced
0x59ec6b  ...                      ; build and show the window
```

`loc_14059ED92` is the plain epilogue, so forcing the branch acknowledges the
signal without ever constructing the panel.  The handler's return value is
discarded by both callers (`mov eax, r15d` immediately overwrites `al`), so the
forced early-out cannot leave a caller holding a bogus result.

This is the **automatic** path only.  The manual route — the 游戏中心 toolbar
button — goes through `ShellWindow::triggerGameTools` (`sub_140284480`), a
different function that does not reach the handler, so the button keeps working.
To make the panel unreachable by any route, `SubShellWindow::showGameTools`
(`sub_14059EE70`) would have to be patched as well; that is deliberately left
alone so the panel remains available on demand.

**(b) The per-game config fetch.** `sub_140BCBFF0` already opens with a
"should fetch" guard:

```
0xbcbff0  test r9b, r9b            ; caller's flag
0xbcbff3  jz   loc_140BCC0D1       ; <-- forced
0xbcbff9  push rbx ...             ; build and send the request
```

`loc_140BCC0D1` is a bare `ret`, reached before any register is pushed, so
forcing the branch is stack-safe.  The fetch becomes a no-op: no request to
`api/sidebar`, and nothing new written under `data\GameToolsData\`.

### What each patch costs

| patch | removes | side effect |
| --- | --- | --- |
| `gametools-no-autopopup` | the unprompted popup on game launch | the toolbar button still opens the panel |
| `gametools-no-config-fetch` | the `api/sidebar` request and its cache | the manual panel has no server-driven tabs, so it opens empty |

The second is the broadest: the config is what decides *which* games get which
tabs and how many times the panel may pop up, so removing it also removes the
data behind the first.  Applying it alone is enough to stop every server-driven
popup; applying both makes the intent explicit in the binary rather than
dependent on the server returning nothing.

### The removed patch, and why id 13 is not a tab

`gametools-dynamics-tab` is not shipped, because NOPing the availability branch
in the factory at `0x2cbd47` crashes the process:

```
0x2cbd47  mov  edx, 0Dh            ; id 13
0x2cbd4c  call sub_140023830      ; available?
0x2cbd53  jnz  loc_1402CBD6A      ; <- was NOPed
```

**That crashes the device process on startup.**  Two identical minidumps were
captured (`crash-files/reports/*.dmp`):

```
exception  0xC0000005 (access violation)
Rip        module base + 0x2c6140
Rcx        0x0
0x2c6140   mov rax,[rcx+40h]        ; reads [0+0x40]
```

The chain, from `sub_1402076A0` (the title-bar/toolbar builder):

```
0x140207f24  mov  edx, 0Dh          ; id 13
0x140207f2c  call sub_14003715F     ; getObjectById -> sub_1402D4C30
0x140207f31  mov  rcx, rax          ; rax = 0 once id 13 is gone
0x140207f34  call sub_14002784F     ; -> 0x2c6140, dereferences rcx
```

`sub_1402D4C30` walks a list and returns `nullptr` when the id is absent, and
that caller has **no null check**.  So id 13 is not a panel tab at all — it is
the 游戏中心 **toolbar button**, and removing it guarantees a null dereference
during startup.

The real 动态栏 tab is built inline in the panel builder `sub_1405CD3B0` (via
the `Dynamics Tab` string at `0x1405cd84c`) and has no reusable availability
gate, so there is no safe single-branch patch for it.  It is only reachable by
opening the panel, and `gametools-no-autopopup` stops it appearing on its own.

If a future build genuinely needs the tab gone, the correct target is the
`QBoxLayout::addWidget` at `0x1405cd81b` that adds the tab widget to the bar —
skip that call rather than make an object lookup fail.

**Lesson recorded in the test suite:** `test_dynamics_tab_patch_is_gone_and_must_not_come_back`
asserts the patch is absent and that no patch claims `0x2cbd47`.

### The 动态栏 *menu* entry — a different, safe target

The name 动态栏 appears in two unrelated places, and the crash above came from
confusing them:

| | panel tab | side-panel menu entry |
| --- | --- | --- |
| built by | `sub_1405CD3B0` (panel builder) | `sub_1402514A0` (main-menu builder) |
| label string | `Dynamics Tab` @ `0x1405cd84c` | `Dynamic Tab` @ `0x140255e9a` |
| gated by | nothing reusable | feature id 44 (`0x2c`), live |
| id assigned | — | `[rbx+30h] = 0Dh` at `0x140256288` |
| patchable | only by skipping `addWidget` | **yes — force its own gate** |

`sub_1402514A0` is the builder that emits every entry the user sees in the side
panel; the string scan of its `lea r8` sites maps label to feature id directly:

```
'Android navigation key' 15   'Keymap' 25          'Gps' 40
'Home' 17                     'Operation record' 26 'Multiple devices' 27
'Window manager' 19           'Sync' 28             'Dynamic Tab' 44
'More tools' 38               'Screenshot' 32       'Screen record' 33
'Apk install' 34              'Volume' 41           'Shake' 39
'share floder' 36             'Device setting' 7    'Help center' 7
'FAQ' 75                      'Problem diagnosis' 8 'Support' 8
'Reboot device' 54            'remote control' (unguarded)
'Game acceleration' 43
```

The 动态栏 guard has the same shape as 加速服务's:

```
0x255e66  mov  rcx, [r14+458h]
0x255e6d  test rcx, rcx
0x255e70  jz   0x25629b            ; no handler object -> skip
0x255e76  mov  edx, 2ch            ; feature id 44
0x255e7b  call Controller_IsFeatureEnabled
0x255e80  test al, al
0x255e82  jz   0x25629b            ; <-- forced by menu-dynamics-tab
```

`0x25629b` is the author's own landing pad: it is where the guard's *first* `jz`
already goes, and where execution resumes for 更多工具 (id 38, guard opens at
`0x2562b3`).  Turning the 6-byte `jz rel32` into `jmp rel32` + `nop` skips
exactly this one item and reaches only code the vendor already wrote.  The
skipped range `0x255e88..0x256296` builds nothing but stack-local QStrings around
the item factory, so jumping over it skips their constructors together with
their destructors — no unwind and no leak.

This is the general rule worth keeping: **force an existing branch, never make a
lookup fail.**  The id-13 patch failed because it changed what a factory
returned; this one only changes which of the vendor's own paths is taken.
