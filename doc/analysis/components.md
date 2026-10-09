# Removing UI components

Which widgets can be removed, where they are built, and the safe lever for each.

## What can and cannot be removed

Goal: make UI elements *not exist*, as opposed to changing their wording.
`.qm` editing cannot do this -- it holds no reference to `avatarButton` at all
(verified: the object name is absent from `zh_hans.qm`).

### What was established

`avatarButton` has **6 references**, all of the same shape, and the shape was
resolved rather than guessed:

```
48 8b f1              mov  rsi, rcx
48 8b 09              mov  rcx, [rcx]
ff 15 1a9fb201        call [isVisible?]
84 c0 / 0f 84 ...     test al, al ; je <early exit>
48 8b 1e              mov  rbx, [rsi]
ba 0c 00 00 00        mov  edx, 12          ; strlen("avatarButton")
48 8d 0d cb3d5201     lea  rcx, [str]
ff 15 5d66b201        call QString::fromAscii_helper
48 89 44 24 70        mov  [rsp+70], rax
...
                      call <findChild / update>
```

The call target RVA `0x1c2be87` resolves through the import table to
**`Qt5Core.dll!QString::fromAscii_helper(char const*, int)`**, and `edx` = 12
matches the 12-character literal. Two independent facts agreeing is what makes
this reading reliable.

**These are `findChild` lookups, not creation.** Consequence: setting the
length to 0 would make the *lookup* fail, but the widget still exists and still
paints. It is not a removal.

Sites: RVA `0x10581e`, `0x10c7fc`, `0x14ae5c`, `0x159db0`, `0x16e7c3`, `0x182f72`.

Related identifiers, with reference counts that matter for risk:

| Identifier | Refs | What the refs actually do |
| --- | --- | --- |
| `avatarButton` | 6 | `findChild` + update |
| `personal_menu` | 1 | `QObject::connectImpl` signal/slot wiring |
| `titleBar` | 2 | real `setObjectName`, but shared by every dialog |
| `profile` | 55 | far too broad to touch |

`titleBar` was checked as a candidate and rejected: the two sites are genuine
creation code (`QWidget::QWidget` -> `setObjectName("titleBar")` ->
`setFixedHeight` -> `NxBaseDialog::setTitleWidget` -> `NxAnchorLayout`), but
this is the **window chrome shared by all dialogs**, not the avatar. Patching it
would affect every dialog for no benefit.

### Scale of the problem

Counting call sites in `.text`:

| API | Sites |
| --- | --- |
| `QObject::setObjectName` | 503 |
| `show` | 60 |
| `hide` | 34 |
| `setVisible` | 19 |
| `setEnabled` | 97 |

There is no single narrow hook. Removing a component means finding the one
construction path among 27 `QPushButton` constructor call sites, and the avatar
button is created somewhere that does not name it `avatarButton` (since all six
name references are lookups, the name is likely assigned by a later
`setObjectName` whose literal is shared or indirect).

### Method names recovered

The binary logs 966 distinct `[Class::method]` tags, which gives real symbol
names for free. Those relevant to the avatar:

```
AccountFlowManager::handleAccountFlowTransition_ / handleFlowResult_
                  / handleLogin_ / handleUserInfoRequestFail_ / setState
                  / showDisplayWindow_
NxMainPresenterImpl::onAccountInit / onAccountLoginStatusChanged
                   / onAccountLogout / onAccountSwitched / onLoginWinPopup
                   / onLogoutWinPopup / onPaymentWinPopup
NxMainWindow::notifyLoginWinPopup / updateMuMuRemoteStatus
```

One embedded build path also leaked:
`F:\b\ns-20260930001534-14212\r\src\ui\nx_main\NxMainWindow.cpp`.

These tag strings could not be reached by any `lea` or absolute-pointer
reference, so the code behind them was not located statically. They are the
best starting point for a debugger session.

### Why static analysis is not enough here

The construction site cannot be found by reading the image:

* the `.qm` route is **ruled out** for component removal;
* the `avatarButton` reference sites are **lookups**, so patching them is not a
  removal;
* `titleBar` is **too broad** — it is the window chrome shared by every dialog;
* `profile` is **too broad** (55 references);
* the actual construction site is not reachable from any of those.

Finding it needs a live session: break on `QPushButton::QPushButton`, let the
main window build, and walk the return addresses to find which caller builds the
title-bar avatar, then identify the widget by a later `setObjectName`. See
[debugging.md](debugging.md) for the recipe.

## The avatar button: the construction site

The dynamic search succeeded. `setObjectName` logging with an app-side caller
filter, redirected to a file with `LogRedirect`, yielded **162 app call sites**
and the complete title-bar widget inventory.

The site itself:

```
call @0x14ae3e : NX::NxPushButton2::NxPushButton2(NxIconPushButton::WidgetData, QWidget*)
lea  @0x14ae5c : "avatarButton"
call @0x14ae63 : QString::fromAscii_helper
call @0x14ae76 : QObject::setObjectName
```

* **Creation call: RVA `0x14ae3e`**
* Widget class: **`NX::NxPushButton2`** (an icon push button)
* Naming: `setObjectName("avatarButton")` immediately after

RVA `0x14ae5c` is also one of the **six `avatarButton` references** counted
earlier — where it reads as another `findChild` lookup. It is in fact the
**creation site**. Only the other five
(`0x10581e`, `0x10c7fc`, `0x159db0`, `0x16e7c3`, `0x182f72`) are lookups.

The constructor call sits 9 bytes *before* the `lea`, which is why scanning
only the `lea` neighbourhood and assuming "lookup" gives the wrong answer.

### The title-bar cluster

The surrounding sites form one contiguous group, matching the screenshot:

| RVA | Widget |
| --- | --- |
| `0x14a3f6` | `mainAdBtn` |
| `0x14a95b` | `mainUpdateBtn` |
| **`0x14ae7c`** | **`avatarButton`** |
| `0x14b430` | `MainTitleMenuButton` |
| `0x14bae5` | `mainMinBtn` |
| `0x14bfe5` | `mainCloseBtn` |

Adjacent groups identified in the same run: `leftDeviceBtn`,
`leftMuMuRemoteBtn`, `leftCloudPhoneBtn`, `feedbackBtn`, `deviceNewBtn`,
`deviceBatchBtn`, `deviceArrangeBtn`, `DeviceListSearchButton`,
`DeviceListSortMenuButton`, and the banner/cloud-phone widgets.

### Reading a widget's construction site

1. Break on the **function body** of `Qt5Core`'s `setObjectName`
   (`Qt5Core.dll+0x1E0D90`), resolved from the IAT slot at runtime.
2. Condition: `[[rsp]] >= <exe base> && [[rsp]] < <exe base> + 0x1C00000`,
   which keeps only app-side callers and drops Qt's own internal use.
3. `LogRedirect "<path>"` to write the log to a file.
4. Run, let the UI build, then `LogRedirect ""` to release the file lock and
   read it.

The file lock is worth noting: the log is unreadable while redirected and only
becomes readable after the redirect is closed.

## The avatar button: the patch

The `remove-components` profile removes the account avatar button, and it is
**confirmed working in a real run**: `MuMuNxMain_test.exe` started normally
(221 MB, both CEF children up) with **the avatar gone**.

The avatar's construction is left entirely intact -- it is still allocated,
constructed, named `avatarButton`, and has its two click handlers connected.
Only the final `QBoxLayout::addWidget` is replaced with six NOPs:

```
0x14ae3e  call NX::NxPushButton2::ctor        kept
0x14ae5c  lea  "avatarButton"                 kept
0x14ae76  setObjectName("avatarButton")       kept
0x14af0c  QObject::connectImpl                kept
0x14afa1  QObject::connectImpl                kept
0x14afc1  QBoxLayout::addWidget               -> 90 90 90 90 90 90
```

Because it is never added to a layout, the widget is never laid out, never
painted and occupies no space. Same-length replacement, so nothing relocates.

### Why not skip the construction?

Making the constructor not run was considered first and **rejected on
evidence**, not on taste:

* `setObjectName` dereferences `this` immediately
  (`mov rbx, [rcx+8]`, no null check), so a null widget would crash;
* the branch that runs when `new` returns null does `mov rbx, r12`, so
  flipping the `jz` would call `setObjectName` on *some other widget* --
  silent corruption rather than removal;
* two `QObject::connect` calls follow, which also assume a live object.

So the widget must exist; the only safe lever is whether it reaches a layout.

### The rule a signature must satisfy

A signature must not pin the bytes the replacement rewrites. Pinning the `FF 15`
opcode bytes of a call being replaced works once and then becomes **invisible**:
after patching, the signature no longer matches, so `verify` reports the patch as
lost and a re-run reports the signature as missing.

`Patch.validate()` enforces this per byte, not per signature: it rejects any
signature byte that conflicts with the replacement. Testing "does the signature
contain any wildcard" is not enough, because a signature can contain a wildcard
*and* still pin other bytes that the replacement changes.

### `locate_rva` and why it is now the exception

The two adjacent title-bar widgets compile to **byte-identical** instruction
sequences apart from one call displacement, so no signature can separate them
*within those 16 bytes*. `locate_rva` patches at an exact address, with the
signature still verified there first, so a different build is caught rather than
silently misapplied.

That is the right answer to the question as posed — but the question was wrong:
the two sites *are* distinguishable, by the object-name literal each block
assigns a short way earlier. Every patch that used `locate_rva` for this reason
uses a `string-ref` locator instead; see
[version-drift.md](version-drift.md) for the one remaining exception.

## Component inventory for the screenshot's remaining boxes

The live session's widget inventory (the `setObjectName` method above) plus a
static sweep for menu identifiers located every element in the screenshot.

### Left navigation rail

| Widget object name | Screenshot item |
| --- | --- |
| `leftDeviceBtn` | 设备 |
| `leftMuMuRemoteBtn` | 远控 |
| `leftCloudPhoneBtn` | 云手机 |

Also present nearby: `leftLobsterBtn`, and the nav items
`audioNavItem`, `diskNavItem`, `displayNavItem`, `modelNavItem`,
`networkNavItem`, `performanceNavItem`, `developerNavItem`, `shortcutNavItem`,
`otherNavItem`.

### Title-bar dropdown menu

The dropdown is a native `QMenu` named **`MainMenu`** (`0x168121` sets that
object name with `QString::fromAscii_helper(.,8)`), built inside one function
spanning RVA `0x16803e`-`0x16939c`.

Each of the six items is a self-contained block with this shape:

```
lea  rdx, <metaobject ctx>            ; e.g. 0x1abbe50
call QMetaObject::tr                  ; the visible Chinese label
...  4 icon records: {index, white svg, black svg} ...
lea  r9, <lambda> ; mov edx,0x18 ; mov r8d,4
lea  rcx, [rbp+X]
call 0xbd43                           ; copy the 4 records into a container
...
lea  rdx, <name literal>              ; e.g. "mainMessageCenterMenuItem"
call QString::operator=(const char*)
...  feature-flag test via a `mov al,1; ret` stub ...
lea  r8, [rbp+Y] ; lea rdx, [rbp+Z] ; mov rcx, rdi
call <item factory>                   ; <-- creates the item and adds it
```

| `tr()` label | Item | Name literal | Create call | Factory |
| --- | --- | --- | --- | --- |
| `MessageCenter` `0x1681f8` | 消息中心 | `0x1629bb0` | `0x16842b` | `0x1ec3b` |
| `RedemptionCenter` `0x1684f3` | 兑换中心 | `0x1629bd0` | `0x168778` | `0x2c5c` |
| `SettingCenter` `0x1687ea` | 设置中心 | `0x1629c88` | `0x168a6f` | `0x2c5c` |
| `FAQ` `0x168ae1` | 常见问题 | `0x1629d10` | `0x168d66` | `0x2c5c` |
| `download MuMuPlayer App` `0x168db6` | 下载掌上MuMu | `0x1629e08` | `0x169035` | `0x2c5c` |
| `AboutUs` `0x16909d` | 关于 MuMu | `0x1629ea8` | `0x169313` | `0x2c5c` |

Two plausible-looking answers are both wrong, and the table above is the
corrected one: the name literals are **not** at `0x16287b0`-`0x1628aa8` (those
hold format strings such as `"Window] delay 100ms"`), and the `call 0xbd43` at
the end of each block is **not** the point that makes an item visible — patching
all four of those sites leaves the menu unchanged.

### Why `call 0xbd43` is not the menu

`0xbd43` is an ILT thunk resolving to **`0x13229a0`**, which disassembles to:

```
imul rdi, r8            ; rdi = rcx + rdx*r8
add  rdi, rcx
...
loop: call rdx          ; invoke the lambda for each of r8 elements
      dec  rbx
```

That is a **container range-fill loop** — `std::vector`/`QList` style. Its
arguments at each site are `edx=0x18` (24-byte elements) and `r8d=4` (four of
them), matching the four `{index, whiteIcon, blackIcon}` records built just
above. It copies data into an in-memory list; it touches no widget and no
`QMenu`. Patching it is invisible, which is exactly what the live test showed.

### The real intervention point

Each item is created by a call at the end of its block. The factories are two
near-identical siblings, and they are the only place a menu item object comes
into existence:

| Factory | Allocates | Constructor | Used by |
| --- | --- | --- | --- |
| `0x462310` (via thunk `0x1ec3b`) | `0xC8` | `0x30305` | 消息中心 only |
| `0x461c80` (via thunk `0x2c5c`) | `0xC8` | `0xd3d2` | the other five |

Both take `rcx` = parent `MainMenu`, `rdx` = the name QString, `r8` = widget
data, and both end with `call 0x1113`. Replacing the *call site's* `call` with
five NOPs means the item is never created at all, so it is genuinely absent
rather than blank.

**Why this is safe.** The factory's return value is discarded: the instruction
immediately after every call is `mov rcx, [rbp+...]`, overwriting `rax`, and the
code that follows is null-guarded (`test rcx,rcx` / `je`). Nothing consumes the
result, so skipping the call cannot leave a dangling pointer or a garbage
handle. Same-length replacement, so nothing relocates.

**How the four identical sites are told apart.** The redemption, setting, FAQ and
about sites are byte-identical for the whole 16-byte window
(`48 8D 55 20 48 8B CF E8 ?? ?? ?? ?? 90 48 8B 8D`), so a bare scan returns
**four** matches. The object-name literal each block assigns a short way earlier
is unique, so a `string-ref` locator on that literal narrows the window to one
site and the signature then verifies it. The message-center and download sites
are unique on their own but use the same shape for consistency; see
[patch-sites.md](../patch-sites.md).


### Bottom-left

| Object name | Screenshot item |
| --- | --- |
| `feedbackBtn` | 反馈 |

### Not in the screenshot, for completeness

`mainAdBtn`, `mainUpdateBtn`, `MainTitleMenuButton` (the hamburger that opens
the dropdown), `mainMinBtn`, `mainCloseBtn`, and the device-list controls
(`deviceNewBtn`, `deviceBatchBtn`, `deviceArrangeBtn`,
`DeviceListSearchButton`, `DeviceListSortMenuButton`,
`DeviceListDisplayModeSwitchButton`).

## The system-tray menu

The tray is a **separate** `TrayMenuWidget`, not the title-bar dropdown, and it
repeats 兑换中心 under its own identifier:

| Object name | Tray item | Name literal | Item start |
| --- | --- | --- | --- |
| `trayShowMainWindowMenuItem` | 显示主界面 | `0x1627c28` | `0x10d3bb` |
| `trayExitClawMenuItem` | 退出（云手机） | `0x1627cd0` | `0x10d608` |
| `trayExitPlayerMenuItem` | 退出（模拟器） | `0x1627d08` | `0x10d861` |
| `trayRedemptionCenterMenuItem` | 兑换中心 | `0x1627dc0` | `0x10db63` |

All four items live in **one** function, RVA `0x10d0e0`–`0x10dda9`. Because the
dropdown's 兑换中心 and the tray's 兑换中心 are separate identifiers in separate
functions, removing one does **not** remove the other — both need their own
patch.

Three of the four items (显示主界面, both 退出 entries) end with the *same*
append routine as the dropdown, `call 0xbd43`:

```
0x10d5ad   显示主界面
0x10d802   退出（云手机）
0x10db08   退出（模拟器）
```

`0x10d35a` is a fourth call to the same routine that precedes every name site,
belonging to a pre-list item.

### 兑换中心: a guard that can be flipped

The tray's 兑换中心 is the block at `0x10d8e7`-`0x10db63`, labelled by
`tr("RedemptionCenter")` at `0x10d933`. Unlike the title-bar dropdown, its
removal needs no new control flow: the compiler already emitted a skip guard
around the whole entry, and both of its failure paths jump to `0x10dbfc`,
which is where the *next* tray entry begins.

```
0x10d8e7  mov  rax, [rdi]           ; the tray object
0x10d8ea  mov  rcx, [rax+0x160]
0x10d8f1  test rcx, rcx
0x10d8f4  je   0x10dbfc             ; <-- patched to an unconditional jmp
0x10d8fa  mov  edx, 0x54
0x10d8ff  call 0x37a1               ; a pure predicate: reads [rcx+0xa8]
0x10d904  test al, al
0x10d906  je   0x10dbfc             ; already skips when the predicate is false
```

Turning the first `je` into a `jmp` removes the entry by taking a path the
binary already contains. The replacement is 5 bytes of `jmp rel32` plus one
NOP, so it matches the original 6-byte `je rel32` and nothing relocates. Note
the displacement *changes* (`0x302` -> `0x303`) because the two instructions
have different lengths — the requirement is that both resolve to `0x10dbfc`,
which is what the test asserts.

**Why not patch inside the block.** Its only `rel32` calls are the same pair
the dropdown uses — the container fill `call 0xbd43` (`0x10db08`) and a
widget-data helper `call 0xb82f` (`0x10daac`) — and the fill was already proven
invisible on the dropdown. The guard is the reliable lever.

**Relation to the submenu.** The *next* block (`0x10db63`,
`trayRedemptionCenterMenuItem`) builds the flyout's child actions into the
submenu at `[obj+0x4f8]` and then calls `QMenu::exec` at `0x10dd3b`. Those
three `call 0x2c5c` sites pass `rcx = [obj+0x4f8]` — the submenu, not the tray
menu — which is why they are not item creation. Skipping the top-level entry
makes the flyout unreachable, so no separate patch is needed.

Two similarly-named identifiers are **not** UI and must be left alone:

| Identifier | Literal | Reference | What it is |
| --- | --- | --- | --- |
| `mainMenuExchangeCenter` | `0x1629ad8` | `0x118638` | `findChild` lookup |
| `trayMenuExchangeCenter` | `0x1627b00` | `0x117808` | `findChild` lookup |

Both sit in small functions that do `mov rcx,[rcx+8]` / `add rcx, 0x490` /
`lea rdx,<name>` / `call [rip]` — the signature of a `findChild`-style accessor,
not of construction. Patching these would break a lookup, not hide an item.

## The left navigation rail

The rail is built by one function spanning RVA `0x146b80`-`0x147900`. Five
buttons are created, each named with `setObjectName`, four of them registered
with `QButtonGroup::addButton`, and each inserted into the rail's `QBoxLayout`
with `QBoxLayout::addWidget`:

| Widget | Screenshot item | `setObjectName` | `addWidget` | `addButton` |
| --- | --- | --- | --- | --- |
| `leftDeviceBtn` | 设备 *(kept)* | `0x146c1b` | `0x146c38` | `0x146c4b` |
| `leftMuMuRemoteBtn` | 远控 | `0x146ebc` | `0x146f79` | `0x146f8f` |
| `leftLobsterBtn` | *(not in the screenshot)* | `0x1471e2` | `0x147200` | `0x147222` |
| `leftCloudPhoneBtn` | 云手机 | `0x147473` | `0x14749b` | `0x1474b1` |
| `feedbackBtn` | 反馈 | `0x147782` | `0x1477aa` | *(none)* |

**The build order is not the on-screen order.** `leftLobsterBtn` is constructed
*before* `leftCloudPhoneBtn`, so the `addWidget` at `0x147200` belongs to the
lobster button (which is not in the screenshot and is deliberately left alone)
and the cloud-phone one is at `0x14749b`. The mapping in this table was
confirmed by scanning back from each `addWidget` to the nearest
`setObjectName`-bearing name literal, not inferred from address order. Assuming
address order silently targets the wrong button.

`feedbackBtn` is a plain button and is never added to the button group.

The API census for the function confirms the shape — 5 `addWidget`,
4 `addButton`, 1 `addStretch` (the spacer that pushes 反馈 to the bottom),
1 `setCheckable`, 3 `connectImpl`, 5 `setObjectName`.

**The guards are styling, not visibility.** At `0x146c51`-`0x146c69` there is
the same guard shape as the tray:

```
0x146c51  mov  rcx, [rdi+0x160]
0x146c58  test rcx, rcx
0x146c5b  je   0x146c6f
0x146c5d  mov  edx, 0x2d
0x146c62  call 0x37a1
0x146c67  test al, al
0x146c69  je   0x146f95
```

but `0x146f95` is not an exit: it loads the **clawbox** icon set
(`clawbox_dark1_focus.svg` etc.) where the fall-through loads the *remote* icon
set. Both branches converge on the same `addWidget`. Patching this guard would
therefore change the icon theme, not remove the button.

**Intervention point.** NOPing each `addWidget` call leaves the button fully
constructed, named, connected and still a member of the button group, but never
laid out — so it is not painted and takes no space. This is the same technique
already proven by `avatar-button`, and it is the safe choice for the same
reason: the surrounding code assumes the widget exists.

All five `addWidget` sites share a 12-byte prologue, so `leftMuMuRemoteBtn`,
`leftCloudPhoneBtn` and `feedbackBtn` each match **seven** places in the image
(and `leftDeviceBtn` matches two). A bare signature therefore cannot separate
them; the widget's own object-name literal does, which is why each patch carries
a `string-ref` locator and lets the signature verify the result.

**设备 is retained.** Its `addWidget` at `0x146c38` (prologue `0x146c2c`) is
deliberately not patched, so the device list stays reachable. A test asserts
that no patch ever claims that address.
