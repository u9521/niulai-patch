# Attaching a debugger to the launcher

The working recipe for locating a Qt widget construction site, and the traps.

The working recipe for locating a Qt widget construction site in
`MuMuNxMain.exe`, and the traps that make the obvious approaches fail.

## Break on the function body, not the IAT slot

```
IAT slot   mumunxmain.exe+0x1c2f570   -> resolves to Qt5Widgets.dll+0x177F70
                                        but logs 0 hits
function   Qt5Widgets.dll+0x177F70    -> fires, 68 hits in one run
```

Reading the IAT slot confirms it resolves correctly to
`Qt5Widgets.dll+0x177F70`, yet a breakpoint there logs **zero hits** even while
RIP is demonstrably inside `qt5widgets.dll+0x177FCC`. An IAT breakpoint only
traps *indirect calls through that slot*, and this binary reaches the
constructor by other means.

`Qt5Widgets.dll+0x177F70` is a genuine prologue (`mov [rsp+0x18], rbx` /
`push rdi` / `sub rsp, 0x20`), so it is the right address; only the slot is
wrong.

## Filter the callers

Qt builds buttons for its own standard dialogs too, so the constructor fires far
more often than the target's own widget code. A **conditional** breakpoint that
keeps only callers inside the main module cuts the noise to something readable:

```
[[rsp]] >= 0x7FF6593F0000 && [[rsp]] < 0x7FF65B3F0000
```

With that armed, one run logged **68 button constructions** and the target
reached 240 MB in a running state. Without it, the second hit already returned
into `Qt5Widgets.dll+0x4D3999` — Qt building buttons for one of its own dialogs.

## Every construction site is self-identifying

`setObjectName` follows every construction, so reading the call right after the
constructor names the widget without guesswork. First hit, caller RVA `0x14a3b2`:

```
QBoxLayout ctor -> setContentsMargins -> addWidget -> addLayout -> addStretch
-> QPushButton(parent)                       <-- caller RVA 0x14a3ac
-> setObjectName("mainAdBtn")
-> hide()
-> setFixedSize(...)
-> setStyleSheet("QPushButton{border-image: url(:/resources/images/nx/ic_top_a...")
```

That is `mainAdBtn`, a top **ad** button hidden by default. The method is the
point: keep the conditional breakpoint armed and read the logged callers until
one is followed by `setObjectName("avatarButton")`.

## The target restarts itself

Runs can end with the debuggee gone and a *new* `MuMuNxMain.exe` at ~39 MB
appearing outside the debugger. MuMu enforces a single instance and hands off,
so the debugged process is not necessarily the one that ends up running. Expect
to re-attach, or to work with the instance that survives.

## A naming detour worth not repeating

The bytes after `avatarButton` in the file look like a pointer table
(`0x141785790`, `0x1400147c7`), which would suggest the string is Qt meta-object
data rather than a `setObjectName` literal. Decoding shows they are simply the
next NUL-separated object names in a dense string table
(`BatchCleanupConfirmMessageBox`, `Login`, `profile`, `avatarButton`, ...), so
the six `lea` references to `avatarButton` are real. See
[components.md](components.md).

## Where the label strings come from

The binary's own logging tags yield **966 real function names**, which is a far
better starting point than guessing from call graphs.
`AccountFlowManager::setState`, `AccountFlowManager::showDisplayWindow_`,
`NxMainPresenterImpl::onAccountInit`,
`NxMainPresenterImpl::onAccountLoginStatusChanged` and
`NxMainPresenterImpl::onAccountLogout` are the account/avatar state machine, and
`NxMainWindow::notifyLoginWinPopup` is the window side of it. These tags cannot
be reached by any `lea` or absolute-pointer reference, so they are a starting
point for a debugger session rather than for static work.
