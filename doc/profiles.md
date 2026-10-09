# Profiles

What each patch profile changes, and what it costs.

Every profile that patches a binary declares the integrity profile for that
binary as a `requires` dependency, so the two below are pulled in automatically
and never have to be passed by hand.

### `no-integrity-punish` / `no-device-integrity-punish`

The two binaries each verify their own Authenticode signature at startup and
treat "unsigned" as tampering — which is exactly what a patched build looks like,
because the tool strips the signature. The punishment is not a dialog: it spawns
eleven detached threads, each looping forever over ten million `sqrt`
accumulations, so a full core is pegged for the life of the process.

| Profile | Binary | Check | Patch site |
| --- | --- | --- | --- |
| `no-integrity-punish` | `nx_main/MuMuNxMain.exe` | `sub_1407198B0` | `0x7198ea` |
| `no-device-integrity-punish` | `nx_device/15.0/shell/MuMuNxDevice.exe` | `sub_1408DEF90` | `0x8defca` |

Both checks have the same shape — `if (!A || !B)` — so both patches do the same
thing: NOP out the first guard and turn the second into an unconditional jump to
the check's own clean-exit path. Defusing only one is a no-op, because a stripped
binary fails `A` and the first guard reaches the punishment block on its own.

The check is not disabled, only disarmed: it still runs, still calls
`WinVerifyTrust` and still reads the signer name; it just no longer acts on a
negative result.

Disarming the punishment stops the CPU burn and the input corruption, but **not
the reporting**: the punishment block also queues a `MainProgramCrackDetection`
statistics event. That half is `no-device-telemetry`, below.

### `no-telemetry`

Retargets the reporting endpoints in `nx_main/MuMuNxMain.exe` to an empty string,
so reporting has nowhere to post:

| Patch | Endpoint(s) | Site |
| --- | --- | --- |
| `shence-endpoint` | `shence-api.mumu.163.com/sa?project=store_{prod,test}` | `0x4e5127` |
| `gearup-endpoint` | `event.sc.gearupportal.com/sa?project=mumu_player_{prod,test}` | `0x4e4d67` |
| `crashrpt-endpoint` | `mumu.nie.netease.com/api/crashrpt` | `0xc9ceb8` |

Each is a same-length rewrite of a `lea` displacement, so no instruction moves
and nothing relocates. See [analysis/telemetry.md](analysis/telemetry.md) for the
disassembly and for how the empty-string target was chosen.

The two Sensors accessors pick their endpoint at run time from the
`sensors_debug` registry value:

```
lea rax, [test URL]      ; 48 8D 05 <disp32>
lea rdx, [prod URL]      ; 48 8D 15 <disp32>
test ebx, ebx
cmovnz rdx, rax          ; sensors_debug != 0 -> use the test URL
```

Both patches rewrite **both** `lea`s in one 18-byte window, so neither branch can
resolve to a live endpoint. (`crashrpt-endpoint` has no `cmovnz` and so no second
branch.)

The locators anchor on each function's **registry key**, not on the URL. That is
a requirement, not a style choice: the patch destroys the URL reference it
rewrites, so a URL anchor resolves on the pristine file and then fails on the
patched one — `verify` would report the patch lost and a re-run could not find
the site. Each accessor opens its own key
(`HKCU\Software\Netease\MuMuPlayer` for `shence`, `...\MuMuNx` for `gearup`),
which the patch never touches.

### `no-device-telemetry`

The `MuMuNxDevice.exe` counterpart, and the other half of the tamper story: it
stops the analytics reporting, including the `MainProgramCrackDetection` event a
patched build would otherwise send.

Every statistics event from this binary goes to Sensors Analytics, and the host
comes from `UrlManager`, which picks between a test and a production endpoint
based on the `sensors_debug` registry value:

| Patch | Function | Registry key | Site |
| --- | --- | --- | --- |
| `sensors-host` | `UrlManager::getSensorsHost` | `HKCU\Software\Netease\MuMuPlayer` | `0x78eeb7` |
| `nxsensors-host` | `UrlManager::getNXSensorsHost` | `HKCU\Software\Netease\MuMuNx` | `0x78eaf7` |

`getNXSensorsHost` is the one the device window reports through —
`NxDevicePresenterImpl::init` hands its result to the statistics service.

Each patch rewrites **both** the test and production `lea` in one 18-byte window,
so the `cmovnz` that selects between them has nothing live to select. Like
`no-telemetry` above, the locators anchor on the registry key rather than the URL
— the patch destroys the URL reference it rewrites, so a URL anchor would stop
resolving the moment the patch was applied.

There is no config switch for this: the 82 `feature.*.enabled` keys contain
nothing telemetry-related, and `sensors_debug` only chooses *which* endpoint is
used. Only the two host strings are redirected — the account, store and
cloud-phone APIs are untouched.

### `remove-components`

Removes UI elements rather than hiding them. Currently:

| Patch | Removes | Site |
| --- | --- | --- |
| `avatar-button` | the account avatar button in the title bar | `0x14afc1` |

The widget is still constructed, named and connected — only the
`QBoxLayout::addWidget` that puts it in the title bar is replaced with NOPs, so
it is never laid out, never painted and occupies no space. The construction
cannot simply be skipped: `setObjectName` dereferences `this` with no null
check and two `QObject::connect` calls follow, so a missing widget would crash.

**Verified in a real run**: a patched copy started normally and the avatar was
gone.

Because adjacent title-bar widgets compile to byte-identical instruction
sequences, no signature can separate them on its own. Each patch therefore
locates its site by the widget's own object-name literal (`mainFaqMenuItem`,
`leftMuMuRemoteBtn`, …), which is unique in the image, and the signature
verifies the result. See [patch-sites.md](patch-sites.md).

### `device-ui`

The `MuMuNxDevice.exe` counterpart: it strips the side-panel menu entries and the
startup ad carousel from a running device's window, rather than from the
launcher. Currently:

| Patch | Removes / suppresses | Site |
| --- | --- | --- |
| `splash-carousel` | the promotional carousel painted during boot | `0x2a79ec` |
| `splash-logo` | the startup logo splash | `0x2a1e1d` |
| `splash-ad-download` | the campaign-image download path | `0x102379a` |
| `menu-remote-control` | the 远程控制 menu entry | `0x254f9e` |
| `menu-acceleration` | the 加速服务 menu entry | `0x25502b` |
| `menu-dynamics-tab` | the 动态栏 side-panel menu entry | `0x255e76` |
| `gametools-no-autopopup` | the game-tools panel auto-opening | `0x59ec5e` |
| `gametools-no-config-fetch` | the game-tools config fetch | `0xbcbff0` |

It declares `requires = ["no-device-integrity-punish"]`, because patching this
binary arms the device-side copy of the self-integrity check — see
the `no-integrity-punish` / `no-device-integrity-punish` section above and
[analysis/device-window.md](analysis/device-window.md).
