# Telemetry and reporting endpoints

Every reporting URL, the code that references it, and how it is redirected.

URLs recovered from `.rdata`, and the code sites that reference them.

| Endpoint | Purpose | RVA of the referencing `lea` |
| --- | --- | --- |
| `shence-api.mumu.163.com/sa?project=store_{prod,test}` | Sensors Analytics (神策) events | `0x4e512e` / `0x4e5127` |
| `event.sc.gearupportal.com/sa?project=mumu_player_{prod,test}` | event reporting | `0x4e4d6e` / `0x4e4d67` |
| `mumu.nie.netease.com/api/crashrpt` | crash report upload | `0xc9ceb8` |
| `sentry.netease.com/238`, `/394` | Sentry crash reporting | see note below |
| `feedback-system.webapp.163.com` | the 反馈 button target | — |
| `mumu.163.com/help/` | the 常见问题 button target | — |

The two "sensors" sites share one shape, confirmed by disassembly in a live
x64dbg session (module base `0x7FF6593F0000`):

```
lea  rax, [rip+disp]     ; 48 8D 05 <disp32>   -> the test URL
lea  rdx, [rip+disp]     ; 48 8D 15 <disp32>   -> the prod URL
test ebx, ebx            ; 85 DB
cmovnz rdx, rax          ; 48 0F 45 D0         -> sensors_debug != 0 -> test
mov  rcx, rsi            ; 48 8B CE
call qword ptr [...]
```

The patch rewrites **both** displacements to an empty string, in one 18-byte
window. Rewriting only the prod `lea` -- which is what the profile did before --
leaves the `cmovnz` free to select the live test endpoint on any machine with
`sensors_debug` set in the registry.

Each displacement was recomputed and asserted to resolve to the intended
address, rather than assumed:

```
shence    insn 0x4e5127 + 7 + 0x011b4e02 = 0x1699f30  (store_test URL)  ✓
          insn 0x4e512e + 7 + 0x011b4e3b = 0x1699f70  (store_prod URL)  ✓
gearup    insn 0x4e4d67 + 7 + 0x011b52b2 = 0x169a020  (player_test URL) ✓
          insn 0x4e4d6e + 7 + 0x011b52fb = 0x169a070  (player_prod URL) ✓
crashrpt  insn 0xc9ceb8 + 7 + 0x00a35261 = 0x16d2120  (crashrpt URL)    ✓
```

**The locators cannot anchor on the URLs.** This is forced, not stylistic: the
patch rewrites the very `lea` that references the URL, so after applying there is
no reference left for `resolve` to find -- `verify` reports the patch lost and a
re-run cannot locate the site. Both Sensors patches therefore anchor on the
registry key their accessor opens (`HKCU\Software\Netease\MuMuPlayer` for
`shence`, `...\MuMuNx` for `gearup`), which the patch does not touch. Each key is
a single `lea` reference in the image, so it is also unambiguous.

That failure mode is easy to miss because it only appears *after* a successful
apply, and the same trap was hit independently while writing the device-side
profile; `tests/test_profiles.py::test_main_telemetry_locators_survive_their_own_patch`
now pins it.

### The empty-string target

`EMPTY_RVA = 0x1619000` lies inside a NUL run in `.rdata` (272 bytes from that
point to the next non-zero byte). It is inert, mapped, read-only memory, so
pointing a string argument at it yields a valid empty C string. (The RVA is
per-binary — `MuMuNxDevice.exe` uses `0x1a5b115`, 267 bytes into a run of its
own.)

> Worth recording because the first attempt was wrong: setting the displacement
> to `0` does **not** produce an empty string. `lea rdx,[rip+0]` resolves to the
> *next instruction*, so the callee would receive live code bytes as a URL. The
> mistake was caught by asserting on the resolved bytes rather than trusting the
> arithmetic.
