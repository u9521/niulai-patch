# Making the patches survive a version update

Semantic locators, build identity, and declared dependencies.

### The problem, stated as a number

Every profile originally located its site one of three ways: a unique byte
signature, a literal byte `anchor`, or `locate_rva` (an absolute address). The
last two encode one particular link's layout. Eighteen of twenty-one patches
used `locate_rva`, because the compiler emits identical instruction sequences
for adjacent widgets and no signature could separate them.

The cost was measured rather than argued. `tests/test_robustness.py` shifts every
section's RVA and raw offset by 0x1000 bytes — the model of "the vendor inserted
code" — and asserts that every patch that is not deliberately build-specific
resolves to *exactly* the shifted address:

| target | shift | before | after |
| --- | --- | --- | --- |
| `MuMuNxMain.exe` | +0x1000 | 3/12 | 12/12 |
| `MuMuNxDevice.exe` | +0x1000 | 0/9 | 9/9 |

Two deliberate reductions, both made after measuring rather than guessing:

* **One delta, not two.** A semantic locator never consults an absolute address,
  so a property that holds for one shift holds for any. The 0x40 case re-ran the
  same multi-second capstone index build per binary to re-test something that
  cannot vary with the shift size.
* **Exact tracking, not "it resolved".** The assertion is that every patch lands
  on *exactly* the shifted address. A locator that resolves to the wrong place
  fails here, where a "did it resolve" count would pass it. That stronger
  assertion is what makes a single delta sufficient rather than a coverage loss.

(The excluded patch is `integrity-check-clean-exit`; see "the one exception"
below. Its device-side counterpart, `device-integrity-check-clean-exit`, is *not*
excluded — it is found through an `import-call` locator.)

### A gap the first `import-call` locator exposed

`shift_sections` moves each section's RVA and raw offset, and every data
directory that points into the image. That is enough for a `string-ref` locator,
which only needs `.text` decoded — so for as long as all twenty locators were
`string-ref`, a real incoherence in the mutant went unnoticed.

An `IMAGE_IMPORT_DESCRIPTOR` is itself made of RVAs, and so is every thunk array
it points at. The mutant copied those bytes verbatim, leaving them naming
pre-shift addresses. `pefile` walks that chain by RVA, so it parsed 513 of 4318
imports and the new `import-call` locator failed — which reads exactly like "this
locator is not shift-robust" and is not.

The mutation now relocates the import tables too, and
`test_shift_keeps_the_import_table_coherent` asserts the symbol count is
identical before and after, at both shifts. A real vendor rebuild regenerates the
import table, so advancing those RVAs is the more faithful model: leaving them
stale was not a relocation but a corrupt image.

### Why `expect` was not the bug

An earlier reading of this code concluded that `expect` was defeating the
signature's wildcards, because `apply_patch_to_bytes` compares the whole window
against it. That is true of the mechanism but wrong about the consequence: all
21 patches carry an `expect` that pins bytes the signature *deliberately*
wildcards. `expect` is therefore the primary verifier, not a redundant second
check, and masking it by the signature would have deleted the only check on the
bytes being overwritten. It is unchanged.

The fragility was in the *locators*, and that is all that changed.

### The fix: separate finding from verifying

A locator answers "where is the interesting code?" using facts that survive a
rebuild. The signature then *verifies* the site rather than having to find it.

A locator yields **anchor references**, not answers. Each reference expands into
candidate **sites** by scanning a bounded RVA window for the signature, and the
patch resolves **only if exactly one (reference, site) pair exists**. The
conjunction is what makes a non-unique string usable:

| literal | references in image | sites resolved |
| --- | --- | --- |
| `avatarButton` | 6 | 1 |
| `leftMuMuRemoteBtn` | 3 | 1 |
| `leftCloudPhoneBtn` | 2 | 1 |
| `mainFaqMenuItem` | 1 | 1 |

Verified for all 20 migrated sites: each locator lands on exactly the RVA the
profile recorded, and on the shifted image, exactly `shift` bytes away from it.

### Two implementation traps worth recording

**Linear disassembly does not work here.** The obvious implementation is one
`md.disasm` pass per executable section. On `MuMuNxMain.exe` that desyncs as
soon as it reaches data embedded in `.text` — jump tables, vtables, string
blobs — and capstone stops at the first undecodable byte, at RVA `0x40e1c`. The
sweep found **1,057** string references where the image contains **24,147**, and
silently missed every site the module exists to find. `skipdata=True` is not a
fix: it resynchronises one byte at a time and produced ten million bogus
"instructions" for the same section. Scanning for the handful of opcode shapes
that can encode the references, and decoding each candidate individually, is
immune to desync — a candidate that is really mid-instruction simply fails to
decode or decodes to the wrong shape.

**Window scans must walk RVA space, not raw bytes.** A window can straddle a
section boundary, and a raw slice would splice the end of `.text` onto the start
of `.rdata` — two regions that are not adjacent in memory. The first version of
the robustness harness had exactly this bug and produced false negatives. A
candidate is now accepted only when its whole extent maps to a contiguous run of
file bytes, and `test_window_scan_does_not_cross_a_section_boundary` pins it.

### The one exception

`integrity-check-clean-exit` keeps `locate_rva`. Its predicate calls
`WinVerifyTrust` through a pointer resolved at run time, so the symbol appears in
no import table at all (verified: `CRYPT32.dll` is imported only for
`CertGetNameStringW`, `CertFindCertificateInStore`, `CryptQueryObject`,
`CryptMsgGetParam` and similar), and no string literal sits within 0x800 bytes.
There is nothing to anchor on.

It fails closed — after a shift it reports "bytes at recorded RVA ... do not
match the signature, so this is a different build" — and
`tests/test_robustness.py::test_the_documented_exception_still_fails_closed`
asserts that, so it cannot regress into silently patching the wrong place.

Its device-side counterpart is the interesting contrast. `MuMuNxDevice.exe` runs
the same check with the same shape (`!A || !B`, two guards, the same clean-exit
lever), but *its* check opens by calling `QCoreApplication::applicationFilePath`
— a plain import call — and the patched window begins 0x15 bytes later. So that
one is located from a fact that survives a rebuild and needs no exception at all.
The difference is not a matter of effort; it is that one predicate hides its
callee behind a runtime-resolved pointer and the other does not.

`applicationFilePath` is called from seven places in the device image, so the
anchor alone does not discriminate — the signature does. All seven are checked
and exactly one has the window within 0x40 bytes, which is why the locator's
window is deliberately narrow.

### Build identity

`pe/buildid.py` computes a 16-hex-character fingerprint over the **non-`.text`
sections** plus `TimeDateStamp` and `SizeOfImage`. A whole-file hash would be
useless: the target is the file being patched, so it would change the moment the
first patch landed. Every patch writes into `.text` only, and `strip_signature`
touches only the trailing certificate blob, so the fingerprint is identical
before and after — verified against the pristine and fully-patched binaries, and
pinned by `test_fingerprint_survives_our_own_patching`.

It is a diagnostic, never a gate: a mismatch prints "profiles were authored
against build X, this is build Y" and the patch proceeds. The per-patch checks
remain the real gate.

### `requires`

Patching `MuMuNxMain.exe` strips its Authenticode blob, which arms the
self-integrity check that spawns CPU-burning threads (see
[device-window.md](device-window.md)). `no-telemetry` and `remove-components`
declare `requires = ["no-integrity-punish"]`, the CLI applies required profiles
in the same pass, and a test asserts that *every* profile targeting that binary
declares the dependency. Declaring it is what keeps the companion from having to
be remembered at the command line.

### The same trap in `MuMuNxDevice.exe`

`MuMuNxDevice.exe` carries its **own** copy of the check, at `sub_1408DEF90` —
the same `!A || !B` shape as `MuMuNxMain.exe`'s, with unrelated addresses. On a
patched build it pegs a full core, which is why `device-ui` must declare
`requires = ["no-device-integrity-punish"]`:

```
QCoreApplication::applicationFilePath(v9);
if ( !sub_14002B3FA(*a1, v9) || !sub_14003644E(*a1, v9) )
{
    ... decode obfuscated base64 strings, log them ...
    sub_14001EB2D();   // RandomLagPunisher: 11 threads, each a sqrt loop
    sub_140037CC7();   // RandomInputLossPunisher
    sub_140012396();   // RandomMouseOffsetPunisher
    sub_140027D72();
    sub_140010A91();
}
```

The RTTI type descriptors name the punishers outright
(`.?AVRandomLagPunisher@@`, `.?AVRandomInputLossPunisher@@`,
`.?AVRandomMouseOffsetPunisher@@`), which is what identifies this as a
deliberate punishment rather than a runaway loop. The predicates are the same two
halves: `sub_14002B3FA` wraps `WinVerifyTrust` and returns TRUE unless the file is
*unsigned*; `sub_14003644E` compares a digest of the file against a base64
constant. A stripped binary fails the first, and `!A || !B` is enough.

`sub_14001EB2D` → `sub_1408E1380` spawns one detached thread running
`sub_1408DC9A0` → `sub_1408DED60`, whose `++v2 >= 11` bound is where the eleven
threads come from. It joins them, and the join never returns, because each runs
`sub_1408DDEF0` — an unconditional infinite loop of 10 million `sqrt`
accumulations followed by a sleep.

What the live process looked like, which is how this was found rather than
inferred:

* `MuMuNxDevice.exe` (pid 21072): 8051 s of CPU and 339 threads, on a 32-core
  host, against ~8 s for `MuMuNxMain.exe` and under 1 s for the service
  processes.
* Exactly eleven threads carried the burn, each with ~617 s of **user-mode** CPU
  and ~0 s of kernel time.
* Sampled over 30 s the process ran at a steady **1.00 core**, and the eleven
  threads accounted for all of it at ~9–10% each — a duty-cycled load, not eleven
  pegged cores. The lifetime total is higher than 1 core × uptime, which fits the
  second (escalating) trigger loop below.
* A RIP sample of the hottest threads landed repeatedly inside the sqrt loop at
  RVA `0x8ddf21` / `0x8ddf35` / `0x8ddf3b` / `0x8ddf41`, with the remaining
  samples in `ntdll`'s wait path — "compute, sleep, repeat".

The lever is identical to the main-binary one, and so is the reasoning: both
branches must be defused, because patching only guard 2 is a no-op when a
stripped binary fails guard 1. `no-device-integrity-punish` carries the patch,
`device-ui` declares `requires = ["no-device-integrity-punish"]`, and the two
integrity profiles are asserted to target different binaries so a copy-paste
between them cannot survive review.

#### What the two predicates actually are

`sub_1408E2B60` (predicate A) wraps `WinVerifyTrust` with `WTD_UI_NONE` and
`WTD_REVOKE_NONE`, so it shows no dialog and fetches no CRL/OCSP — it is a purely
local check. It returns TRUE for anything that is signed at all, *including* a
file whose bytes no longer match its signature (`TRUST_E_BAD_DIGEST` is not
`TRUST_E_NOSIGNATURE`). That gap is why predicate B exists.

`sub_1408E2C60` (predicate B) is **not** a digest check. It calls
`sub_140034086` → `sub_1408E18D0`, which:

* `CryptQueryObject(CERT_QUERY_OBJECT_FILE, path, CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED, …)`
  to open the embedded Authenticode blob;
* `CryptMsgGetParam(hCryptMsg, CMSG_SIGNER_INFO_PARAM, …)` for the signer info;
* `CertFindCertificateInStore(hCertStore, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0, CERT_FIND_SUBJECT_CERT, …)`
  for the signer's certificate;
* `CertGetNameStringW(pCertContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, …)` for the
  publisher's display name.

`sub_1408E2C60` then compares that name against an obfuscated constant. So B is a
**publisher pin** — "is this signed by the expected vendor?" — and the pair reads
as: A catches tampering, B catches re-signing with someone else's certificate.
Both fail closed on an unsigned file (A directly, B because `CryptQueryObject`
fails and yields an empty string).

#### The punishment is more than a CPU burn

Four things start, not one. The CPU burner is `sub_14001EB2D`, and its burn is
*duty-cycled* — ten million `sqrt` accumulations followed by a sleep — which is
why each thread sits near 10% of a core and the eleven together come to about one
core, rather than eleven.

The other three are Qt native event filters, and all three are **randomised per
event** (`std::_Random_device`-seeded mt19937, gating on `100 * rand()`):

| installer | class | eventFilter | effect |
| --- | --- | --- | --- |
| `sub_140037CC7` | `RandomLagPunisher` | `sub_1408E40A0` | randomly stalls the event loop |
| `sub_140012396` | `RandomInputLossPunisher` | `sub_1408E3F30` | randomly swallows keyboard/mouse messages |
| `sub_140027D72` | `RandomMouseOffsetPunisher` | `sub_1408E4340` | randomly shifts mouse coordinates |

The input-loss filter gates on message type: `sub_1408E2ED0` matches keyboard
messages (`WM_KEYDOWN` 0x100 – `WM_SYSCHAR` 0x106) and `sub_1408E2F90` matches
mouse messages (`WM_MOUSEMOVE` 0x200 – `WM_MOUSEHWHEEL` 0x20E). So a tampered
build does not merely burn a core — it also drops keystrokes and clicks and moves
the pointer, which is what makes it feel broken rather than busy.

Finally, the punishment **reports**. `sub_140010A91` → `sub_140F7C7F0` queues
`sub_140F7B950`, which sends a statistics event named `MainProgramCrackDetection`
(`module_name = "mainProgram"`) through the NemuStatistics service. It is
rate-limited by a QSettings key holding a `QDate`, so it reports at most once a
day. Its sibling `sub_1410F4F90` reports `MainProgramAuthVerify` with
`status_code` / `error_code` / `failure_reason` / `error_msg`. Disarming the
punishment therefore stops the CPU burn and the input corruption but not the
telemetry — see the next section for that half.

#### Silencing the reporting (`no-device-telemetry`)

There is no configuration switch for this. The 82 `feature.*.enabled` keys this
binary understands contain nothing telemetry-related — a scan for
`feature.*(stat|report|track|log|sensor|shence|data|upload|event)*.enabled`
returns nothing — and the `sensors_debug` registry value only chooses *which*
endpoint is used, not whether reporting happens. The endpoints are the lever.

Every statistics event from this binary goes to Sensors Analytics, and the host
is chosen by `UrlManager`:

| function | registry key | RVA |
| --- | --- | --- |
| `UrlManager::getNXSensorsHost` (`sub_14078EA00`) | `HKCU\Software\Netease\MuMuNx` | `0x78eaf7` |
| `UrlManager::getSensorsHost` (`sub_14078EDC0`) | `HKCU\Software\Netease\MuMuPlayer` | `0x78eeb7` |

`getNXSensorsHost` is the one the device window reports through: its result is
what `NxDevicePresenterImpl::init` (`sub_140E0BDB0`) hands to the statistics
service before firing its `statistics.ready` event, and what `sub_14124E9A0`
passes to the same service.

Each function selects between two endpoints at run time:

```
lea rax, [test URL]      ; 48 8D 05 <disp32>
lea rdx, [prod URL]      ; 48 8D 15 <disp32>
test ebx, ebx
cmovnz rdx, rax          ; sensors_debug != 0 -> use the test URL
mov rcx, rsi
call QString::operator=(char const*)
```

The fix rewrites **both** `lea` displacements to point at an empty byte
(`0x1a5b115`, inside a 267-byte NUL run in `.rdata`), in one 18-byte window per
function, so the `cmovnz` has nothing live to select. The `no-telemetry` profile
for `MuMuNxMain.exe` was later given the same treatment.

Two details worth recording, because both cost time to find:

* **The locators cannot anchor on the URLs.** This is forced rather than
  stylistic, and the same trap appeared independently on the main binary: the
  patch rewrites the very `lea` that references the URL, so once applied there is
  no reference left for `resolve` to find — `verify` reports the patch lost and a
  re-run cannot locate the site at all. The registry keys are opened by exactly
  one function each and are untouched by the patch, which makes them both unique
  and durable. Verified: each is a single `lea` reference in the whole image, and
  each still resolves after the patch is applied.
* **The empty target is per-binary.** `0x1a5b115` here; the
  `MuMuNxMain.exe` profile uses `0x1619000`. `.rdata` layout differs, so the RVA
  cannot be shared.

Scope: only the two host strings are redirected. The registry reads, the logging,
the statistics machinery, and every functional endpoint in the binary (account,
store, cloud-phone) are untouched — this silences event reporting, not the
product's functional network traffic.

#### How it is triggered, and why it is sometimes invisible

Both threads are queued from `ApplicationImpl::run` (`sub_140149480`) at startup,
each via `QMetaObject::invokeMethodImpl(…, Qt::QueuedConnection)`:

* `0x14014a93c` → `sub_140021503` → `sub_140143ED0` → `sub_14001EED4` →
  `sub_1408E6030` → `InitOnce(0x1420DE008)` → `_beginthreadex(sub_1408DCA70)` →
  **`sub_1408DEF90`**, the check;
* `0x14014a9ca` → `sub_14000FC90` → `sub_140143F20` → `sub_1400081C0` →
  `sub_1408E6090` → `InitOnce(0x1420DE028)` → `_beginthreadex(sub_1408DC7A0)` →
  `sub_1408E5F30` → `sub_1408DC8B0` → **`sub_1408DDF80`**, a second, independent
  loop that re-spawns all four punishments every ten counted "errors" with a
  random sleep between iterations.

That second loop matters for anyone debugging this: it means the punishment can
escalate and repeat over a process's lifetime, and it is a *separate* trigger
from the check.

Four reasons the burn can be absent or look absent:

1. **It only fires when the check fails.** A pristine, signed binary passes both
   predicates and is never punished.
2. **It is per-binary.** Patching `MuMuNxMain.exe` does not arm
   `MuMuNxDevice.exe`'s check, which is exactly why `no-integrity-punish` did
   nothing for the device process.
3. **It is per-device-instance.** `MuMuNxDevice.exe` runs as
   `--vm MuMuPlayer-15.0-0`, one process per device window. With no device open
   there is no process to burn; closing the window makes the symptom vanish while
   `MuMuNxMain.exe` keeps running.
4. **The burn is duty-cycled**, so per-thread CPU% fluctuates and a short look at
   Task Manager can read as "sometimes".
