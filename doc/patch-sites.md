# Locating a patch site

Semantic locators, surviving a version update, and adding a patch.

A byte signature has to do two jobs at once: be *unique* in the image, and
*cover* the bytes the patch rewrites. Those goals fight — covering the rewrites
means wildcarding the call displacement or the stack slot, which destroys the
very bytes that told one site from its identical neighbours. The old answer was
`locate_rva`, an absolute address. It was unambiguous and it broke on every
rebuild: a 0x40-byte shift of the image invalidated 9 of the 9
`remove-components` sites.

So the two jobs are now separated. A **locator** answers *where is the
interesting code?* using facts that survive a rebuild; the signature only
**verifies** what the locator found:

```toml
[[patch]]
id = "menu-faq"
file = "nx_main/MuMuNxMain.exe"
locate = { kind = "string-ref", value = "mainFaqMenuItem", window = 0x100 }
signature = "48 8D 55 20 48 8B CF ?? ?? ?? ?? ?? 90 48 8B 8D"
expect    = "48 8D 55 20 48 8B CF E8 F1 9E E9 FF 90 48 8B 8D"
replace   = "48 8D 55 20 48 8B CF 90 90 90 90 90 90 48 8B 8D"
known_rvas = ["0x168d5f"]
```

The locator yields **anchor references**, not answers. Each reference is expanded
into candidate **sites** by scanning a bounded window for the signature, and the
patch resolves **only if exactly one (reference, site) pair exists**. That
conjunction is what makes otherwise-hopeless strings usable: `avatarButton` is
referenced from six places, `leftMuMuRemoteBtn` from three, and requiring the
anchor and the signature to agree collapses each to a single site. Every failure
mode — no reference, no reference with the signature nearby, several sites — is
fatal.

Locator kinds: `string-ref` (a `lea r64,[rip+disp]` whose target is the literal)
and `import-call` (a `call qword ptr [rip+disp]` resolving to a named import).

Requires the optional `capstone` dependency:

```sh
pip install 'mumu-patch[semantic]'
```

Without it, a patch that *asks* for a semantic locator fails closed with a clear
message. It never falls back to a weaker search, because a bare scan of a
deliberately-ambiguous pattern would resolve to whichever site came first.

Exactly one patch still uses `locate_rva`, and the reason is documented in
`no-integrity-punish.toml`: its predicate calls `WinVerifyTrust` through a
pointer resolved at run time, so the symbol is in no import table and no string
literal sits within reach. It fails closed, and `rebase` reports it as needing
manual work. `tests/test_robustness.py` pins both facts.

The device-side counterpart is the contrast that makes the exception legible:
`MuMuNxDevice.exe` runs the same check, but *its* version opens by calling
`QCoreApplication::applicationFilePath` — a plain import call — so it is found
with an `import-call` locator and needs no exception at all. Same trap, same
lever, and the only difference is whether the predicate hides its callee behind a
runtime-resolved pointer.

### Surviving a version update

`tests/test_robustness.py` measures this rather than asserting it. It shifts
every section by 0x1000 bytes — the model of "the vendor inserted code" — and
checks that every patch that is not deliberately build-specific resolves to
*exactly* the shifted address:

| | before | after |
| --- | --- | --- |
| `MuMuNxMain.exe` (shift +0x1000) | 3/12 | **12/12** |
| `MuMuNxDevice.exe` (shift +0x1000) | 0/9 | **9/9** |

Only one shift is exercised, and the assertion is exact tracking rather than
merely "a site was found". A semantic locator never consults an absolute address,
so if it tracks one shift it tracks any; a second delta re-ran the same
multi-second index build per binary to re-test a property that cannot vary with
it. The stronger assertion is what makes dropping the second delta free:
resolving to the *wrong* place now fails, where the old "did it resolve" check
would have passed it.

(The one `locate_rva` patch is excluded from the count and covered separately by
`test_the_documented_exception_still_fails_closed`, which asserts it refuses with
"different build" rather than mis-patching. Its device-side counterpart is *not*
excluded: it is located through an `import-call` locator, so it survives.)

Writing that device-side locator is what exposed a gap in the harness itself. The
shift moved the sections and the data directories but copied `.idata` verbatim,
leaving its `IMAGE_IMPORT_DESCRIPTOR` chain naming pre-shift addresses. Every
earlier locator was a `string-ref`, which only needs `.text` decoded, so nobody
noticed; the first `import-call` locator then failed and the failure looked like
a locator defect rather than a corrupt mutant. The mutation now relocates the
import tables too, and `test_shift_keeps_the_import_table_coherent` pins it by
asserting pefile parses the same number of symbols before and after.

When a MuMu update does break a profile, `rebase` re-resolves it:

```sh
niulai-patch rebase                  # report: unchanged / moved / needs manual work
niulai-patch rebase --write          # record the new RVAs
niulai-patch rebase --write --update-build   # also refresh the build fingerprint
```

`--write` edits only the `locate_rva`/`known_rvas`/`window` lines, line by line,
so the profiles' comments survive. A TOML round-trip would discard all of them,
and those comments are the most valuable thing in the files.

## Adding a patch

Patches are declarative TOML under `src/pe/patches/`:

```toml
[[patch]]
id = "my-patch"
description = "What it does"
file = "nx_main/MuMuNxMain.exe"
locate     = { kind = "string-ref", value = "mainFaqMenuItem", window = 0x100 }
signature  = "48 8D 15 ?? ?? ?? ?? 85 DB"   # ?? = wildcard
expect     = "48 8D 15 3B 4E 1B 01 85 DB"   # bytes the pristine file must have
replace    = "48 8D 15 CB 3E 13 01 85 DB"   # same length as the signature
known_rvas = ["0x4e512e"]
```

`expect` is always taken from the **pristine vendor binary**, never from the
file currently on disk — that file already has the profile applied, so a
displacement read back from it would record the patched value as the expected
one, and the patch would then look "already applied" on a fresh install while
silently doing nothing. `niulai-patch rebase` and the pristine copies under
`.backups/` are the two supported sources.

Three rules matter, all enforced at load time:

1. **Wildcard the bytes you rewrite.** A signature that pins the bytes it
   replaces stops matching once applied, so the patch becomes undetectable and
   `verify` reports it as lost. `Patch.validate()` rejects such patches with an
   explanatory error rather than letting them misbehave later.
2. **Keep `replace` the same length as `signature`**, so no instruction moves.
3. **Declare exactly one resolver.** `locate`, `locate_rva` and `anchor` are
   mutually exclusive; two on one patch would silently shadow each other.

Prefer a `locate` semantic locator. If a signature is genuinely unique on its
own, no resolver is needed. `locate_rva` and byte `anchor` pin one link's
layout and are the last resort — `tests/test_robustness.py` fails if a new one
appears without being added to its documented-exception set.

To find the string to anchor on, look for the log line or object name the code
uses near the site: `niulai-patch dbg --profile X --base <base>` prints live
addresses for a debugger session, and `analyze` shows which resolver each patch
uses.
