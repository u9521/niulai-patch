# Replacing the desktop

Swapping MuMu's NetEase Lawnchair fork for a build from source.

```bash
# Show what would change
uv run niulai-patch lawnchair --dry-run

# Write the bundled build into the image
uv run niulai-patch lawnchair --yes

# Or use an APK of your own
uv run niulai-patch lawnchair --apk /tmp/Lawnchair-testkey.apk
```

MuMu 15 ships a NetEase fork of Lawnchair (`app.lawnchair`, 41.3 MiB, phoning
home to `sentry.netease.com`). The bundled replacement is 17.4 MiB and is a
*universal* APK — it includes `lib/x86_64/`, which is the ABI this guest
reports. Both use the application id `app.lawnchair`, so this replaces the fork
rather than installing alongside it, and being smaller it fits the space the
fork already occupies.

The fork's ART artefacts (`oat/x86_64/Lawnchair.odex`, 80 MB, and
`Lawnchair.vdex`) describe the fork's code and are removed with it; leaving them
would have the runtime load stale compilation units against different bytecode.

### Why the replacement is a checked-in build

The APK in `src/prebuilts/` is **not** the published upstream release. Upstream
crashes on this platform in two independent ways, and both are source-level
defects that no amount of post-processing the release can repair:

* `Task.java` names
  `android.app.ActivityManager$RecentTaskInfo$PersistedTaskSnapshotData`, a type
  Android 15 does not have. ART's class verifier resolves every type a method
  mentions, so it rejects the whole `Task` class and the Recents screen crashes
  with `VerifyError`.
* Upstream gets `IRecentsAnimationRunner` from a `compileOnly` framework jar, so
  nothing is packaged. MuMu defines those interfaces under
  `com.android.wm.shell.recents` instead, and the process dies with
  `NoClassDefFoundError` before the Recents gesture can work at all.

So the launcher is a **build from source** with both fixed, signed with the
**AOSP testkey**. The project keeps the diffs and the build recipe in
[patches/](../patches/); the built artifact is committed so that
`niulai-patch lawnchair` works without an Android SDK. Its hash is pinned in
`lawnchair.py` and verified before anything is written.

### Iterating with `adb install`

Rewriting the 1.8 GB image for every experiment is slow. Because the installed
launcher carries the AOSP testkey, any build signed with that same key can be
pushed over it in seconds:

```bash
./tools/sign-test-apk.sh Lawnchair.apk /tmp/Lawnchair-test.apk
adb connect 127.0.0.1:16384
adb install -r /tmp/Lawnchair-test.apk
```

Android refuses a same-package update signed with a different key, so the shared
key is what makes this possible. Because signing changes the APK's digest,
writing a signed build into the image needs `--allow-unknown-installed`; see
[patches/README.md](../patches/README.md) for the full build and signing loop.
