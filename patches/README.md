# Building Lawnchair for Android 15 (SDK 35)

The launcher in MuMu's system image is a **build from source**, not a patched
binary, signed with the **AOSP testkey**. This directory holds the source diff
and the build recipe; the resulting APK is committed at
`src/prebuilts/Lawnchair-15.0.0-beta3.0-mumu15.apk` and is what
`niulai-patch lawnchair` installs.

## Why the source and not a dex patch

Upstream Lawnchair is compiled against a platform newer than the one MuMu ships.
`Task.java` names
`android.app.ActivityManager$RecentTaskInfo$PersistedTaskSnapshotData`, a type
that does not exist on Android 15, in two ways:

* as the declared type of `Task.lastSnapshotData`;
* as the platform field `RecentTaskInfo.lastSnapshotData`, which this SDK does
  not have either.

ART's class verifier resolves every type a method mentions, so it rejects the
whole `Task` class:

```
java.lang.VerifyError: Verifier rejected class
    com.android.systemui.shared.recents.model.Task
  ... not instance of 'Unresolved Reference:
      android.app.ActivityManager$RecentTaskInfo$PersistedTaskSnapshotData'
```

`Task` is constructed while the task list loads, so the Recents screen crashes
with it.

Rewriting the *field declarations* to `java.lang.Object` in the dex is not
enough, and neither is an `SDK_INT` guard: the reference has to be gone from the
code. Doing that in dex bytecode means editing instructions; doing it in the
source is a five-line change that a compiler then gets right.

## Why Recents also needs an AIDL shim

The `Task` fix above stops the Recents *screen* from crashing once it is
already open. It does not make the Recents *gesture* work, and the second patch
is what does.

MuMu 15's `framework.jar` is missing two AIDL classes that upstream Lawnchair
links against:

```
android.view.IRecentsAnimationRunner      absent from framework.jar
android.view.IRecentsAnimationController  absent from framework.jar
```

The platform moved both to `com.android.wm.shell.recents` before the release
MuMu shipped, and MuMu's SystemUI implements the *newer* names: its
`IRecentsAnimationController` handles transactions 1–7 and nothing else.

Upstream compiles against `prebuilts/libs/framework-15.jar`, which supplies the
old names as a **`compileOnly`** dependency — they are on the javac classpath
but are deliberately not packaged in the APK. So the built dex contains

```
Landroid/view/IRecentsAnimationRunner$Stub;   referenced, defined nowhere
```

and ART resolves every type a class mentions when it verifies it. The failure
lands while verifying `ActivityManagerCompatVV`:

```
java.lang.NoClassDefFoundError: Failed resolution of:
    Landroid/view/IRecentsAnimationRunner$Stub;
  at app.lawnchair.compatlib.fifteen.QuickstepCompatFactoryVV.getActivityManagerCompat
  at ... TaskStackChangeListeners$Impl.addListener
  at ... RecentsAnimationDeviceState.<init>
  at ... TouchInteractionService.onCreate
```

`TouchInteractionService` dying in `onCreate` is the whole symptom: the
`OverviewCommandHelper` command queue never sees `onTransitionComplete`, fills
to its cap of 3, and every later APP_SWITCH is dropped with

```
the pending command queue is full (3). command not added: 4
```

The patch adds the two interfaces as hand-written sources under
`src/android/view/`. They keep the **AOSP 15 class names** — so every existing
`import android.view.IRecentsAnimation*` still compiles and links — while
`DESCRIPTOR` and the transaction numbers come from MuMu's SystemUI:

| interface | method | transaction |
| --- | --- | --- |
| `IRecentsAnimationRunner` | `onAnimationCanceled` | 2 |
| | `onAnimationStart` | 3 |
| | `onTasksAppeared` | 4 |
| `IRecentsAnimationController` | `screenshotTask` | 1 |
| | `setFinishTaskTransaction` | 2 |
| | `finish` | 3 |
| | `setInputConsumerEnabled` | 4 |
| | `setWillFinishToHome` | 5 |
| | `detachNavigationBarFromApp` | 6 |
| | `handOffAnimation` | 7 |

A hand-written shim is required rather than AIDL: an `.aidl` file derives
`DESCRIPTOR` from its `package`, and here the package (`android.view`) and the
wire name (`com.android.wm.shell.recents.*`) deliberately differ.

The remaining five controller methods have no transaction on this platform, so
the proxy answers them locally instead of sending a call the server would not
recognise: four are no-ops and `removeTask` returns `false`.

This matches what the stock NetEase fork does — it bundles the same two classes
with the same descriptors, which is how the shipped launcher works at all.

## The second half: the shell publishes its binders under different names

Fixing the AIDL classes stops the crash but does *not* make the gesture work.
With the shim in place `TouchInteractionService` survives, yet pressing the
Recents key still left the launcher behind the foreground app and logged

```
OverviewCommandHelper: switching via recents animation - onGestureStarted
OverviewCommandHelper: executeNext ... result: false
```

and then nothing — no `onTransitionComplete`, ever.

The cause is one level up, in how the two sides name the binders they exchange.
`ShellController` builds the init bundle by walking its external-interface map
and calling `bundle.putBinder(key, binder)` with whatever key each controller
registered under:

* **AOSP** (`ShellSharedConstants` in the wmshell sources) registers them as
  `extra_shell_pip`, `extra_shell_recent_tasks`, …;
* **MuMu 15's SystemUI** registers them by AIDL descriptor —
  `com.android.wm.shell.common.pip.IPip`,
  `com.android.wm.shell.recents.IRecentTasks`, … .

Not one `extra_shell_*` key except `extra_shell_can_hand_off_animation` exists
in MuMu's SystemUI, so every `bundle.getBinder(KEY_EXTRA_SHELL_*)` returned
`null`. For Recents this is fatal in a way that is easy to miss:
`SystemUiProxy.startRecentsActivity` begins

```java
if (mRecentTasks == null) {
    ActiveGestureLog.INSTANCE.addLog("Null mRecentTasks", RECENT_TASKS_MISSING);
    return false;
}
```

so the call was refused before it reached SystemUI, and every further
`OverviewCommandHelper` command piled up behind the one that never completed.

`TouchInteractionService.onInitialize` now looks the binder up under the
descriptor first and falls back to the AOSP key, so it works against either
SystemUI. The helper is deliberately a two-key lookup rather than a rewritten
constant: the value is a wire format agreed with whatever SystemUI is running,
not a property of the SDK level.

This is also why the stock fork has no `extra_shell_recent_tasks` string
anywhere in its dex — it was built against MuMu's naming, not AOSP's.

With both fixes the full path runs and Recents opens:

```
OverviewCommandHelper: adding command type: 4
RecentsView: setRecentsAnimationTargets - recentsAnimationController:
    com.android.quickstep.RecentsAnimationController@dfb2b7d
OverviewCommandHelper: switching via recents animation - onTransitionComplete
OverviewCommandHelper: scheduleNextTask called
OverviewCommandHelper: executeNext - mPendingCommands is empty
```

## Build

```bash
git clone --depth 1 --branch v15.0.0-beta3.0 \
    https://github.com/LawnchairLauncher/lawnchair.git lawnchair
cd lawnchair
git submodule update --init --recursive --depth 1
git apply /path/to/lawnchair-sdk35-recents.patch
git apply /path/to/lawnchair-mumu15-recents-shim.patch

export ANDROID_HOME=/path/to/android-sdk        # needs platform 36.1 + build-tools 36.1.0
./gradlew -Duser.home=/tmp/lc-build/home :assembleLawnWithQuickstepGithubRelease
```

The variant matters: `lawnWithQuickstepGithub` is the one that produces
`app.lawnchair` with the Quickstep recents implementation, which is what the
shipped launcher is.

Two things about the environment, both learned the hard way:

* **`-Duser.home` is required** if the real home is not writable. The release
  build runs `validateSigning…`, which creates `~/.android/debug.keystore`;
  pointing `user.home` at a scratch directory keeps that out of the way.
  `ANDROID_USER_HOME` is *not* a substitute — AGP 9 fails to create its
  locations service when it is set.
* **`build-tools 36.1.0`** is required by the project (`buildToolsVersion
  "36.1.0"`), which is newer than the 36.0.0 that ships with many SDK
  installs. It is a direct download:
  `https://dl.google.com/android/repository/build-tools_r36.1_linux.zip`.

The result is a drop-in replacement. Before the shim the build came out
17,314,011 bytes against the published release's 17,314,003, with the same 1,813
zip entries and the same four ABIs, so the `Task` change really was the only
difference from the release. With the shim it grows to 17,456,572 bytes, because
the two interfaces and their stubs are now part of the dex.

That final figure is what is committed as
`src/prebuilts/Lawnchair-15.0.0-beta3.0-mumu15.apk` (SHA-256
`d88613d2384f9ac846dc9140484e1b6efe5fd0752b9cddf72bc07d3cfef009e5`), and it is
what `niulai-patch lawnchair` writes. The hash is pinned in `lawnchair.py` and
re-checked before any byte is written. Rebuilding from these patches should
reproduce it; if it does not, the build environment differs and the pinned hash
will say so rather than silently installing something else.

## Sign

With the AOSP testkey (`CN=Android, OU=Android, O=Android`, SHA-256
`a40da80a59d170caa950cf15c18c454d47a39b26989d8b640ecd745ba71bf5dc`):

```bash
apksigner sign \
  --key testkey.pk8 --cert testkey.x509.pem \
  --v2-signing-enabled true --v3-signing-enabled true \
  --out Lawnchair-testkey.apk Lawnchair.15.Dev.*.github.release.apk
```

The keys come from AOSP, `build/make/target/product/security/`. They are
public by design — every AOSP build uses them — which is exactly what makes
them useful here: a device that accepts the testkey accepts anything signed
with it, so iterating no longer means rewriting the 1.8 GB image.

```bash
# fetch them
for f in testkey.pk8 testkey.x509.pem; do
  curl -sL "https://android.googlesource.com/platform/build/+/refs/heads/main/target/product/security/$f?format=TEXT" \
    | base64 -d > "$f"
done
```

## Install

```bash
adb connect 127.0.0.1:16384
adb install -r Lawnchair-testkey.apk
```

**On MuMu 15 `adb install -r` fails even when the APK is byte-identical to the
one already in the image:**

```
Failure [INSTALL_FAILED_UPDATE_INCOMPATIBLE: Existing package app.lawnchair
signatures do not match newer version; ignoring!]
```

The APK is not the problem — pulling `/system/priv-app/Lawnchair/Lawnchair.apk`
out of the image and reinstalling that same file fails the same way, and
`dumpsys package app.lawnchair` shows the recorded signature
(`signatures=[b4addb29]`, `versionName=15.Beta 3`) as coming from the *original*
in-image build rather than from anything on disk. Uninstalling
(`pm uninstall --user 0 app.lawnchair`) does not clear it either; the package
has to be brought back with `cmd package install-existing app.lawnchair`.

To iterate without touching the image, bind-mount the new APK over the old one:

```bash
adb root
adb push Lawnchair-testkey.apk /data/local/tmp/lc.apk
adb shell "mount --bind /data/local/tmp/lc.apk \
    /system/priv-app/Lawnchair/Lawnchair.apk"
```

`umount` then fails with `Device or resource busy` while anything holds the
file open; `adb reboot` clears the bind and restores the original.

or, to put it in the image itself:

```bash
uv run niulai-patch lawnchair --apk Lawnchair-testkey.apk --allow-unknown-installed
```

To check the result independently, extract the system partition and run
`e2fsck -fn` over it; the tool itself re-reads and compares every byte it wrote,
but that is a self-consistency check. See
[doc/analysis/disk-writer.md](../doc/analysis/disk-writer.md).

`--allow-unknown-installed` is needed because a rebuilt APK has a different
digest from either build the tool knows by name.
