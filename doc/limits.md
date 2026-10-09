# Limits

What this tool does not do, and what is left unverified.

* **The screenshot's menu is not removable by binary patching.** 消息中心,
  兑换中心, 设置中心, 常见问题 and 下载掌上MuMu exist nowhere as literals in any
  module. A live run showed why: the launcher embeds CEF web views, and the
  title-bar menu is gated by **server-supplied feature flags** (a 27-entry
  `GrayFeature` enum including `RedemptionCenter`, `HelpCenterFrequentlyQuestions`
  and `MainSettingCenter`), fetched over HTTP and cached in shared memory. The
  hide paths already exist in the binary; they are simply being told not to run.
  See [analysis/ui-and-flags.md](analysis/ui-and-flags.md) — a runtime hook on the
  flag check is the promising route, and is left as an open avenue because it
  needs write access to the install to develop.
* Only builds matching the recorded signatures are supported, but a MuMu update
  is now a routine event rather than a dead end. `analyze` reports the build
  fingerprint and which patches still resolve; `rebase` re-resolves the rest and
  can record the new RVAs. Patches that cannot be placed are reported as needing
  manual work rather than guessed at — a site that has genuinely moved *and*
  changed shape is a behaviour change, and needs a debugger.
* **The version-drift testing is synthetic.** Only MuMu 6.8.2.0 is on hand, so
  `tests/test_robustness.py` models a rebuild by shifting every section rather
  than by rebasing against a real newer release. That mutation is deliberately
  kind to the old locators — rip-relative references still resolve because source
  and target move together — so it is a floor, not a substitute for the first
  real update. The measured improvement (3/12 → 12/12 on the main binary) is real
  but is the easy half of the problem.
* Windows-only in practice: patching needs write access to
  `C:\Program Files\Netease\MuMu`, which normally means running elevated. On
  non-Windows the tool still works for analysis against a mounted copy.
* The Sentry DSN is passed as a **process argument** to every CEF child, not
  built in code, so it is not a binary-patch target either.
* **A kernel replacement does not make the guest boot.** `kernel` writes the
  image and the partition table correctly — that is verified — but this project
  has no way to confirm that a given `bzImage` actually starts, because doing so
  needs a real boot. Treat `--apply` as producing a candidate, and keep the
  backup.
* **Growing `sda3` relocates 1.76 GB.** Correct, and fast (about 1.2 s), but it
  is a rewrite of the partition table and the data after it. It is refused
  rather than approximated when the plan does not validate; an early naive
  attempt produced an overlapping partition table, which 7-Zip correctly
  refused.
* **Nothing writes a filesystem except this project's own writer.** That is why
  `debugfs` is safe to use in the *test suite* but was never safe to use in the
  product: driving it to write is unsafe in exactly the case that matters. With
  no space left it prints `Could not allocate block in ext2 filesystem` and
  *then creates the inode anyway*. Reproduced on the real boot partition — a
  file reporting `Size: 20000000` with `Blockcount: 156`, i.e. claiming 20 MB
  while holding 78 KB, and `e2fsck` calls the result corrupt. The in-tree writer
  refuses the same request outright (`need 19,532 blocks but the filesystem
  reports only 12,153 free`) and leaves the file untouched. In the suite,
  `mke2fs` and `debugfs` only ever *build fixtures*, never edit the user's image.
* **No kernel source is shipped**, so KernelSU cannot be removed. It is a
  compile-time option in NetEase's fork (`CONFIG_KSU=y`, with
  `CONFIG_KSU_DISABLE_MANAGER` unset), so dropping it means rebuilding their
  kernel — not a patch to the shipped binary.
* **No partition-rebuild tool is shipped.** A from-scratch builder such as
  `make_ext4fs` would only be needed to rebuild a partition from nothing; every
  edit here is in place. See [disk.md](disk.md) for the pure-Python stack that
  does the work instead.
* Replacing the launcher leaves the `privapp-permissions-platform.xml` whitelist
  naming `com.android.launcher3` and not `app.lawnchair`. Both the fork and the
  upstream APK request the same privileged permissions and neither is whitelisted,
  so an upstream swap adds no new exposure — but on a build that enforces the
  whitelist strictly, a priv-app may be refused instead of silently degraded.
