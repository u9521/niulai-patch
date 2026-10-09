# How it stays safe

The guarantees each write path provides, and why they exist.

* **Signatures, not addresses.** The binaries use ASLR
  (`DllCharacteristics = 0x8160`), so runtime addresses change every launch.
  Patches match byte patterns and are recorded as RVAs.
* **Ambiguity is fatal.** If a signature matches zero or several places, the
  tool refuses and tells you to tighten it. It never silently picks the first
  hit — that is how you patch the wrong function.
* **No silent truncation.** If an internal match cap is reached, the scan
  raises instead of returning a partial list (a partial list makes a present
  match look absent).
* **Backups are verified.** Each file is copied and the copy re-hashed; a
  backup failing its own SHA-256 check is never restored over a good file.
* **A failure never destroys its own backup.** Backups are written to a hidden
  staging directory and promoted to their final name only once whole, so an
  interrupted copy is never mistaken for a backup. Crucially, when a run
  *fails* the captured files are **kept**, with `interrupted: true` in the
  manifest — the backup exists to undo the failure in progress, so deleting it
  is the one thing that must not happen. Only a session that never captured a
  file is removed, because there is nothing in it to keep.
* **An edit cannot start unless it can be undone.** Before the first write,
  `_require_restorable` re-hashes every file in the backup and confirms the
  destination is still writable. A backup that cannot be read back is not
  insurance, and the moment to find out is before the image changes, not after.
* **Transactional writes.** Files are written via a same-directory temp file
  plus `os.replace`, and a failure mid-run rolls back the files already written.
* **No "is MuMu running?" check, by design.** `system.vdi` is declared
  `type="Readonly"` with `nemud.system_writable=0`, so the guest never writes it
  back and a running emulator cannot clobber an edit. The check this replaced
  was worse than nothing: on WSL it silently returned "not running" because
  `tasklist` is a Windows executable, so it only ever gave false confidence
  about the most destructive operation in the project. The real guard is the
  backup plus `_require_restorable`, which does not depend on the host.
* **Idempotent.** Re-running `patch` reports `already-applied` and writes
  nothing.
* **Sites are found semantically, not by address.** A patch's site is located
  from a fact that survives a rebuild — a string literal, an import name —
  rather than an absolute RVA. The signature then *verifies* the site instead of
  having to find it. See [patch-sites.md](patch-sites.md).
* **A required companion cannot be forgotten.** Patching either executable
  strips its Authenticode blob, which arms that binary's own self-integrity check
  — and the punishment is CPU-burning threads. Both `MuMuNxMain.exe` and
  `MuMuNxDevice.exe` carry one. `no-integrity-punish` and
  `no-device-integrity-punish` defuse them, and every profile that touches those
  binaries now *declares* the dependency (`requires`) rather than relying on the
  operator to remember it.
* **A build change is diagnosed, not guessed at.** Each profile records the
  vendor build fingerprint it was authored against (`pe/buildid.py`). A mismatch
  warns in plain language — "profiles were authored against build X, this is
  build Y" — instead of surfacing as twenty-one separate signature failures.
  It never blocks a patch; the per-patch checks remain the gate.

Disk edits add four guarantees of their own, because the failure mode is worse:
a wrong byte inside `/system` does not produce a bad patch result, it produces a
device that will not boot.

* **A write allocates only when it has been measured as affordable.**
  `extfs.replace_file_in_place` overwrites only blocks the file already owns and
  refuses any increase, so it cannot disturb the free-block count. When a
  replacement really is larger, `replace_file_growing` frees the old blocks
  *first* and allocates the difference — and the caller has to have compared
  that difference against the free space it read from the same filesystem in the
  same operation. An unaffordable growth is refused with the numbers rather than
  attempted.
* **The five bugs the writer's invariants came from.** An independent checker
  (`e2fsck`, over every edit) caught five genuine bugs that the in-tree checks
  were happy with —
  * `i_blocks` double-counted when rewriting an extents file (`170768` where
    `85384` was correct, exactly twice the data blocks);
  * group-descriptor checksums were never recomputed, so every descriptor the
    writer touched was invalid under the `uninit_bg` feature;
  * the bitmap padding bits past a short final group were being *cleared*,
    where `mke2fs` sets them and `e2fsck` requires them set;
  * the group start was computed as `N * blocks_per_group`, ignoring the boot
    block that a 1 KiB block size reserves, so every bitmap bit was off by one;
  * `i_blocks` counted only the 15 pointer slots, and the free list named only
    slots 12–14, so the inner indirect tables leaked.
  Each is now pinned by a regression test in `tests/test_disk.py`, which is what
  carries the guarantee. See
  [analysis/disk-writer.md](analysis/disk-writer.md).
* **What is not checked.** Nothing reads an edited filesystem with an
  independent implementation. The in-tree verification is a re-read through a
  fresh handle, which can only prove self-consistency. If you want an outside
  opinion, extract the partition and run `e2fsck -fn` yourself; it is read-only
  and exits non-zero when something is wrong.
* **A partition refuses to address past its own end.** Each partition is a
  device with its own extent, so a wrong offset raises instead of reading or
  writing the next partition along — which is what the hand-rolled offset
  adapters this replaced would have done, silently.
* **Every write is re-read and compared.** A mismatch raises rather than being
  left for boot time to discover. This is not theoretical: driving `debugfs` to
  write a 24 MB kernel into the 14 MiB boot partition prints *both* `Could not
  allocate block in ext2 filesystem` *and* `Allocated inode: 11`, then records a
  24,725,504-byte size with zero free blocks — an image that `ls` renders as
  perfectly fine. That is why the writer, not `debugfs`, performs every
  allocation.
* **The container layout is verified, not remembered.** The VDI header is a C
  struct with 8-byte alignment, so it is not the packed layout it resembles;
  `doctor` cross-checks every field against MuMu's own `vbox-img.exe` and
  reports a disagreement as a reason not to edit.
* **Ambiguity is fatal here too.** An extent index read as a leaf yields a start
  block outside the filesystem; a directory routed to the wrong block-map parser
  yields garbage. Both are now regression-tested against the real image.

Applying any patch invalidates the Authenticode signature, so the tool strips it
properly: the security data directory is zeroed, the file truncated at the
certificate's start, and the PE checksum recomputed. Windows may still warn
about an unsigned binary — that is expected.
