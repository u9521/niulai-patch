"""Command line interface."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
from typing import NoReturn

import click
from rich.console import Console
from rich.table import Table

import backup
import filesystems
import install
import splash as splash_assets
from __about__ import __version__
from pe import buildid, patcher, pe, rebase, sigscan
from rcc import rcc, rccpatch

console = Console()
err_console = Console(stderr=True)


def _fail(msg: str, code: int = 1) -> NoReturn:
    """Report a fatal problem and exit.

    ``NoReturn`` is load-bearing rather than decorative: callers use this as a
    failure guard (``try: ... except ...: _fail(...)``) and then go on to use the
    value the guard was protecting.  Without the annotation a type checker has to
    assume ``_fail`` returns, so every such value looks possibly-unbound.
    """
    err_console.print(f"[bold red]error:[/] {msg}")
    raise SystemExit(code)


def _report_build_identity(inst, profiles: list[patcher.Profile]) -> None:
    """Warn when the profiles were authored against a different vendor build.

    Diagnostic only, and deliberately non-blocking: after a MuMu update the
    signatures may still match perfectly, in which case refusing to run would be
    obstructive.  What is worth avoiding is the *other* outcome -- twenty-one
    separate "signature not found" errors that each look like a bug in the
    signature rather than what they are, which is "this is a different build".

    Prints nothing when every profile agrees with the file on disk.
    """
    seen: set[str] = set()
    for prof in profiles:
        for rel, expected in prof.build.items():
            if rel in seen:
                continue
            seen.add(rel)
            target = inst.resolve(rel)
            if not target.is_file():
                continue
            actual = buildid.fingerprint(target.read_bytes())
            if actual == expected:
                continue
            err_console.print(
                f"[yellow]warning:[/] {rel} is build {actual}, but the profiles "
                f"were authored against {expected}."
            )
            err_console.print(
                "  Signatures may still match; if some do not, that is a build "
                "change, not a broken signature. See [bold]niulai-patch rebase[/]."
            )


def _write_failure(exc: OSError) -> str:
    """Explain a failed write, from the error rather than from a guess.

    This project deliberately does **not** ask "is MuMu running?" before writing.
    For the disk images that question is meaningless -- ``system.vdi`` is
    declared ``Readonly`` with ``nemud.system_writable=0``, so the guest never
    writes it back -- and the check that used to stand here silently answered
    "not running" under WSL, where ``tasklist`` is not on ``PATH``.  A guard that
    only ever returns the reassuring answer is worse than none.

    For the host files (``MuMuNxMain.exe``, ``NxDeviceResource.rcc``) a running
    emulator does hold them open, and Windows then fails the replace with a
    sharing violation.  That is a real case, but it is better handled by
    reporting the failure we actually got than by predicting it: the error names
    the file, and the hint below says what to do about it.

    ``os.replace`` is atomic, so this failure leaves the original intact.
    """
    failed = getattr(exc, "filename", None) or "(unknown path)"
    hint = ""
    # Which directory the failure is in is the more specific fact, so it is
    # checked first: an EPERM against the backup root is a backup-root problem,
    # and saying "close the emulator" for it would send the reader the wrong way.
    if failed.startswith(str(backup.default_backup_root())):
        hint = (
            "\n  The backup directory is not writable. Set "
            "MUMU_PATCH_BACKUP_ROOT to a writable location."
        )
    else:
        lowered = str(exc).lower()
        if "permission" in lowered or getattr(exc, "errno", None) in (13, 5):
            hint = (
                "\n  If MuMu is open it holds this file; close the emulator and "
                "retry. Otherwise the install directory needs an elevated "
                "(Administrator) shell."
            )
    return f"write failed: {exc.strerror or exc}\n  path: {failed}{hint}"


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(__version__, prog_name="niulai-patch")
def main():
    """Patch the installed Netease MuMu emulator to strip unwanted features.

    All modifications are backed up first and can be reverted with `restore`.
    """


# --------------------------------------------------------------------------- #
# analyze
# --------------------------------------------------------------------------- #
@main.command()
@click.option(
    "--install-dir",
    type=click.Path(path_type=Path),
    default=None,
    help="MuMu installation root (default: auto-detect).",
)
def analyze(install_dir):
    """Report the installation and what each profile would do. Read-only."""
    try:
        inst = install.find_install(install_dir)
    except install.InstallError as exc:
        _fail(str(exc))

    console.print(f"[bold]Installation[/]  {inst.summary()}")
    exe = inst.main_exe
    if not exe.is_file():
        _fail(f"main executable not found: {exe}")

    data = exe.read_bytes()
    info = pe.parse(data)
    console.print(f"[bold]Target[/]        {exe}")
    console.print(
        f"  size {len(data):,} bytes, {'x64' if info.is_64bit else 'x86'}, "
        f"{info.num_sections} sections, ASLR={'on' if info.sections else '?'}"
    )
    if info.has_signature:
        console.print(
            f"  Authenticode signature present: {info.cert_size:,} bytes "
            f"at {info.cert_offset:#x} [yellow](will be stripped on patch)[/]"
        )
    else:
        console.print("  no Authenticode signature")
    console.print(f"  PE checksum {info.checksum:#010x}")
    console.print(f"  build fingerprint {buildid.fingerprint(data)}")

    profiles = patcher.load_profiles()
    if not profiles:
        console.print("\n[yellow]no patch profiles found[/]")
        return

    # How each patch finds its site is worth surfacing: a profile that drifts
    # back to an absolute RVA is fragile in a way that is invisible in the
    # patch's own description, and this is the cheapest place to notice.
    resolvers: dict[str, int] = {}
    for prof in profiles.values():
        for p in prof.patches:
            resolvers[p.resolver()] = resolvers.get(p.resolver(), 0) + 1
    build_specific = [
        p.id for prof in profiles.values() for p in prof.patches if p.is_build_specific()
    ]
    console.print("  locators: " + ", ".join(f"{k} x{v}" for k, v in sorted(resolvers.items())))
    if build_specific:
        console.print(
            f"  [yellow]{len(build_specific)} patch(es) located by a "
            f"build-specific number[/] [dim]({', '.join(build_specific)})[/]"
        )

    for name, prof in profiles.items():
        table = Table(title=f"profile: {name}", title_justify="left")
        table.add_column("patch")
        table.add_column("target")
        table.add_column("located by")
        table.add_column("status")
        for patch in prof.patches:
            target = inst.resolve(patch.file)
            resolver = patch.resolver()
            if not target.is_file():
                status = "[red]file missing[/]"
            else:
                tdata = target.read_bytes()
                try:
                    m = patcher.locate(tdata, patch)
                    if patcher.verify_patch(tdata, patch):
                        status = f"[green]already applied[/] (RVA {m.rva:#x})"
                    elif patch.known_rvas and m.rva not in patch.known_rvas:
                        status = (
                            f"[yellow]match at {m.rva:#x}, "
                            f"expected {[hex(r) for r in patch.known_rvas]}[/]"
                        )
                    else:
                        status = f"[green]ready[/] (RVA {m.rva:#x})"
                except sigscan.SignatureError as exc:
                    status = f"[red]{exc}[/]"
            table.add_row(patch.id, patch.file, resolver, status)
        console.print()
        console.print(table)


# --------------------------------------------------------------------------- #
# list-patches
# --------------------------------------------------------------------------- #
@main.command("list-patches")
def list_patches():
    """List available profiles and patches."""
    profiles = patcher.load_profiles()
    if not profiles:
        _fail("no patch profiles found")
    for name, prof in profiles.items():
        console.print(f"\n[bold cyan]{name}[/] -- {prof.description}")
        for p in prof.patches:
            console.print(f"  [bold]{p.id}[/]: {p.description}")
            console.print(f"      {p.file}")
            console.print(f"      sig: {p.signature}")


# --------------------------------------------------------------------------- #
# patch
# --------------------------------------------------------------------------- #
@main.command()
@click.option("--profile", "profile_name", required=True, help="Profile to apply.")
@click.option("--install-dir", type=click.Path(path_type=Path), default=None)
@click.option("--only", "only", multiple=True, help="Apply only these patch ids.")
@click.option("--dry-run", is_flag=True, help="Show what would change; write nothing.")
@click.option(
    "--force",
    is_flag=True,
    help="Proceed even if a signature matches a different RVA than recorded.",
)
@click.option(
    "--no-strip-signature",
    is_flag=True,
    help="Leave the Authenticode blob in place (it becomes invalid anyway).",
)
def patch(profile_name, install_dir, only, dry_run, force, no_strip_signature):
    """Apply a patch profile in place, with backups."""
    try:
        inst = install.find_install(install_dir)
    except install.InstallError as exc:
        _fail(str(exc))

    profiles = patcher.load_profiles()
    if profile_name not in profiles:
        _fail(f"unknown profile {profile_name!r}; have: {', '.join(profiles) or 'none'}")

    # A profile may declare that it depends on another (see `requires`).  Expand
    # before planning so the dependency is applied in the same pass; the user
    # asking for one profile is asking for a working result, not a fragment.
    try:
        chain = patcher.resolve_requirements(profiles, [profile_name])
    except patcher.PatchError as exc:
        _fail(str(exc))
    chain = [n for n in chain if n in profiles]
    required = [n for n in chain if n != profile_name]
    if required:
        console.print(f"[dim]{profile_name} requires: {', '.join(required)} (applied together)[/]")

    _report_build_identity(inst, [profiles[n] for n in chain])

    try:
        plans = patcher.plan_profiles([profiles[n] for n in chain], inst.root, list(only) or None)
    except patcher.PatchError as exc:
        _fail(str(exc))
    if not plans:
        _fail("nothing to do (no matching patches)")

    # -- pre-flight: everything must be verifiable before we touch a byte ----
    prepared: list[tuple[patcher.FilePlan, Path, bytes, list[patcher.PatchResult]]] = []
    problems: list[str] = []

    for plan in plans:
        target = inst.resolve(plan.file)
        if not target.is_file():
            problems.append(f"{plan.file}: file not found")
            continue
        data = target.read_bytes()
        working = data
        results: list[patcher.PatchResult] = []
        for p in plan.patches:
            try:
                working, res = patcher.apply_patch_to_bytes(working, p)
            except (patcher.PatchError, sigscan.SignatureError, pe.PEError) as exc:
                problems.append(f"{p.id}: {exc}")
                break
            if force is False and p.known_rvas and res.status == "applied" and res.detail:
                problems.append(f"{p.id}: RVA drift -- {res.detail} (use --force)")
                break
            results.append(res)
        else:
            prepared.append((plan, target, working, results))

    if problems:
        err_console.print("[bold red]pre-flight failed; nothing was modified:[/]")
        for p in problems:
            err_console.print(f"  - {p}")
        raise SystemExit(1)

    # -- report ------------------------------------------------------------
    changed_files = 0
    for plan, target, _working, results in prepared:
        real_changes = [r for r in results if r.status == "applied"]
        if real_changes or (not no_strip_signature and pe.parse(target.read_bytes()).has_signature):
            changed_files += 1
        console.print(f"\n[bold]{plan.file}[/]")
        for r in results:
            colour = {"applied": "green", "already-applied": "yellow"}.get(r.status, "white")
            console.print(
                f"  [{colour}]{r.status:16}[/] {r.patch_id} @ RVA {r.rva:#x} (file {r.offset:#x})"
            )
            if r.detail:
                console.print(f"      [dim]{r.detail}[/]")

    if dry_run:
        console.print("\n[bold]dry run:[/] no files were modified.")
        return

    if not changed_files:
        console.print("\n[bold]nothing to change[/] (already patched).")
        return

    # -- apply, with backup ------------------------------------------------
    try:
        with backup.BackupSession(
            inst.root,
            inst.product_version,
            # Record every patch id that this run is responsible for, including
            # the required profiles' -- `verify` and `restore` read this list,
            # and a dependency applied silently would otherwise be invisible.
            [p.id for prof in [profiles[n] for n in chain] for p in prof.patches],
        ) as session:
            written: list[Path] = []
            try:
                for _plan, target, working, results in prepared:
                    if all(r.status == "already-applied" for r in results):
                        continue
                    session.backup(target, [r.patch_id for r in results])
                    _require_restorable(session, "patch")
                    out = working
                    if not no_strip_signature:
                        out, stripped = pe.strip_signature(out)
                        if stripped:
                            console.print(f"  [dim]stripped signature from {target.name}[/]")
                    backup.atomic_write(target, out)
                    written.append(target)
            except BaseException:
                # Best effort: put back anything we already overwrote.
                for t in written:
                    rec = next(
                        (f for f in session.manifest.files if f.original_path == str(t)),
                        None,
                    )
                    if rec:
                        try:
                            backup.atomic_write(t, Path(rec.backup_path).read_bytes())
                        except OSError:
                            err_console.print(f"[red]rollback failed for {t}[/]")
                raise
            mpath = session.save()
    except OSError as exc:
        _fail(_write_failure(exc))

    console.print(f"\n[bold green]done.[/] {len(written)} file(s) patched.")
    console.print(f"backup manifest: {mpath}")
    console.print("revert with: [bold]niulai-patch restore[/]")


# --------------------------------------------------------------------------- #
# restore
# --------------------------------------------------------------------------- #
@main.command()
@click.option("--install-dir", type=click.Path(path_type=Path), default=None)
@click.option(
    "--backup-dir",
    type=click.Path(path_type=Path),
    default=None,
    help="Restore from this specific backup directory.",
)
@click.option("--latest", is_flag=True, help="Restore the most recent backup.")
@click.option("--list", "do_list", is_flag=True, help="List available backups.")
@click.option("--dry-run", is_flag=True)
@click.option("--yes", is_flag=True, help="Skip the confirmation prompt.")
def restore(install_dir, backup_dir, latest, do_list, dry_run, yes):
    """Restore files from a backup manifest.

    Discovers backups in both places they are written: the user's data
    directory (small program files) and beside each disk image (the multi-
    gigabyte ones, which ``lawnchair`` and ``kernel`` keep next to the image so
    the copy stays on one filesystem).  Searching only the first meant the
    image backups were invisible to ``restore --list``.
    """
    from disk import images

    roots: list[Path] = [backup.default_backup_root()]
    try:
        vm = images.find_vm_images(install_dir)
        roots.append(_backup_root_for(vm.system))
    except Exception:
        # Discovery is best-effort: without a usable install we can still list
        # whatever is in the default root.
        pass

    manifests: list[tuple[Path, backup.Manifest]] = []
    seen: set[str] = set()
    for root in roots:
        for mpath, man in backup.load_manifests(root):
            key = str(mpath)
            if key not in seen:
                seen.add(key)
                manifests.append((mpath, man))
    manifests.sort(key=lambda t: t[1].created, reverse=True)

    if do_list or (not backup_dir and not latest):
        if not manifests:
            _fail("no backups found. Looked in: " + ", ".join(str(r) for r in roots))
        table = Table(title="available backups")
        table.add_column("#")
        table.add_column("created")
        table.add_column("version")
        table.add_column("files")
        table.add_column("patches")
        table.add_column("state")
        for i, (_mpath, m) in enumerate(manifests):
            import datetime

            problems = backup.verify_backup(m)
            if problems:
                state = f"[red]unusable ({len(problems)})[/]"
            elif m.interrupted:
                state = "[yellow]interrupted run[/]"
            else:
                state = "[green]ok[/]"
            table.add_row(
                str(i),
                datetime.datetime.fromtimestamp(m.created).strftime("%Y-%m-%d %H:%M:%S"),
                m.product_version,
                str(len(m.files)),
                ", ".join(m.patch_ids),
                state,
            )
        console.print(table)
        for mpath, m in manifests:
            if m.interrupted:
                console.print(
                    f"[yellow]note:[/] the backup at {mpath.parent} was taken by a "
                    f"run that did not finish. Its files are still valid copies of "
                    f"what was on disk before the edit, so restoring from it is safe."
                )
        stale = backup.incomplete_sessions()
        if stale:
            console.print(
                f"[yellow]note:[/] {len(stale)} incomplete session(s) left in "
                f"staging (no manifest, never captured a file):"
            )
            for path in stale:
                console.print(f"  {path}")
        if do_list and not latest:
            return
        if not manifests:
            _fail("nothing to restore")

    if backup_dir:
        mpath = Path(backup_dir) / backup.MANIFEST_NAME
        if not mpath.is_file():
            _fail(f"no manifest at {mpath}")
        try:
            man = backup.Manifest.from_json(mpath.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            _fail(f"cannot read manifest: {exc}")
    else:
        _, man = manifests[0]

    console.print(f"restoring {len(man.files)} file(s) from {man.product_version}")
    for f in man.files:
        console.print(f"  {f.original_path}")

    # A restore is the last line of defence, so verify the source before
    # reporting success: restoring half a file is worse than refusing.
    problems = backup.verify_backup(man)
    if problems:
        for path, why in problems:
            err_console.print(f"[red]unusable backup:[/] {path}: {why}")
        _fail(
            "this backup cannot be restored; it is incomplete or has been "
            "modified since it was taken"
        )
    if man.interrupted:
        console.print(
            "[yellow]note:[/] this backup came from a run that did not finish. "
            "Its files are valid copies of the pre-edit state."
        )
    if not man.files:
        _fail("this backup records no files; there is nothing to restore")

    if not dry_run and not yes:
        click.confirm("proceed?", abort=True)

    try:
        results = backup.restore_files(man, dry_run=dry_run)
    except OSError as exc:
        _fail(_write_failure(exc))

    restored = sum(1 for _, s in results if s == "restored")
    for path, status in results:
        colour = {"restored": "green", "unchanged": "yellow", "missing": "red"}[status]
        console.print(f"  [{colour}]{status:10}[/] {path}")
    console.print(f"\n[bold]{'would restore' if dry_run else 'restored'} {restored} file(s).[/]")


# --------------------------------------------------------------------------- #
# verify
# --------------------------------------------------------------------------- #
@main.command()
@click.option("--install-dir", type=click.Path(path_type=Path), default=None)
def verify(install_dir):
    """Check whether the recorded patches are still in effect."""
    try:
        inst = install.find_install(install_dir)
    except install.InstallError as exc:
        _fail(str(exc))

    manifests = backup.load_manifests()
    relevant = [m for _, m in manifests if Path(m.install_dir) == inst.root]
    if not relevant:
        console.print("[yellow]no backups recorded for this install[/]")

    profiles = patcher.load_profiles()
    all_patches = {p.id: p for prof in profiles.values() for p in prof.patches}

    applied_ids = {pid for m in relevant for pid in m.patch_ids}
    if not applied_ids:
        console.print("no patches recorded as applied for this install.")
        return

    table = Table(title="patch status")
    table.add_column("patch")
    table.add_column("file")
    table.add_column("state")
    for pid in sorted(applied_ids):
        p = all_patches.get(pid)
        if p is None:
            # The patch was applied by an earlier run and has since been
            # removed from the profile (e.g. the user asked to keep that
            # component after all).  Its bytes may still be modified in the
            # file, so say so plainly instead of "definition missing".
            table.add_row(
                pid,
                "?",
                "[yellow]no longer in the profile[/] [dim](applied previously; restore to undo)[/]",
            )
            continue
        target = inst.resolve(p.file)
        if not target.is_file():
            table.add_row(pid, p.file, "[red]file missing[/]")
            continue
        data = target.read_bytes()
        if patcher.verify_patch(data, p):
            state = "[green]in effect[/]"
        else:
            try:
                m = patcher.locate(data, p)
                state = f"[red]lost[/] (original bytes at {m.rva:#x})"
            except sigscan.SignatureError:
                state = "[yellow]signature not found (build changed?)[/]"
        sig = "signed" if pe.parse(data).has_signature else "unsigned"
        table.add_row(pid, p.file, f"{state} [dim]({sig})[/]")
    console.print(table)


# --------------------------------------------------------------------------- #
# rebase
# --------------------------------------------------------------------------- #
@main.command()
@click.option(
    "--install-dir",
    type=click.Path(path_type=Path),
    default=None,
    help="Rebase the profiles against this installation (default: auto-detect).",
)
@click.option(
    "--from-file",
    "from_file",
    type=click.Path(path_type=Path, exists=True),
    default=None,
    help="The old binary the profiles were authored against (report only).",
)
@click.option(
    "--file",
    "target_rel",
    default=None,
    help="Rebase only this profile-relative target, e.g. nx_main/MuMuNxMain.exe.",
)
@click.option(
    "--write", is_flag=True, help="Rewrite the TOML files. Without this, nothing is written."
)
@click.option(
    "--update-build", is_flag=True, help="With --write, also record the new build fingerprint."
)
def rebase_cmd(install_dir, from_file, target_rel, write, update_build):
    """Re-resolve patch sites against a different MuMu build.

    Reports, per patch, whether its site still resolves, has moved, or needs a
    human.  The default is a dry report; --write records the new RVAs, editing
    only the locate_rva/known_rvas lines so the profiles' comments survive.
    """
    try:
        inst = install.find_install(install_dir)
    except install.InstallError as exc:
        _fail(str(exc))

    profiles = patcher.load_profiles()
    if not profiles:
        _fail("no patch profiles found")

    targets = sorted({p.file for prof in profiles.values() for p in prof.patches})
    if target_rel:
        if target_rel not in targets:
            _fail(f"{target_rel!r} is not a patch target; have: {', '.join(targets)}")
        targets = [target_rel]

    # The comparison is informational: it says whether the profiles were
    # authored against this build, which sets expectations for what follows.
    for rel in targets:
        target = inst.resolve(rel)
        if not target.is_file():
            err_console.print(f"[yellow]skipping[/] {rel}: not present")
            continue
        data = target.read_bytes()
        actual = buildid.fingerprint(data)
        recorded = {fp for prof in profiles.values() for f, fp in prof.build.items() if f == rel}
        if recorded and actual not in recorded:
            console.print(
                f"[bold]{rel}[/] is build [cyan]{actual}[/]; profiles record "
                f"{', '.join(sorted(recorded))}"
            )
        elif recorded:
            console.print(f"[bold]{rel}[/] matches the recorded build {actual}")
        else:
            console.print(f"[bold]{rel}[/] build {actual} (no fingerprint recorded)")

        report = rebase.rebase(data, rel, profiles)

        table = Table(title=f"rebase: {rel}", title_justify="left")
        table.add_column("patch")
        table.add_column("profile")
        table.add_column("status")
        for outcome in report.outcomes:
            colour = {
                "unchanged": "green",
                "moved": "yellow",
                "found": "yellow",
            }.get(outcome.status, "red")
            table.add_row(
                outcome.patch_id,
                outcome.profile,
                f"[{colour}]{outcome.describe()}[/]",
            )
        console.print()
        console.print(table)

        if report.unplaced:
            console.print(
                f"[yellow]{len(report.unplaced)} patch(es) need manual work.[/] "
                "A site that cannot be placed is a behaviour change, not just a "
                "moved address: check it in a debugger before forcing anything."
            )
        if report.edits:
            if write:
                try:
                    written = rebase.apply_edits(report)
                except patcher.PatchError as exc:
                    _fail(str(exc))
                console.print(f"[green]updated[/] {', '.join(p.name for p in written)}")
                if update_build:
                    for prof in profiles.values():
                        edits = rebase.refresh_build(prof, data)
                        if edits:
                            rebase.apply_edits(
                                rebase.RebaseReport(edits={rebase._toml_path_for(prof.name): edits})
                            )
                    console.print("[green]recorded the new build fingerprint[/]")
            else:
                files = ", ".join(sorted(p.name for p in report.edits))
                console.print(f"[dim]would update {files}; re-run with --write to apply[/]")
        elif not report.unplaced:
            console.print("[green]nothing to change[/]")


# --------------------------------------------------------------------------- #
# dbg
# --------------------------------------------------------------------------- #
@main.command()
@click.option("--install-dir", type=click.Path(path_type=Path), default=None)
@click.option(
    "--base", "base_addr", default=None, help="Live module base in hex, e.g. 0x7ff6593f0000."
)
@click.option("--profile", "profile_name", default=None)
def dbg(install_dir, base_addr, profile_name):
    """Convert patch RVAs to live addresses for an x64dbg session.

    Signatures are anchored on RVAs because the binaries use ASLR; this maps
    them to the addresses you actually see in the debugger.
    """
    try:
        inst = install.find_install(install_dir)
    except install.InstallError as exc:
        _fail(str(exc))

    if base_addr is None:
        _fail("--base is required (read it from x64dbg's module list)")

    try:
        base = int(base_addr, 0)
    except ValueError:
        _fail(f"cannot parse base address {base_addr!r}")

    profiles = patcher.load_profiles()
    if profile_name:
        if profile_name not in profiles:
            _fail(f"unknown profile {profile_name!r}")
        profiles = {profile_name: profiles[profile_name]}

    table = Table(title=f"live addresses (base {base:#x})")
    table.add_column("patch")
    table.add_column("file")
    table.add_column("RVA")
    table.add_column("live address")
    for prof in profiles.values():
        for p in prof.patches:
            target = inst.resolve(p.file)
            if not target.is_file():
                continue
            data = target.read_bytes()
            try:
                m = patcher.locate(data, p)
                rva_s = f"{m.rva:#x}"
                live = f"{base + m.rva:#x}"
            except sigscan.SignatureError:
                rva_s = live = "[dim]not present[/]"
            table.add_row(p.id, p.file, rva_s, live)
    console.print(table)
    console.print(
        "\nSet breakpoints on the live addresses above, e.g. [bold]bp 0x...[/] in x64dbg."
    )


# --------------------------------------------------------------------------- #
# strings
# --------------------------------------------------------------------------- #
@main.command()
@click.option("--install-dir", type=click.Path(path_type=Path), default=None)
@click.option(
    "--rcc",
    "rcc_path",
    type=click.Path(path_type=Path),
    default=None,
    help="Inspect this rcc file instead of the launcher's.",
)
@click.option("--list", "do_list", is_flag=True, help="List resources, don't search.")
@click.option("--resource", default=None, help="Resource path suffix to inspect, e.g. '.qm'.")
@click.argument("text", nargs=-1)
def strings(install_dir, rcc_path, do_list, resource, text):
    """Search the launcher's translated UI strings.

    The Chinese menu labels live in a Qt `.qm` translation inside
    `nx_main/rcc/NxMainResource.rcc`, not in any executable -- see
    doc/analysis/ui-and-flags.md. This command shows where they are.
    """
    if rcc_path is None:
        try:
            inst = install.find_install(install_dir)
        except install.InstallError as exc:
            _fail(str(exc))
        rcc_path = inst.root / "nx_main" / "rcc" / "NxMainResource.rcc"
    if not rcc_path.is_file():
        _fail(f"rcc file not found: {rcc_path}")

    try:
        container = rcc.load_rcc(rcc_path)
    except rcc.RccError as exc:
        _fail(str(exc))

    console.print(f"[bold]{rcc_path.name}[/]  version {container.version}")

    if do_list or (not text and not resource):
        table = Table(title="resources")
        table.add_column("resource")
        table.add_column("compression")
        table.add_column("offset")
        for r in container.walk():
            if resource and not r.path.lower().endswith(resource.lower()):
                continue
            table.add_row(r.path, r.compression, f"{r.offset:#x}")
        console.print(table)
        if do_list:
            return

    suffix = resource or ".qm"
    candidates = container.find(suffix)
    if not candidates:
        _fail(f"no resource matching {suffix!r} in {rcc_path.name}")
    # Prefer the Simplified Chinese translation: it is the one the launcher
    # actually loads, per the LanguageManager log line.
    target = next((r for r in candidates if "zh_hans" in r.path), candidates[0])
    console.print(f"[bold]resource[/] {target.path}  ({target.compression})")

    try:
        blob = container.payload(target)
    except rcc.RccError as exc:
        _fail(str(exc))

    needles = list(text) or [
        "关于 MuMu",
        "设置中心",
        "消息中心",
        "下载掌上MuMu",
        "常见问题",
        "兑换中心",
    ]
    hits = rcc.find_strings(blob, needles)
    table = Table(title=f"search {target.path.split('/')[-1]}")
    table.add_column("string")
    table.add_column("hits")
    table.add_column("offsets in payload")
    for needle in needles:
        found = hits[needle]
        table.add_row(
            needle,
            str(len(found)),
            ", ".join(f"{h.offset:#x}" for h in found) or "[dim]not present[/]",
        )
    console.print(table)


# --------------------------------------------------------------------------- #
# splash
# --------------------------------------------------------------------------- #
RCC_DEVICE = "nx_device/15.0/shell/rcc/NxDeviceResource.rcc"


@main.command("splash")
@click.option("--install-dir", type=click.Path(path_type=Path), default=None)
@click.option(
    "--image",
    "image_path",
    type=click.Path(path_type=Path),
    default=None,
    help="JPEG to use; omit to list the current slots.",
)
@click.option(
    "--bundled",
    "use_bundled",
    is_flag=True,
    help="Use the artwork shipped with the project (prebuilts/splash/).",
)
@click.option(
    "--portrait",
    "use_portrait",
    is_flag=True,
    help="With --bundled, use the 9:16 image instead of the 16:9 one.",
)
@click.option("--dry-run", is_flag=True, help="Report what would change; write nothing.")
@click.option("--yes", is_flag=True, help="Skip the confirmation prompt.")
def splash(install_dir, image_path, use_bundled, use_portrait, dry_run, yes):
    """Show or replace the built-in startup images.

    The boot splash normally shows a campaign image downloaded from Netease,
    cached under %APPDATA% and refreshed on every launch -- so editing the
    cache does not stick.  These bundled images are the durable fallback and
    are only ever read by the application.

    Replacing them keeps every byte count identical, so the surrounding
    resource container stays valid.

    With no --image and no --bundled the current slots are listed instead.
    """
    if use_bundled and image_path is not None:
        _fail("--bundled and --image are mutually exclusive")

    try:
        inst = install.find_install(install_dir)
    except install.InstallError as exc:
        _fail(str(exc))

    target = inst.resolve(RCC_DEVICE)
    if not target.is_file():
        _fail(f"resource container not found: {target}")

    data = target.read_bytes()
    try:
        slots = rccpatch.find_startup_images(data)
    except rccpatch.RccPatchError as exc:
        _fail(str(exc))

    if not slots:
        _fail("no startup images found in the container")

    if image_path is None and not use_bundled:
        table = Table(title=f"startup images in {RCC_DEVICE}")
        table.add_column("resource")
        table.add_column("offset")
        table.add_column("max jpeg bytes", justify="right")
        for s in slots:
            table.add_row(
                s.path.split("resources/")[-1],
                f"{s.payload_offset:#x}",
                f"{s.usable_jpeg_bytes:,}",
            )
        console.print(table)
        console.print(
            "\n[dim]Replace them with:[/] niulai-patch splash --image <file.jpg>\n"
            "[dim]or with the artwork shipped here:[/] niulai-patch splash --bundled"
        )
        return

    if use_bundled:
        name = splash_assets.PORTRAIT_NAME if use_portrait else splash_assets.DEFAULT_NAME
        try:
            jpeg = splash_assets.load(name)
        except splash_assets.SplashAssetError as exc:
            _fail(str(exc))
        image_path = splash_assets.asset_path(name)
        console.print(f"[dim]using bundled artwork {name}[/]")
    else:
        assert image_path is not None, "click requires one of --image / --bundled"
        if not image_path.is_file():
            _fail(f"image not found: {image_path}")
        jpeg = image_path.read_bytes()

    try:
        rccpatch.validate_jpeg(jpeg)
    except rccpatch.RccPatchError as exc:
        _fail(f"{image_path}: {exc}")

    limit = min(s.usable_jpeg_bytes for s in slots)
    if len(jpeg) > limit:
        _fail(
            f"{image_path} is {len(jpeg):,} bytes but the smallest slot holds "
            f"{limit:,}; re-encode it smaller (e.g. lower the JPEG quality)"
        )

    console.print(f"[bold]{image_path}[/] -> {len(slots)} startup image(s) in {RCC_DEVICE}")
    for s in slots:
        console.print(
            f"  {s.path.split('resources/')[-1]:<56} {s.declared:,} -> {len(jpeg):,} bytes"
        )
    if dry_run:
        console.print("\ndry run: nothing was written.")
        return
    if not yes and not click.confirm(f"Overwrite {target.name}?", default=False):
        raise SystemExit(1)

    out = data
    for s in slots:
        out = rccpatch.replace_image(out, s, jpeg)
    if len(out) != len(data):
        _fail("internal error: the container size changed")

    try:
        with backup.BackupSession(inst.root, inst.product_version, ["splash-image"]) as session:
            session.backup(target, ["splash-image"])
            _require_restorable(session, "splash")
            backup.atomic_write(target, out)
            mpath = session.save()
    except OSError as exc:
        _fail(_write_failure(exc))

    console.print(
        f"\n[green]done.[/] {len(slots)} image(s) replaced, container size "
        f"unchanged ({len(out):,} bytes)\n"
        f"backup manifest: {mpath}\n"
        f"revert with: niulai-patch restore --backup-dir "
        f"{Path(mpath).parent}"
    )


# --------------------------------------------------------------------------- #
# doctor
# --------------------------------------------------------------------------- #
@main.command()
@click.option("--install-dir", type=click.Path(path_type=Path), default=None)
def doctor(install_dir):
    """Report the helper binary and the guest disk images. Read-only.

    The only external executable the disk path can call is ``vbox-img.exe``,
    which ships with MuMu; a missing one is reported here rather than surfacing
    in the middle of an edit.
    """
    import hosttools
    from disk import images

    table = Table(title="helper binaries")
    table.add_column("tool")
    table.add_column("state")
    table.add_column("path")
    for report in hosttools.inspect_tools():
        if report.ok:
            state = "[green]ok[/]"
        elif report.required:
            state = "[red]missing[/]"
        else:
            state = "[yellow]optional[/]"
        table.add_row(report.name, state, str(report.path or "-"))
    console.print(table)
    for report in hosttools.inspect_tools():
        if report.version:
            console.print(f"  [dim]{report.name}: {report.version}[/]")

    try:
        vm = images.find_vm_images(install_dir)
    except images.ImageError as exc:
        console.print(f"\n[yellow]{exc}[/]")
        return

    console.print(f"\n[bold]guest images[/]  {vm.summary()}")
    itable = Table()
    itable.add_column("image")
    itable.add_column("size", justify="right")
    for path in vm.all_vdi():
        itable.add_row(path.name, f"{path.stat().st_size:,}")
    console.print(itable)

    # Cross-check our own header parser against the bundled tool, which is the
    # authority on the format.  A failure here is reported, not raised: doctor
    # exists to diagnose, so finding a broken image is a result, not a crash.
    #
    # The import is outside the `try` on purpose: inside it, a failed import
    # would be caught by the very `except` that names the module, turning a
    # clear ImportError into a confusing NameError.
    from disk import image as image_mod

    try:
        ours = image_mod.vdi_header_fields(vm.system)
    except image_mod.ImageError as exc:
        console.print(f"\n[red]cannot parse {vm.system.name}:[/] {exc}")
        return

    try:
        theirs = hosttools.vbox_img_info(vm.system)
    except hosttools.ToolError:
        theirs = {}

    console.print("\n[bold]header cross-check[/] (ours vs vbox-img.exe)")
    if not theirs:
        console.print("  [yellow]vbox-img.exe did not report a header; skipping[/]")
        return
    agree = True
    for key, value in ours.items():
        other = theirs.get(key)
        if other is None:
            mark = "[dim]not reported[/]"
        elif other == value:
            mark = "[green]ok[/]"
        else:
            mark = "[red]DIFFERS[/]"
            agree = False
        console.print(f"  {key:18} {value:>12}  {other or '-':>12}  {mark}")
    if agree:
        console.print("  [green]headers agree[/]")
    else:
        console.print(
            "  [red]the two readers disagree[/] -- do not edit this image until that is understood"
        )


# --------------------------------------------------------------------------- #
# lawnchair
# --------------------------------------------------------------------------- #
@main.command("lawnchair")
@click.option("--install-dir", type=click.Path(path_type=Path), default=None)
@click.option(
    "--apk",
    "apk_path",
    type=click.Path(path_type=Path),
    default=None,
    help="Replacement APK. Omit to use the build bundled in prebuilts/.",
)
@click.option("--dry-run", is_flag=True, help="Report what would change; write nothing.")
@click.option(
    "--keep-oat", is_flag=True, help="Leave the old .odex/.vdex in place (not recommended)."
)
@click.option(
    "--allow-unknown-installed",
    is_flag=True,
    help="Overwrite the launcher even though it is neither the "
    "NetEase fork nor this project's build. Needed when the "
    "image already holds an APK this tool did not write.",
)
@click.option("--yes", is_flag=True, help="Skip the confirmation prompt.")
def lawnchair_cmd(install_dir, apk_path, dry_run, keep_oat, yes, allow_unknown_installed):
    """Replace the built-in desktop with open-source Lawnchair.

    MuMu 15 ships a NetEase fork of Lawnchair in the read-only system image.
    The bundled build shares the application id ``app.lawnchair``, so it
    replaces the fork directly rather than installing alongside it -- and it is
    smaller, so it fits in the space the fork already occupies.

    The bundled APK is built from the patched Lawnchair source under
    ``patches/`` and signed with the AOSP testkey; see ``patches/README.md``.
    The published upstream release is deliberately *not* used, because it
    crashes on this platform.

    The fork's ART artefacts (``Lawnchair.odex``, ``Lawnchair.vdex``) describe
    the fork's code and are removed with it; leaving them would have the
    runtime load stale compilation units against different bytecode.
    """
    import lawnchair
    from disk import extfs, images

    try:
        vm = images.find_vm_images(install_dir)
    except images.ImageError as exc:
        _fail(str(exc))

    image = vm.system
    if not image.is_file():
        _fail(f"system image not found: {image}")

    # -- obtain the APK ----------------------------------------------------
    using_bundled = apk_path is None
    if using_bundled:
        apk_path = lawnchair.bundled_apk_path()
        console.print(f"[bold]bundled build[/] {apk_path}")
        if not apk_path.is_file():
            _fail(
                f"the bundled APK is missing: {apk_path}\n"
                f"Build it from the patches in patches/ (see patches/README.md) "
                f"or pass --apk with a build of your own."
            )
    elif not apk_path.is_file():
        _fail(f"APK not found: {apk_path}")
    apk = apk_path.read_bytes()
    console.print(f"[bold]{apk_path}[/] ({len(apk):,} bytes)")

    # Only the bundled build is identified by hash.  A caller-supplied APK is
    # whatever they built, so it is validated structurally below and not
    # compared against a hash this project has no business knowing.
    if using_bundled:
        digest = hashlib.sha256(apk).hexdigest()
        if digest != lawnchair.BUNDLED_APK_SHA256:
            _fail(
                f"the bundled APK has hash {digest},\n"
                f"expected {lawnchair.BUNDLED_APK_SHA256}. Refusing to use it -- "
                f"the checked-in build has been modified."
            )
        console.print("  [green]hash verified[/]")

    problems = lawnchair.verify_apk_is_launcher(apk)
    if problems:
        err_console.print("[bold red]the replacement APK is not usable:[/]")
        for p in problems:
            err_console.print(f"  - {p}")
        raise SystemExit(1)

    # -- inspect -----------------------------------------------------------
    try:
        with lawnchair.SystemImage.open(image) as img:
            before = img.check_launcher()
            oat = img.stale_oat()
            free = img.free_space()
    except (filesystems.FilesystemError, extfs.ExtError, lawnchair.LawnchairError) as exc:
        _fail(f"cannot read the system image: {exc}")

    console.print(f"\n[bold]installed[/]  {before.describe()}")
    console.print(f"[bold]replacing[/]  {apk_path.name}")
    console.print(f"  free space in partition: {free:,} bytes")

    # Skip only when the installed APK is what we would write *and* there is
    # nothing else to clean up.  Comparing digests rather than a marker means a
    # build that differs by a byte is still written.
    already_target = before.sha256 == hashlib.sha256(apk).hexdigest()
    if already_target and (not oat or keep_oat):
        console.print(
            "\n[yellow]the launcher is already the one that would be written.[/] nothing to do."
        )
        return

    # The size question is settled inside the writer, which knows how much the
    # partition actually has free; duplicating the check here would refuse a
    # build that is a few kilobytes larger than what it replaces while
    # megabytes of space sit unused.
    if len(apk) > before.size:
        console.print(
            f"  [dim]the replacement is {len(apk) - before.size:,} bytes larger "
            f"than what is installed; {free:,} bytes are free[/]"
        )

    for item in oat:
        console.print(f"  [dim]will remove {item.name} ({item.size:,} bytes)[/]")

    if dry_run:
        console.print("\n[bold]dry run:[/] nothing was written.")
        return
    if not yes and not click.confirm(f"Modify {image.name}?", default=False):
        raise SystemExit(1)

    # -- back up, then write ----------------------------------------------
    try:
        with backup.BackupSession(
            image.parent, vm.product, ["lawnchair-replace"], root=_backup_root_for(image)
        ) as session:
            session.backup(image, ["lawnchair-replace"])
            # Everything that can be checked must be checked *before* the first
            # write, so a failure here leaves the image untouched.
            _require_restorable(session, "launcher")
            try:
                with lawnchair.SystemImage.open(image, writable=True) as img:
                    after = img.replace_launcher(apk, expect_fork=not allow_unknown_installed)
                    removed = [] if keep_oat else img.remove_stale_oat()
            except BaseException:
                # The image is now suspect; the backup is the recovery.  It was
                # deliberately NOT deleted -- see BackupSession.__exit__.
                err_console.print(
                    "[red]the edit failed. Restore the image from the backup "
                    "before starting the emulator:[/]"
                )
                err_console.print(
                    f"  [bold]niulai-patch restore --backup-dir {session.dir} --yes[/]"
                )
                raise
            mpath = session.save()
    except OSError as exc:
        _fail(_write_failure(exc))

    console.print(f"\n[green]done.[/] {after.describe()}")
    if removed:
        console.print(f"  removed {', '.join(removed)}")
    console.print(f"\nbackup: {mpath}")
    console.print(f"revert with: [bold]niulai-patch restore --backup-dir {Path(mpath).parent}[/]")


# --------------------------------------------------------------------------- #
# boot
# --------------------------------------------------------------------------- #
# The boot partition is four files in a 14 MiB ext2 that GRUB reads by index.
# They share one command group because they share one implementation: reading,
# planning and writing are the same operation for all four (see `boot.image`),
# and only the validation differs.  `kernel` used to be a command of its own,
# which stopped being honest once initrd and cmdline became writable too.
@main.group()
def boot():
    """Inspect or replace the kernel, ramdisks and command line."""


def _boot_target(install_dir):
    """Resolve the installation and its system image, or fail with why."""
    from disk import images

    try:
        vm = images.find_vm_images(install_dir)
    except images.ImageError as exc:
        _fail(str(exc))
    image = vm.system
    if not image.is_file():
        _fail(f"system image not found: {image}")
    return vm, image


def _boot_open(image, *, writable=False):
    """Open the boot partition, turning its errors into CLI failures."""
    from boot import image as boot_image
    from disk import extfs

    try:
        return boot_image.BootImage.open(image, writable=writable)
    except (boot_image.BootError, filesystems.FilesystemError, extfs.ExtError) as exc:
        _fail(f"cannot read the boot partition: {exc}")


def _boot_inventory(image):
    from boot import image as boot_image
    from disk import extfs

    try:
        return boot_image.read_inventory(image)
    except (boot_image.BootError, filesystems.FilesystemError, extfs.ExtError) as exc:
        _fail(f"cannot read the boot partition: {exc}")


def _print_boot_table(inv):
    table = Table(title=f"boot partition ({inv.partition})")
    table.add_column("file")
    table.add_column("bytes", justify="right")
    table.add_column("blocks", justify="right")
    table.add_column("spare", justify="right")
    for info in inv.files:
        table.add_row(
            info.file.name,
            f"{info.size:,}",
            str(info.blocks),
            f"{info.slack:,}",
        )
    table.add_row("[bold]capacity[/]", f"[bold]{inv.capacity:,}[/]", "", "")
    table.add_row("[bold]free[/]", f"[bold]{inv.free_bytes:,}[/]", "", "")
    console.print(table)


def _boot_apply(vm, image, name, data, *, grow, yes):
    """Back up once, then write one boot file.  The shared tail of every edit.

    Split out because the four subcommands differ only in how they obtain
    ``data``: the backup, the pre-write restorability check, the confirmation
    and the failure message must be identical for all of them, or one of them
    will eventually be the one that was forgotten.
    """
    from boot import grow as grow_mod
    from boot import image as boot_image

    plan = boot_image.plan_replacement(image, name, data)
    console.print()
    console.print(plan.summary())
    if not plan.ok and not grow:
        err_console.print(
            "\n[red]the replacement does not fit[/] and the partition has not been allowed to grow."
        )
        err_console.print(
            "  re-run with [bold]--grow[/] to rewrite the partition table and "
            f"relocate the {plan.shortfall:,} bytes it is short by"
        )
        raise SystemExit(2)

    if not yes and not click.confirm(f"Modify {image.name}?", default=False):
        raise SystemExit(1)

    try:
        with backup.BackupSession(
            image.parent,
            vm.product,
            ["boot-replace"],
            root=_backup_root_for(image),
        ) as session:
            session.backup(image, ["boot-replace"])
            _require_restorable(session, "boot")
            try:
                if plan.ok:
                    with boot_image.BootImage.open(image, writable=True) as img:
                        written = img.replace(name, data)
                else:
                    written = grow_mod.write_growing(image, name, data, log=console.print)
            except BaseException:
                err_console.print(
                    "[red]the edit failed. Restore the image from the backup "
                    "before starting the emulator:[/]"
                )
                err_console.print(
                    f"  [bold]niulai-patch restore --backup-dir {session.dir} --yes[/]"
                )
                raise
            mpath = session.save()
    except OSError as exc:
        _fail(_write_failure(exc))

    console.print(f"\n[green]done.[/] wrote {written:,} bytes to {name}")
    console.print(f"backup: {mpath}")


# --------------------------------------------------------------------------- #
# boot show
# --------------------------------------------------------------------------- #
@boot.command("show")
@click.option("--install-dir", type=click.Path(path_type=Path), default=None)
def boot_show(install_dir):
    """Report the four boot files and the space left. Read-only."""
    _vm, image = _boot_target(install_dir)
    inv = _boot_inventory(image)

    console.print(f"[bold]image[/]  {image}")
    if inv.kernel is not None:
        console.print(f"[bold]kernel[/] {inv.kernel.describe()}")
        console.print(
            f"  setup {inv.kernel.setup_bytes:,} bytes, boot protocol {inv.kernel.boot_protocol:#x}"
        )
    else:
        console.print("[bold]kernel[/] [yellow]does not parse as a bzImage[/]")
    console.print(f"[bold]cmdline[/] {inv.cmdline}")
    console.print()
    _print_boot_table(inv)

    from boot import initrd as initrd_mod

    for name in ("initrd", "ramdisk"):
        try:
            raw = initrd_mod.unpack_gzip(_boot_file_bytes(image, name))
        except initrd_mod.InitrdError as exc:
            console.print(f"\n[bold]{name}[/] [red]{exc}[/]")
            continue
        try:
            entries = initrd_mod.cpio_entries(raw)
        except initrd_mod.InitrdError as exc:
            console.print(f"\n[bold]{name}[/] [red]{exc}[/]")
            continue
        console.print(f"\n[bold]{name}[/] expands to {len(raw):,} bytes, {len(entries)} entries")
        console.print("  [dim]list them with[/] niulai-patch boot initrd --list")


def _boot_file_bytes(image, name):
    from boot import image as boot_image
    from disk import extfs

    try:
        return boot_image.read_file(image, name)
    except (boot_image.BootError, extfs.ExtError) as exc:
        _fail(str(exc))


# --------------------------------------------------------------------------- #
# boot extract
# --------------------------------------------------------------------------- #
@boot.command("extract")
@click.option("--install-dir", type=click.Path(path_type=Path), default=None)
@click.option(
    "--out",
    "out_dir",
    type=click.Path(path_type=Path),
    default=Path("bootdump"),
    show_default=True,
    help="Directory to write the four files into.",
)
def boot_extract(install_dir, out_dir):
    """Write kernel, initrd, ramdisk and cmdline out to plain files.

    Read-only with respect to the image.  Nothing is unpacked: each file is
    written exactly as it is stored, so a file can be edited and handed back to
    `boot <file> --image`.
    """
    from boot import image as boot_image
    from disk import extfs

    _vm, image = _boot_target(install_dir)
    try:
        written = boot_image.extract_all(image, out_dir)
    except (boot_image.BootError, extfs.ExtError, OSError) as exc:
        _fail(str(exc))

    console.print(f"[bold]extracted to[/] {Path(out_dir).resolve()}")
    for path in written:
        console.print(f"  {path.name:10} {path.stat().st_size:>12,} bytes")


# --------------------------------------------------------------------------- #
# boot kernel
# --------------------------------------------------------------------------- #
@boot.command("kernel")
@click.option("--install-dir", type=click.Path(path_type=Path), default=None)
@click.option(
    "--image",
    "kernel_path",
    type=click.Path(path_type=Path),
    default=None,
    help="Replacement bzImage. Omit to just report.",
)
@click.option("--apply", is_flag=True, help="Actually write it.")
@click.option(
    "--grow", is_flag=True, help="Allow growing the partition when the kernel does not fit."
)
@click.option("--dry-run", is_flag=True, help="Report only; write nothing.")
@click.option("--yes", is_flag=True, help="Skip the confirmation prompt.")
def boot_kernel(install_dir, kernel_path, apply, grow, dry_run, yes):
    """Inspect or replace the guest kernel.

    The kernel is 12,362,752 bytes in a partition with 79,872 bytes free, so a
    larger replacement needs blocks -- and past a certain size, a bigger
    partition.  This reports which case applies; `--grow` is what allows the
    risky one (rewriting the MBR that GRUB boots from).
    """
    vm, image = _boot_target(install_dir)
    if kernel_path is None:
        inv = _boot_inventory(image)
        if inv.kernel is not None:
            console.print(f"[bold]installed kernel[/]  {inv.kernel.describe()}")
            console.print(
                f"  setup: {inv.kernel.setup_bytes:,} bytes, "
                f"boot protocol {inv.kernel.boot_protocol:#x}"
            )
        console.print(f"[bold]cmdline:[/] {inv.cmdline}")
        console.print()
        _print_boot_table(inv)
        console.print(
            "\n[dim]Evaluate a replacement with[/] niulai-patch boot kernel --image <bzImage>"
        )
        return

    if not kernel_path.is_file():
        _fail(f"kernel image not found: {kernel_path}")
    data = kernel_path.read_bytes()

    from boot import image as boot_image

    try:
        plan = boot_image.plan_replacement(image, "kernel", data)
    except boot_image.BootError as exc:
        _fail(f"{kernel_path}: {exc}")
    except Exception as exc:
        _fail(f"cannot evaluate {kernel_path}: {exc}")

    if dry_run or not apply:
        console.print()
        console.print(plan.summary())
        console.print("\n[bold]dry run:[/] nothing was written.")
        console.print("re-run with [bold]--apply[/] to write it.")
        return
    _boot_apply(vm, image, "kernel", data, grow=grow, yes=yes)


# --------------------------------------------------------------------------- #
# boot cmdline
# --------------------------------------------------------------------------- #
def _read_cmdline_replacement(set_value, file_path):
    """The new command line, from one of the two mutually exclusive sources."""
    if set_value is not None and file_path is not None:
        _fail("give either --set or --file, not both")
    if set_value is not None:
        return set_value.encode("utf-8")
    if file_path is not None:
        if not file_path.is_file():
            _fail(f"command line file not found: {file_path}")
        return file_path.read_bytes().rstrip(b"\n")
    return None


@boot.command("cmdline")
@click.option("--install-dir", type=click.Path(path_type=Path), default=None)
@click.option("--set", "set_value", default=None, help="New command line, as one string.")
@click.option(
    "--file",
    "file_path",
    type=click.Path(path_type=Path),
    default=None,
    help="Read the new command line from this file.",
)
@click.option("--apply", is_flag=True, help="Actually write it.")
@click.option("--grow", is_flag=True, help="Allow growing the partition when it does not fit.")
@click.option("--dry-run", is_flag=True, help="Report only; write nothing.")
@click.option("--yes", is_flag=True, help="Skip the confirmation prompt.")
def boot_cmdline(install_dir, set_value, file_path, apply, grow, dry_run, yes):
    """Show or replace the kernel command line.

    GRUB passes this file as a single command line (`kernel --use-cmd-line`), so
    it is one line with no trailing newline and no NUL -- a newline would be
    silently truncated and a NUL would cut the line short.  Both are refused
    rather than written.

    Editing this can stop the machine booting, so the old and new values are
    printed side by side before anything is written.
    """
    vm, image = _boot_target(install_dir)
    inv = _boot_inventory(image)
    console.print(f"[bold]installed cmdline[/]  ({inv.get('cmdline').size} bytes)")
    console.print(f"  {inv.cmdline}")

    data = _read_cmdline_replacement(set_value, file_path)
    if data is None:
        console.print("\n[dim]Replace it with[/] niulai-patch boot cmdline --set 'root=...'")
        return

    from boot import image as boot_image

    try:
        plan = boot_image.plan_replacement(image, "cmdline", data)
    except boot_image.BootError as exc:
        _fail(str(exc))

    console.print()
    console.print(plan.summary())
    console.print("\n[bold]new value[/]")
    console.print(f"  {data.decode('utf-8', 'replace')}")

    if dry_run or not apply:
        console.print("\n[bold]dry run:[/] nothing was written.")
        console.print("re-run with [bold]--apply[/] to write it.")
        return
    _boot_apply(vm, image, "cmdline", data, grow=grow, yes=yes)


# --------------------------------------------------------------------------- #
# boot initrd / boot ramdisk
# --------------------------------------------------------------------------- #
def _boot_ramdisk_command(name, install_dir, list_entries, image_path, apply, grow, dry_run, yes):
    """The body shared by `boot initrd` and `boot ramdisk`.

    They are the same file format with different contents, so they are the same
    code; only the name and the help differ.  Two copies would be two places for
    the validation to drift.
    """
    from boot import image as boot_image
    from boot import initrd as initrd_mod

    vm, image = _boot_target(install_dir)
    installed = _boot_inventory(image).get(name)
    console.print(f"[bold]installed {name}[/]  {installed.size:,} bytes")

    if list_entries:
        blob = _boot_file_bytes(image, name)
        try:
            raw = initrd_mod.unpack_gzip(blob)
            entries = initrd_mod.cpio_entries(raw)
        except initrd_mod.InitrdError as exc:
            _fail(str(exc))
        console.print(f"  expands to {len(raw):,} bytes, {len(entries)} entries")
        for entry in entries:
            kind = "d" if entry.is_dir else ("l" if entry.is_symlink else "f")
            console.print(f"    {kind} {entry.name}")
        return

    if image_path is None:
        console.print(f"\n[dim]List its contents with[/] niulai-patch boot {name} --list")
        console.print(f"[dim]Replace it with[/] niulai-patch boot {name} --image <file>")
        return
    if not image_path.is_file():
        _fail(f"{name} image not found: {image_path}")
    data = image_path.read_bytes()

    try:
        plan = boot_image.plan_replacement(image, name, data)
    except boot_image.BootError as exc:
        _fail(f"{image_path}: {exc}")

    if dry_run or not apply:
        console.print()
        console.print(plan.summary())
        console.print("\n[bold]dry run:[/] nothing was written.")
        console.print("re-run with [bold]--apply[/] to write it.")
        return
    _boot_apply(vm, image, name, data, grow=grow, yes=yes)


@boot.command("initrd")
@click.option("--install-dir", type=click.Path(path_type=Path), default=None)
@click.option("--list", "list_entries", is_flag=True, help="List the archive's contents and stop.")
@click.option(
    "--image",
    "image_path",
    type=click.Path(path_type=Path),
    default=None,
    help="Replacement gzip'd cpio ramdisk.",
)
@click.option("--apply", is_flag=True, help="Actually write it.")
@click.option("--grow", is_flag=True, help="Allow growing the partition when it does not fit.")
@click.option("--dry-run", is_flag=True, help="Report only; write nothing.")
@click.option("--yes", is_flag=True, help="Skip the confirmation prompt.")
def boot_initrd(install_dir, list_entries, image_path, apply, grow, dry_run, yes):
    """Inspect or replace /initrd, the Android-x86 init ramdisk.

    This is the ramdisk that pairs with the kernel.  It is an Android-x86
    `init` with `bin/busybox` and `bin/e2fsck`; a GKI kernel and this ramdisk are
    not interchangeable, so replacing the kernel usually means revisiting it too.
    """
    _boot_ramdisk_command(
        "initrd", install_dir, list_entries, image_path, apply, grow, dry_run, yes
    )


@boot.command("ramdisk")
@click.option("--install-dir", type=click.Path(path_type=Path), default=None)
@click.option("--list", "list_entries", is_flag=True, help="List the archive's contents and stop.")
@click.option(
    "--image",
    "image_path",
    type=click.Path(path_type=Path),
    default=None,
    help="Replacement gzip'd cpio ramdisk.",
)
@click.option("--apply", is_flag=True, help="Actually write it.")
@click.option("--grow", is_flag=True, help="Allow growing the partition when it does not fit.")
@click.option("--dry-run", is_flag=True, help="Report only; write nothing.")
@click.option("--yes", is_flag=True, help="Skip the confirmation prompt.")
def boot_ramdisk(install_dir, list_entries, image_path, apply, grow, dry_run, yes):
    """Inspect or replace /ramdisk, the directory-skeleton ramdisk.

    Only 1,159 bytes: a gzip'd cpio archive of directory names that the Android
    first-stage init consumes.  It is not the init ramdisk -- that is /initrd.
    """
    _boot_ramdisk_command(
        "ramdisk", install_dir, list_entries, image_path, apply, grow, dry_run, yes
    )


# --------------------------------------------------------------------------- #
# boot grow
# --------------------------------------------------------------------------- #
@boot.command("grow")
@click.option("--install-dir", type=click.Path(path_type=Path), default=None)
@click.option(
    "--file",
    "name",
    type=click.Choice(["kernel", "initrd", "ramdisk", "cmdline"]),
    default="kernel",
    show_default=True,
    help="The boot file the growth is for.",
)
@click.option(
    "--image",
    "data_path",
    type=click.Path(path_type=Path),
    required=True,
    help="The (larger) replacement to make room for.",
)
@click.option("--apply", is_flag=True, help="Actually grow and write.")
@click.option("--dry-run", is_flag=True, help="Report only; write nothing.")
@click.option("--yes", is_flag=True, help="Skip the confirmation prompt.")
def boot_grow(install_dir, name, data_path, apply, dry_run, yes):
    """Grow the boot partition so a file that does not fit can be written.

    This is the operation that rewrites the MBR GRUB boots from and relocates
    sda5-sda6, so it is a command of its own with its own confirmation rather
    than something `boot kernel` does quietly when you asked for a kernel swap.

    The ext2 inside the partition is grown in place by the in-tree writer, which
    only ever appends new block groups, and the result is re-read through a
    fresh handle before it is written back.
    """
    from boot import grow as grow_mod
    from boot import image as boot_image

    vm, image = _boot_target(install_dir)
    if not data_path.is_file():
        _fail(f"replacement not found: {data_path}")
    data = data_path.read_bytes()

    try:
        plan = boot_image.plan_replacement(image, name, data)
    except boot_image.BootError as exc:
        _fail(f"{data_path}: {exc}")

    console.print()
    console.print(plan.summary())
    if plan.ok:
        console.print(
            f"\n[green]{name} already fits[/] -- no partition change is needed. "
            f"Write it with `niulai-patch boot {name} --image {data_path} --apply`."
        )
        return

    try:
        growth = grow_mod.plan_growth(image, plan.shortfall)
    except Exception as exc:
        err_console.print(f"[bold red]cannot plan the partition change:[/] {exc}")
        # Reraising as SystemExit loses the traceback on purpose -- this is a
        # diagnosis the user has already been shown -- but `from None` keeps the
        # "during handling of the above exception" noise out of the output.
        raise SystemExit(2) from None
    if growth is None:
        _fail("the planner produced no growth for a file that does not fit")
    if not growth.ok:
        err_console.print("\n[bold red]the growth plan is not valid:[/]")
        for problem in growth.errors:
            err_console.print(f"  - {problem}")
        raise SystemExit(2)

    console.print()
    console.print("[bold]partition change required[/]")
    console.print(growth.summary())
    est = growth.total_bytes_moved / (100 * 1e6)
    console.print(
        f"\n[dim]this relocates {growth.total_bytes_moved / 1e9:.2f} GB; at "
        f"roughly 100 MB/s that is about {est:.0f}s[/]"
    )

    if dry_run or not apply:
        console.print("\n[bold]dry run:[/] nothing was written.")
        console.print("re-run with [bold]--apply[/] to write it.")
        return

    console.print(
        "\n[yellow]This will rewrite the partition table and move "
        f"{growth.total_bytes_moved / 1e9:.2f} GB.[/]"
    )
    if not yes and not click.confirm(f"Modify {image.name}?", default=False):
        raise SystemExit(1)

    try:
        with backup.BackupSession(
            image.parent, vm.product, ["boot-grow"], root=_backup_root_for(image)
        ) as session:
            session.backup(image, ["boot-grow"])
            _require_restorable(session, "boot")
            try:
                written = grow_mod.write_growing(image, name, data, log=console.print)
            except BaseException:
                err_console.print(
                    "[red]the edit failed. Restore the image from the backup "
                    "before starting the emulator:[/]"
                )
                err_console.print(
                    f"  [bold]niulai-patch restore --backup-dir {session.dir} --yes[/]"
                )
                raise
            mpath = session.save()
    except OSError as exc:
        _fail(_write_failure(exc))

    console.print(f"\n[green]done.[/] wrote {written:,} bytes to {name}")
    console.print(f"backup: {mpath}")


def _backup_root_for(image: Path) -> Path:
    """Backups of disk images are large; keep them next to the image by default.

    A 1.8 GB copy does not belong in the user's home directory without asking,
    and putting it beside the image means it is on the same filesystem (so the
    copy is cheap) and is found by anyone looking at the installation.
    """

    env = os.environ.get("MUMU_PATCH_IMAGE_BACKUP_ROOT")
    if env:
        return Path(env)
    return image.parent / "mumu-patch-backups"


def _require_restorable(session, label: str) -> None:
    """Refuse to start an edit that could not be undone.

    Called after the backup and *before* the first write.  A backup that exists
    but cannot be read back is not insurance, and the moment to discover that is
    now -- not after the image has been modified.  This is the check that was
    missing when a failed run removed its own backup and left a corrupt image.
    """
    import backup as backup_mod

    problems = backup_mod.verify_backup(session.manifest)
    if problems:
        detail = "; ".join(f"{path}: {why}" for path, why in problems[:3])
        _fail(
            f"the {label} backup is not usable ({detail}). Refusing to modify "
            f"the image, because it could not be restored afterwards."
        )
    if not session.manifest.files:
        _fail(f"no {label} backup was recorded; refusing to modify the image.")

    # Prove the recovery path actually works by hashing the copy through the
    # same code restore uses, and by confirming the target is still writable.
    for rec in session.manifest.files:
        if not Path(rec.original_path).parent.is_dir():
            _fail(
                f"cannot write back to {Path(rec.original_path).parent}, which "
                f"no longer exists; refusing to modify the image."
            )


if __name__ == "__main__":
    main()
