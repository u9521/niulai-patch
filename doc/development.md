# Development

Running the tests, and what the disk-layer suite carries.

```bash
uv run pytest -q
```

The suite covers the PE checksum algorithm (asserted against the stored value in
the real 30 MB binary, not merely self-consistency), signature parsing and the
ambiguity guards, backup/restore including tamper refusal, an end-to-end
patch → verify → restore round trip, and — for the disk layer — synthetic
VDI/ext2 fixtures plus a read-only class that runs against the installed image
when there is one.

That last group carries the most weight. Every real bug found while writing the
ext2 reader was caught there and *not* by the synthetic fixtures:

| Bug | Symptom |
| --- | --- |
| `ext4_extent_idx` read as an extent | start block `0x400000000` in a 421,086-block filesystem |
| directories routed to the classic block map | `corrupt directory entry at 0 (rec_len=48640)` |
| `cbDisk` read at the wrong offset | `disk_size` of 4,503,599,627,370,496 instead of 2,463,370,240 |
| group *N* assumed to start at `N * blocks_per_group` | `block 14316 is recorded in the inode but already marked free` — a 1 KiB block size reserves block 0 as the boot block, so every bitmap bit was off by one |
| `i_blocks` counted only the 15 pointer slots | `i_blocks is 28, should be 28356` on a 12 MiB file |
| indirect tables listed from slots 12–14 only | the single-indirect tables under a double-indirect table leaked on every free |

The last three share a cause worth naming: the boot partition's bitmaps are
nearly full, so a one-bit shift usually lands on another *used* bit and the
error stays invisible until a write has to free a block at a group boundary.
The 4 KiB system partition has no boot block, so it never showed the problem.
All three are now pinned by tests that build a real filesystem with `mke2fs`
and check the answer against `debugfs`, because a hand-built fixture can only
confirm the layout it was written to have.

Those two tools are **test fixture generators, never part of the product**. The
disk path itself calls neither; `mke2fs` and `debugfs` are used only to produce
an independent filesystem for the reader to be checked against. If they are
absent the affected tests skip, and the rest of the suite still runs.

Its decisive assertion extracts the 41 MiB launcher from inside the live image
and checks its SHA-256, which exercises the extent tree end to end.

```bash
uv run pytest -q                      # everything
uv run pytest -m "not slow" -q            # skip the distribution build (~3 s saved)
uv run pytest tests/test_vdi.py -q        # container: header, BAT, read/write caches
uv run pytest tests/test_partition.py -q  # MBR, bounds, partition discovery
uv run pytest tests/test_image.py -q      # container detection, full-stack round trip
uv run pytest tests/test_disk.py -q       # ext2/ext4, and the real image
uv run pytest tests/test_boot.py -q       # the four boot files, and the real ones
uv run pytest tests/test_layout.py -q     # the flat src/ layout and its cost
uv run pytest tests/test_build.py -q      # the wheel actually contains the program
```

`tests/test_boot.py` and `tests/test_disk.py` are the two that read the
installed image; both skip cleanly when MuMu is absent.
`tests/test_robustness.py` needs the pristine vendor binaries under `.backups/`
and skips when a checkout does not have them.
`tests/test_build.py` is marked `slow` because it runs a real `uv build`.

## A sharp edge: `uv run` may run stale code

`uv_build`'s editable install **copies** the modules into `site-packages`
instead of adding `src/` to `sys.path`, and that copy shadows the live tree. So
after editing a module, a plain `uv run python -c "import cli"` can still load
the previous version.

Two things keep this from mattering in practice:

* `pythonpath = ["src"]` under `[tool.pytest.ini_options]` means the test suite
  always imports the checkout, so an edit is visible to the next `pytest` run
  without reinstalling. (Without it the suite would silently test stale copies —
  `test_layout.py::test_our_modules_resolve_inside_this_repository` is what
  catches that.)
* `uv run --reinstall-package mumu-patch <cmd>` refreshes the copy when you are
  driving the CLI by hand rather than through the tests.

## Checks

```bash
uv run pytest -q          # 776 tests
uv run pyright            # src/ only, `standard` strictness, must be clean
uv run ruff check         # lint, must be clean
uv run ruff format --check
```

`pyright` is configured in `pyproject.toml` under `[tool.pyright]`, scoped to
`src` — pointing it at `tests/` roughly doubles the error count for mostly
fixture-shaped noise.

Two annotations account for most of the type coverage and are worth not
"cleaning up":

* `cli._fail` returns `NoReturn`. It is used as a failure guard whose callers go
  on to use the value being guarded, so without this every such value reads as
  possibly-unbound.
* The six `__exit__` methods return `Literal[False]`, not `bool`. `bool` tells a
  checker the context manager *might* swallow the exception, which makes every
  variable assigned inside the `with` possibly-unbound.

## Building

```bash
uv build          # sdist + wheel into dist/
```

The backend is `uv_build`, configured in `pyproject.toml`. This project ships a
flat `src/` — loose modules (`cli.py`, `backup.py`) alongside packages (`pe/`,
`disk/`) — which `uv_build` cannot express by default: it expects every
`module-name` to be a directory with an `__init__.py`. The combination that
works is `module-name = []` plus `namespace = true`, with
`[tool.uv.build-backend.data] purelib = "src"` doing the actual file selection.

That last line is the one to be careful with. Without it the build still
*succeeds* and produces a wheel containing nothing but `.dist-info`;
`tests/test_build.py` asserts the manifest precisely so that failure cannot go
unnoticed. The same config also rejects `dynamic = ["version"]`, which is why the
version appears both in `pyproject.toml` and `src/__about__.py` and why
`test_layout.py` asserts the two agree.

The non-Python assets — the launcher APK and the startup JPEGs — live in
`src/prebuilts/`, inside the module root, because that is the only place
`uv_build` will pick them up. `lawnchair.py` and `splash.py` resolve them
relative to `__file__`, which works both in a checkout and after installation.

## Verifying an edit

Every edit path ends by re-reading what it wrote through a fresh handle and
checking the structural invariants. That is a *self*-consistency check: it uses
the same reader that wrote the data, so it can catch a mistake but cannot
certify the result the way an independent implementation could. See
[analysis/disk-writer.md](analysis/disk-writer.md) for what is checked and what
is not.

If you want the independent opinion, extract the partition and run the real
`e2fsck` yourself — it is read-only and exits non-zero when something is wrong:

```bash
uv run niulai-patch boot grow --image big-bzImage --apply --yes
# then, outside this tool:
e2fsck -fn /path/to/extracted-sda3.img
```
