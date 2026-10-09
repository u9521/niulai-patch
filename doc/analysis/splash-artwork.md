# The startup splash artwork

Where the boot image comes from, the container format, and the bundled replacements.

## The image the user sees

Section 19 identified the boot splash and patched the carousel so it takes the
"display not allowed" path. That stopped the rotation but **did not remove the
advertisement**: a live run still showed the campaign artwork. The reason is
that the campaign is not drawn by the carousel code at all.

### Where the artwork actually comes from

The device window downloads campaign images into

```
%APPDATA%/Netease/MuMuPlayer/data/startupImage/<campaignId>/
    Normal.jpeg  Hover.jpeg  Pressed.jpeg
imageManager.json
```

``imageManager.json`` lists each campaign with its three image URLs, a
``linkUrl`` (``mumu://store/appdetail/<id>?from=启动广告``), and a ``display``
flag. Crucially the application **rewrites this file on every launch** --
observed directly, it was re-written two seconds after the process started --
so editing anything in that directory is undone the next time the emulator
runs. That rules out the cache as a durable place to intervene.

What the application cannot undo is the **bundled fallback artwork** in

```
nx_device/15.0/shell/rcc/NxDeviceResource.rcc
```

which is read-only in practice and is what appears once the campaign is
suppressed.

### The container format

The nine ``img_startup_*.jpeg`` resources are stored **uncompressed**
(``flags == 0``) as::

    <u32 big-endian length><JPEG bytes>

Two properties make an in-place edit safe, and both were verified against the
real container rather than assumed:

* a resource record carries **no size field** -- a payload runs until the next
  resource's offset, in packed offset order. Changing a length would silently
  shift every later resource, so replacements keep the byte count identical;
* the declared length + 4 equals the slot size for **all nine** copies, and
  the final payload ends exactly where the names block begins
  (``0xda2bf1 + 4 + 160079 == 0xdc9d5c``).

A JPEG decoder stops at the ``FF D9`` end-of-image marker, so a replacement
smaller than its slot is zero-padded and still renders correctly. A larger one
cannot be used at all -- the writer raises rather than truncating, because a
silently clipped JPEG produces a corrupt frame that is far harder to diagnose
than a refusal.

The nine slots and their capacities:

| resource | capacity |
| --- | --- |
| ``images/nx/device/jpeg/img_startup_vertical_15.jpeg`` | 571,624 |
| ``images/nx/device/jpeg/img_startup_landscape_15.jpeg`` | 571,624 |
| ``images/nx/device/jpeg/img_startup_landscape_default_15.jpeg`` | 571,624 |
| ``images/nx/device/jpeg/img_startup_vertical.jpeg`` | 599,990 |
| ``images/nx/device/jpeg/img_startup_landscape.jpeg`` | 599,990 |
| ``images/nx/device/jpeg/img_startup_landscape_default.jpeg`` | 599,990 |
| ``images/jpeg/img_startup_vertical.jpeg`` | 785,570 |
| ``images/jpeg/img_startup_landscape.jpeg`` | 785,570 |
| ``images/jpeg/img_startup_landscape_default.jpeg`` | 785,570 |

All nine are replaced together: which one is used depends on window mode and
orientation (the paths are built by small per-variant getters at ``0xf81a0``
onwards), so replacing only some would leave the ad visible in some layouts.

### Tooling

``rcc.rccpatch`` does the work, and ``niulai-patch splash`` is the entry
point::

    niulai-patch splash                       # list the slots and capacities
    niulai-patch splash --image mine.jpg      # replace all nine

The operation is reversible: a backup of the whole container is taken first,
and ``niulai-patch restore --backup-dir <dir>`` puts it back.

### The logo is a flag, not an asset

The splash also draws the MuMu logo (an 80x80 ``ic_logo.svg``
``NemuSvgWidget``) on top of the background. Replacing those SVG resources in the
container alongside the JPEGs is **not** supported: replacing artwork the user
did not ask to change is the wrong lever, it does not survive an overlay
resource pack, and the binary already exposes the honest control.

``StartupMiddleLogo`` (feature id 51) gates it:

```
mov  edx, 33h                     ; id 51
call Controller_IsFeatureEnabled  ; 0x140011e96
test al, al
jz   loc_1402A1F61                ; not enabled -> skip the logo
```

``feature.startup_middle_logo.enabled`` is the config key, but the stock install
has no ``features.json`` and creating one turns *every other* device feature on
as a side effect (an absent file already means "all on"; see 24.1). So the
``splash-logo`` patch in ``src/pe/patches/device-ui.toml`` instead rewrites the
6-byte ``jz`` at ``0x2a1e29`` into a 5-byte ``jmp`` plus one NOP, always taking
the author's own skip branch. Both forms reach ``0x2a1f61`` exactly.

``find_logos``/``validate_svg`` were deleted with the ``niulai-patch logo``
command; ``rccpatch`` now only handles the startup JPEGs.


## The bundled artwork that replaces it

The splash shown while a device boots is drawn by `StartupBkWidget`
(`sub_1402A4C10`), which is fed by `StartupImageManager`.  Two sources exist,
and only one of them is durable.

### The volatile source

`StartupImageManager::fetchImageInfos_` (`0x141023750`) requests

```
https://api.mumu.nie.netease.com/api/v2/campaign/launcher/launching
```

parses the campaign id, and `downloadImages_` (`0x1410256A0`) writes three JPEGs
plus an `imageManager.json` under

```
%APPDATA%\Netease\MuMuPlayer\data\startupImage\<campaignId>\
```

That JSON is rewritten on **every launch** (observed directly), so editing the
cache does not stick.  `splash-ad-download` and `splash-carousel` in the
`device-ui` profile are what remove this path from the picture entirely.

### The durable source

The fallback artwork is bundled in

```
nx_device/15.0/shell/rcc/NxDeviceResource.rcc
```

and is only ever read.  Nine resources match `img_startup_*`:

| resource | declared bytes | slot capacity | dimensions |
| --- | --- | --- | --- |
| `images/nx/device/jpeg/img_startup_vertical_15.jpeg` | 571,624 | 571,624 | 3200x1800 |
| `images/nx/device/jpeg/img_startup_vertical.jpeg` | 599,990 | 599,990 | 3200x1800 |
| `images/nx/device/jpeg/img_startup_landscape.jpeg` | 599,990 | 599,990 | 3200x1800 |
| `images/nx/device/jpeg/img_startup_landscape_15.jpeg` | 571,624 | 571,624 | 3200x1800 |
| `images/nx/device/jpeg/img_startup_landscape_default.jpeg` | 599,990 | 599,990 | 3200x1800 |
| `images/nx/device/jpeg/img_startup_landscape_default_15.jpeg` | 571,624 | 571,624 | 3200x1800 |
| `images/jpeg/img_startup_vertical.jpeg` | 785,570 | 785,570 | 3836x2160 |
| `images/jpeg/img_startup_landscape.jpeg` | 785,570 | 785,570 | 3836x2160 |
| `images/jpeg/img_startup_landscape_default.jpeg` | 785,570 | 785,570 | 3836x2160 |

**Every one of the nine is 16:9.**  The `vertical` / `landscape` names do not
describe the artwork's shape — both families carry the same aspect, and on a
stock install both carry the *same picture*.  The distinction is about which
window orientation the application selects the resource for, and it scales and
centre-crops to the window from there.

The consequence for a replacement is that **one 16:9 image serves all nine
slots**, and the only real constraint is the byte budget: the smallest slot
holds 571,624 bytes, so a JPEG at or under that fits everywhere.

### Why the replacement is in place

A `.rcc` resource record carries no explicit size: a payload runs until the next
resource's offset, so changing a payload's length would silently shift every
later resource.  `rcc/rccpatch.py` therefore overwrites the payload in place and
keeps the length identical.

Two properties make that work:

* the `img_startup_*` payloads are stored uncompressed (`flags == 0`) as
  `<u32 big-endian length><JPEG bytes>`, and the declared length plus four
  exactly equals the slot size in all nine copies;
* a JPEG decoder stops at the `FF D9` end-of-image marker, so a *shorter*
  replacement is zero-padded and still renders correctly.  A *longer* one cannot
  be used at all and is refused.

The RCC container format itself is documented in
[config-and-features.md](config-and-features.md); `src/rcc/rccpatch.py` carries
the implementation details.

### What ships

`src/prebuilts/splash/` holds two files, both encoded to fit the 571,620-byte
budget:

| file | shape | selected by |
| --- | --- | --- |
| `splash-3200x1800.jpg` | 16:9, 3200x1800 | `niulai-patch splash --bundled` (default) |
| `splash-1800x3200.jpg` | 9:16, 1800x3200 | `niulai-patch splash --bundled --portrait` |

Both are verified by SHA-256 in `src/splash.py` before being written into the
container.  The check earns its place: the payload goes straight into a 14 MB
container, where a truncated asset would show up only as a partially drawn
splash with no other symptom.

`tools/make_splash.py` regenerates both from any source picture.  It
centre-crops to 16:9 for the landscape file and cover-crops to 9:16 for the
portrait one, then encodes each at the highest quality that still fits.

A letterbox-with-blurred-backdrop treatment was tried for the portrait variant
and rejected: this artwork is far brighter at the subject than at the edges, so
the pasted band showed a seam that feathering did not remove.  A cover-crop is
what the application itself does to a mismatched aspect anyway, so doing it in
the generator makes the crop deliberate rather than leaving it to Qt.
