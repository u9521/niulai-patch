# The startup splash

Replacing the bundled boot artwork in the device shell's RCC.

The image shown while a device boots is normally campaign artwork fetched from
`api.mumu.nie.netease.com` and cached under `%APPDATA%`, which is rewritten on
every launch — so editing the cache does not stick. The durable copy is the
fallback bundled in the device shell's Qt resource container:

```
nx_device/15.0/shell/rcc/NxDeviceResource.rcc
```

```bash
# List the nine slots and the largest JPEG each one holds
uv run niulai-patch splash

# Apply the artwork that ships with the project
uv run niulai-patch splash --bundled --yes

# Or supply a picture of your own
uv run niulai-patch splash --image /tmp/splash.jpg --yes
```

Replacement is **in place and byte-count preserving**: a resource record carries
no explicit size, so a payload runs until the next resource's offset and any
change in length would shift every later resource. A JPEG decoder stops at the
`FF D9` end-of-image marker, so a shorter replacement is zero-padded and still
renders; a longer one is refused with the two numbers.

Two images ship under `src/prebuilts/splash/`, both encoded to fit the smallest of
the nine slots (571,620 bytes):

| File | Shape | Use |
| --- | --- | --- |
| `splash-3200x1800.jpg` | 16:9 | the default; every slot is 16:9 |
| `splash-1800x3200.jpg` | 9:16 | `--portrait`, for tall windows |
| `source.jpg` | 2197x1260 | the picture the two above were derived from |

The slots are named `img_startup_vertical*` and `img_startup_landscape*`, but
all nine are 16:9 in the container — the vendor ships the same shape for both —
so 16:9 is what `--bundled` picks unless `--portrait` is given. Both files are
verified by SHA-256 before being written, because a truncated asset would
otherwise show up only as a half-drawn splash.

Regenerate them from a new source with:

```bash
python tools/make_splash.py path/to/source.jpg
```

The script centre-crops to 16:9 for the landscape file and cover-crops to 9:16
for the portrait one, then encodes each to the tightest quality that still fits
the slot budget.
