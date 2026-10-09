# Installation layout and PE characteristics

Where MuMu installs, and what the launchers are.

```
C:\Program Files\Netease\MuMu\
  configs\install_config.json     product/version identity
  configs\main\nx_main.json       UI state, feature flags
  nx_main\                        Qt 5 GUI (the launcher window)
    MuMuNxMain.exe                  30,637,560 bytes, PE32+ x64, 9 sections
    MuMuManager.exe                 21,389,816 bytes
    mumu-cli.exe                    21,389,816 bytes, byte-identical to above
    nemu-ui-lib.dll                 UI widgets
    nemu-statistics.dll             statistics / telemetry module
    mumu-qt-extensions.dll, QCefView.dll
    rcc\*.rcc                       Qt binary resources
  nx_device\15.0\
    shell\                          QtWebEngine shell + bundled CEF/Chromium
      MuMuNxDevice.exe
      CefView\libcef.dll, resources.pak, locales\zh-CN.pak
      resources\dist\               Vue SPA sources (263 .js, 91 .css)
      rcc\NxDeviceResource.rcc      14,597,570 bytes
    vms\MuMuPlayer-15.0-base\       VM images (system.vdi ~1.8 GB)
```

`MuMuManager.exe` and `mumu-cli.exe` share MD5 `c6f6f1e3b337299dbd1164dc3915c115`,
so any patch targeting one applies to both.

## PE characteristics of MuMuNxMain.exe

| Property | Value |
| --- | --- |
| Machine | `0x8664` (x64) |
| Sections | 9 (`.text .rdata .data .pdata .idata .tls .00cfg .rsrc .reloc`) |
| DllCharacteristics | `0x8160` — includes `DYNAMIC_BASE`, i.e. **ASLR is on** |
| PE checksum | `0x01d3e478` (verified: our reimplementation reproduces it) |
| Signature | `WIN_CERTIFICATE`, 10,744 bytes at file offset `0x1d35400` |

Two consequences drove the tool's design:

* **ASLR means runtime addresses are not stable.** A `lea` seen in x64dbg is
  only reproducible as an RVA, so every signature and `known_rvas` entry is
  expressed as an RVA and converted at the edges.
* **The signature is standard, not exotic.** `dwLength` (10,744) equals the
  security directory size exactly, `wRevision` = `0x0200`,
  `wCertType` = 2, then a plain PKCS#7 blob with no trailing padding. Stripping
  is ordinary: zero the directory entry, truncate at `0x1d35400`, recompute the
  checksum. The signature is at the very end of the file, so truncation cannot
  damage any section (asserted in `tests/test_pe.py`).
