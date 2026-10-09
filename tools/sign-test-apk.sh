#!/usr/bin/env bash
# Sign a launcher APK with the AOSP testkey, so it can be adb-installed over
# the build that is in the system image.
#
# Why this exists
# ---------------
# The launcher in /system/priv-app/Lawnchair is built from source and signed
# with the AOSP testkey (see patches/README.md).  Android refuses to update an
# installed package with an APK signed by a different key, so a test build has
# to be signed with the *same* key to be installable:
#
#     ./tools/sign-test-apk.sh in.apk out.apk
#     adb install -r out.apk
#
# The signature does not affect behaviour -- the Recents crash was a missing
# platform type, not a permissions or signature problem -- so iterating this way
# is safe and much faster than rewriting the 1.8 GB image each time.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(dirname "$here")"
key="${MUMU_TEST_KEY:-$repo/signing/testkey.pk8}"
cert="${MUMU_TEST_CERT:-$repo/signing/testkey.x509.pem}"

apksigner="${APKSIGNER:-}"
if [[ -z "$apksigner" ]]; then
  for candidate in \
    "${ANDROID_HOME:-}/build-tools"/*/apksigner \
    "${ANDROID_SDK_ROOT:-}/build-tools"/*/apksigner \
    /opt/android-sdk/build-tools/*/apksigner
  do
    [[ -x "$candidate" ]] && apksigner="$candidate"
  done
fi
if [[ -z "$apksigner" ]]; then
  echo "apksigner not found. Set APKSIGNER=/path/to/apksigner." >&2
  exit 1
fi

if [[ $# -ne 2 ]]; then
  echo "usage: $(basename "$0") <input.apk> <output.apk>" >&2
  exit 2
fi
if [[ ! -f "$key" || ! -f "$cert" ]]; then
  echo "AOSP testkey not found: $key / $cert" >&2
  echo "see patches/README.md for how to fetch it" >&2
  exit 1
fi

in="$1"
out="$2"

# zipalign first: signing does not change alignment, and an unaligned APK is
# rejected on newer platforms.  A gradle build is already aligned, so check
# before rewriting -- `zipalign -f` would produce a byte-different file for no
# reason, and it is useful for the output to be reproducible.
zipalign="$(dirname "$apksigner")/zipalign"
if [[ -x "$zipalign" ]] && ! "$zipalign" -c -p 4 "$in" >/dev/null 2>&1; then
  "$zipalign" -f -p 4 "$in" "$out.aligned"
  in="$out.aligned"
fi

"$apksigner" sign \
  --key "$key" \
  --cert "$cert" \
  --v2-signing-enabled true \
  --v3-signing-enabled true \
  --out "$out" \
  "$in" 2>&1 | grep -v '^WARNING' || true

[[ -f "$out.aligned" ]] && rm -f "$out.aligned"

"$apksigner" verify --print-certs "$out" 2>&1 | grep -E 'DN:|SHA-256 digest' || true
echo "signed: $out"
