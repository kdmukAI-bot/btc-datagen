#!/usr/bin/env bash
# Fetch the third-party code the site is built from, at pinned versions:
# three C libraries for the WASM module (into deps/, gitignored) and one
# JavaScript library for signature verification (into site/vendor/).
#
# These are NOT git submodules on purpose. This repo is mirrored to four forges,
# and submodules make every mirror carry a URL that has to resolve from wherever
# the clone happened; a pinned manifest plus a fetch script keeps the mirrors
# plain copies. The pin is the SHA below — moving it is a deliberate, reviewable
# edit rather than a `git submodule update --remote` that quietly slides.
#
# Local checkouts win when present, so you can iterate on cUR or k_quirc in
# their own working tree and rebuild here without pushing anything:
#
#   SSQR_CUR_DIR=~/dev/seedsigner-micropython-builder/deps/cUR \
#   SSQR_KQUIRC_DIR=~/dev/esp-camera-pipeline/components/k_quirc \
#     bash tools/wasm/fetch_deps.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
DEPS="$REPO_ROOT/deps"

# --- pins -------------------------------------------------------------------
# cUR: the same UR codec the ESP32 firmware runs, so browser-generated frames
# are byte-identical to the device's rather than merely equivalent.
CUR_URL="https://github.com/kdmukAI-bot/cUR.git"
CUR_REF="0ed276bc10b70556925bb42f85149d7c837a6c51"

# k_quirc: SeedSigner's own QR decoder (OpenMV's quirc, adapted). Using the
# device's decoder to read the device's screen means a frame the browser cannot
# read is a frame the hardware would likely also struggle with.
# Pinned to the tip of `seedsigner-dev`, the branch the SeedSigner firmware
# tracks, rather than `main` — the point of using k_quirc here is that the
# browser reads the device's screen with the device's decoder, and a pin that
# lags the firmware quietly gives that up.
KQUIRC_URL="https://github.com/kdmukAI-bot/k_quirc.git"
KQUIRC_REF="494dcc738c94533810eda2e436f832ffb72b8045"

# Nayuki's QR encoder. Chosen because it exposes the exact knobs Sparrow's zxing
# call uses — fixed EC level (no automatic boost), smallest fitting version,
# automatic mask — which is what lets tools/verify.py assert byte-equality with
# the Python `qrcode` output.
QRCODEGEN_URL="https://github.com/nayuki/QR-Code-generator.git"
QRCODEGEN_REF="2c9044de6b049ca25cb3cd1649ed7e27aa055138"

# --- fetch ------------------------------------------------------------------

link_local() {
  local name="$1" src="$2"
  [ -n "$src" ] || return 1
  if [ ! -d "$src" ]; then
    echo "ERROR: $name override '$src' is not a directory" >&2
    exit 1
  fi
  rm -rf "${DEPS:?}/$name"
  ln -s "$(cd "$src" && pwd)" "$DEPS/$name"
  echo "  $name  -> local checkout $src"
}

fetch() {
  local name="$1" url="$2" ref="$3"
  local dir="$DEPS/$name"

  if [ -L "$dir" ]; then           # previous local override; take it back over
    rm -f "$dir"
  fi
  if [ ! -d "$dir/.git" ]; then
    rm -rf "$dir"
    # Full clone rather than --depth 1: a shallow clone can only check out the
    # tip, and the pin is deliberately allowed to lag the branch.
    git clone --quiet "$url" "$dir"
  fi
  if [ "$(git -C "$dir" rev-parse HEAD)" != "$ref" ]; then
    git -C "$dir" fetch --quiet origin
    git -C "$dir" checkout --quiet --detach "$ref"
  fi
  echo "  $name  @ ${ref:0:12}"
}

mkdir -p "$DEPS"
echo "==> Dependencies in $DEPS"
link_local cUR       "${SSQR_CUR_DIR:-}"       || fetch cUR       "$CUR_URL"       "$CUR_REF"
link_local k_quirc   "${SSQR_KQUIRC_DIR:-}"    || fetch k_quirc   "$KQUIRC_URL"    "$KQUIRC_REF"
link_local qrcodegen "${SSQR_QRCODEGEN_DIR:-}" || fetch qrcodegen "$QRCODEGEN_URL" "$QRCODEGEN_REF"

# --- @noble/secp256k1 -------------------------------------------------------
# The only third-party JavaScript on the site, and the only one that runs on a
# visitor's phone, so it is pinned by CONTENT HASH rather than by version: a
# version tag is a name the registry controls, a sha256 is not. The build fails
# closed if the bytes are not exactly what was reviewed.
#
# Used solely to verify signatures out of the PSBT the SeedSigner hands back.
# Nothing here signs anything, and no secret ever enters the browser.
#
# One file, zero dependencies, MIT. Version 3 dropped DER signature support, so
# site/psbt.js converts Bitcoin's DER sigs to the 64-byte compact form itself.
NOBLE_VERSION="3.1.0"
NOBLE_URL="https://registry.npmjs.org/@noble/secp256k1/-/secp256k1-${NOBLE_VERSION}.tgz"
NOBLE_TGZ_SHA256="f5d5f57083b71143291b3bc9aa9ea48a03313337c93d41a31d70b90224b57f74"
NOBLE_JS_SHA256="e0d1bad238ceef8d5451713daf6d5b256ce871d3200fe7ee79dbc01179ec806a"

NOBLE_DEST="$REPO_ROOT/site/vendor/noble-secp256k1.js"
NOBLE_LICENSE="$REPO_ROOT/site/licenses/noble-secp256k1-LICENSE.txt"

if [ -f "$NOBLE_DEST" ] \
   && [ "$(sha256sum "$NOBLE_DEST" | cut -d' ' -f1)" = "$NOBLE_JS_SHA256" ]; then
  echo "  noble-secp256k1  @ ${NOBLE_VERSION} (already present)"
else
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' EXIT
  curl -fsSL "$NOBLE_URL" -o "$tmp/noble.tgz"
  actual="$(sha256sum "$tmp/noble.tgz" | cut -d' ' -f1)"
  if [ "$actual" != "$NOBLE_TGZ_SHA256" ]; then
    echo "ERROR: @noble/secp256k1 ${NOBLE_VERSION} tarball sha256 mismatch" >&2
    echo "  expected $NOBLE_TGZ_SHA256" >&2
    echo "  got      $actual" >&2
    exit 1
  fi
  tar -xzf "$tmp/noble.tgz" -C "$tmp" package/index.js package/LICENSE
  mkdir -p "$(dirname "$NOBLE_DEST")" "$(dirname "$NOBLE_LICENSE")"
  cp "$tmp/package/index.js" "$NOBLE_DEST"
  cp "$tmp/package/LICENSE" "$NOBLE_LICENSE"
  echo "  noble-secp256k1  @ ${NOBLE_VERSION}"
fi
