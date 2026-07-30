#!/usr/bin/env bash
# Build site/vendor/ssqr.{js,wasm} — the UR codec, QR encoder and QR decoder the
# demo site runs in the browser.
#
# Docker-only, with a pinned emsdk image, following the pattern already proven
# in seedsigner-lvgl-screens/tools/apps/web_runner/build.sh: no host Emscripten
# install, and the toolchain version is a value in a file rather than whatever
# happens to be on the machine.
#
# Usage:
#   bash tools/wasm/build.sh
#   EMSDK_TAG=4.0.14 bash tools/wasm/build.sh
#   SSQR_CUR_DIR=~/dev/.../cUR bash tools/wasm/build.sh   # iterate on a local cUR
#
# Output is gitignored. Run this once before `python -m tools.build_site`; the
# build refuses to produce a site without it, because every animated transaction
# QR is generated at runtime by this module.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

EMSDK_TAG="${EMSDK_TAG:-3.1.74}"
IMAGE="emscripten/emsdk:${EMSDK_TAG}"
OUT_DIR="$REPO_ROOT/site/vendor"
EMCACHE_HOST="$SCRIPT_DIR/.emcache"

bash "$SCRIPT_DIR/fetch_deps.sh"

mkdir -p "$OUT_DIR" "$EMCACHE_HOST"

# cUR's own Makefile source list, minus nothing: the type registry cross-links
# the CBOR types, so cherry-picking psbt.c alone just trades a few KB of dead
# code for undefined symbols.
CUR_SRCS="utils.c bytewords.c fountain_decoder.c fountain_encoder.c fountain_utils.c \
crc32.c ur_decoder.c ur_encoder.c ur.c sha256/sha256.c \
types/byte_buffer.c types/cbor_data.c types/cbor_encoder.c types/cbor_decoder.c \
types/registry.c types/bytes_type.c types/psbt.c types/bip39.c \
types/keypath.c types/hd_key.c types/multi_key.c types/output.c"

SRCS="tools/wasm/ssqr.c deps/qrcodegen/c/qrcodegen.c"
for src in $CUR_SRCS; do SRCS="$SRCS deps/cUR/src/$src"; done
for src in k_quirc.c k_quirc_version.c k_quirc_identify.c k_quirc_decode.c; do
  SRCS="$SRCS deps/k_quirc/src/$src"
done

# -DK_QUIRC_ADAPTIVE_THRESHOLD / -DK_QUIRC_BILINEAR_THRESHOLD match k_quirc's own
# host test build, which is the configuration its validation corpus was measured
# against. A phone camera pointed at a backlit LCD is exactly the uneven-lighting
# case adaptive thresholding exists for.
DEFINES="-DUR_CRC32_SLICE_BY_8 -DK_QUIRC_ADAPTIVE_THRESHOLD -DK_QUIRC_BILINEAR_THRESHOLD"

# No ESP-IDF stubs needed: everything platform-specific in k_quirc_internal.h is
# behind `#ifdef ESP_PLATFORM`, and the else-branch is plain malloc + stdio.
INCLUDES="-Ideps/cUR/src -Ideps/qrcodegen/c -Ideps/k_quirc/include -Ideps/k_quirc/src"

# stringToNewUTF8 is needed because cUR takes `const char *`; HEAPU8 because both
# the PSBT bytes and the camera's grayscale plane cross the boundary as raw
# memory. FILESYSTEM=0 drops the whole JS FS shim — nothing here touches files.
# EXPORT_ES6 so one wrapper (site/ssqr.js) serves both consumers: the browser
# reaches it from the classic app.js with a dynamic import(), and the parity test
# imports it straight into node. A non-ES6 MODULARIZE build would have needed a
# script tag in the browser and a createRequire() shim in node — two loaders for
# one module.
LINK_FLAGS="-O3 \
  -sMODULARIZE=1 \
  -sEXPORT_ES6=1 \
  -sEXPORT_NAME=createSSQR \
  -sENVIRONMENT=web,worker,node \
  -sALLOW_MEMORY_GROWTH=1 \
  -sSTACK_SIZE=524288 \
  -sFILESYSTEM=0 \
  -sEXPORTED_FUNCTIONS=_malloc,_free \
  -sEXPORTED_RUNTIME_METHODS=ccall,cwrap,UTF8ToString,stringToNewUTF8,HEAPU8"

# A local-checkout override (see fetch_deps.sh) lands in deps/ as a symlink to
# somewhere outside the repo, and a bind mount of the repo alone would hand the
# container a dangling link. Mount each such target at the same path the symlink
# resolves to inside /src, so the container sees a real directory either way.
EXTRA_MOUNTS=()
for dep in cUR k_quirc qrcodegen; do
  link="$REPO_ROOT/deps/$dep"
  if [ -L "$link" ]; then
    EXTRA_MOUNTS+=(-v "$(readlink -f "$link")":"/src/deps/$dep":ro)
  fi
done

echo "==> Building site/vendor/ssqr.js with ${IMAGE}"
docker run --rm \
  -v "$REPO_ROOT":/src -w /src \
  "${EXTRA_MOUNTS[@]}" \
  -v "$EMCACHE_HOST":/emcache \
  -u "$(id -u):$(id -g)" \
  -e HOME=/tmp \
  -e EM_CACHE=/emcache \
  "$IMAGE" \
  emcc $SRCS $INCLUDES $DEFINES $LINK_FLAGS \
    -Wall -Wextra -Wno-unused-parameter \
    -o site/vendor/ssqr.js

echo ""
echo "==> Done:"
ls -la "$OUT_DIR"/ssqr.js "$OUT_DIR"/ssqr.wasm
echo ""
echo "    Check it end to end:  python -m tools.wasm.reference && node tools/wasm/roundtrip_test.mjs"
