# Sparrow Wallet QR formats (reverse-engineered from source)

Goal: produce QR codes byte-identical to what a real Sparrow user generates, so
they can be used as faithful test input for scanners (e.g. SeedSigner). All
findings are from the Sparrow source (github.com/sparrowwallet/sparrow), not
documentation, which is sparse on these details.

Sparrow has **no scriptable CLI** — its `-t`/`--terminal` mode is an interactive
Lanterna TUI for headless servers, not automatable. So we don't drive Sparrow;
we replicate its output format exactly.

## Two surfaces that emit descriptor/PSBT QRs

| Surface | Class | Static or animated |
|---|---|---|
| Multisig **PDF backup** ("Save PDF...") | `io/PdfUtils.saveOutputDescriptor` | **single static** QR |
| **Show QR** dialog (export/airgap) | `control/QRDisplayDialog` | **animated** (fountain) |

## Shared QR encoding recipe (BOTH surfaces)

From `PdfUtils.getQrCode` and `QRDisplayDialog.getQrCode`:

1. Build the payload as a **UR** (`ur:crypto-output/...` for a wallet output
   descriptor; `ur:crypto-psbt/...` for a PSBT). BBQR is an alternative encoding
   (see below).
2. **`fragment.toUpperCase(Locale.ROOT)`** before encoding. This is the single
   most important density detail: an all-uppercase UR string (`UR:CRYPTO-OUTPUT/`
   + bytewords, which are lowercase a–z + digits → uppercased to A–Z + digits,
   plus `:` `-` `/`) is entirely within the **QR alphanumeric character set**, so
   zxing picks **alphanumeric mode** (~45% denser than byte mode). UR/bytewords
   decoders are case-insensitive, so it round-trips.
3. zxing `QRCodeWriter.encode(..., Map.of(EncodeHintType.MARGIN, "2"))`:
   - **No error-correction hint → zxing default = EC level L.**
   - **Quiet zone (margin) = 2 modules.**
   - Smallest QR version that fits the data is chosen automatically.

Skipping the uppercase step produces a *denser/larger* QR than Sparrow's, e.g.
the 3-of-5 descriptor below is v19 (alphanumeric) vs v24 (byte) — so matching
the uppercase step is mandatory for fidelity.

## A. PDF backup — single static QR (the "demanding" descriptor QR)

`PdfUtils.saveOutputDescriptor(name, descriptor, ur, bbqr)`:

- Uses `new UREncoder(ur, 2000, 10, 0)` — max fragment **2000** chars. Any normal
  multisig descriptor fits in **one** part → a single static QR (no animation).
- That single fragment is uppercased and encoded per the shared recipe above.
- BBQR is used **only if every keystore is a Coldcard-Q-class device**
  (`keystore.getWalletModel().selectBbqr()`); otherwise UR. For generic
  seeds/SeedSigner the path is always UR `crypto-output`.

Measured (mainnet, `wsh(sortedmulti(...))`, BIP48 `m/48h/0h/0h/2h`, throwaway keys):

| Policy | UR length (uppercased) | QR version | Modules |
|---|---|---|---|
| 2-of-3 P2WSH | 677 | v15 | 77×77 |
| 3-of-5 P2WSH | 1097 | v19 | 93×93 |

This single static QR is the densest descriptor QR a Sparrow user encounters with
UR encoding, which makes it the key scanner stress-test target.

## B. Show-QR dialog — animated fountain QR

`QRDisplayDialog` (constants + `createAnimateQRService`):

- UR encoder: `new UREncoder(ur, maxUrFragmentLength, MIN_FRAGMENT_LENGTH=10, 0)`.
- Fragment length is set by the **QR density** preference (`control/QRDensity`):

  | Density | max UR fragment | max BBQR fragment |
  |---|---|---|
  | **NORMAL** (default) | **400** | **2000** |
  | LOW | 80 | 1000 |

- Each animated frame = one uppercased fragment, encoded per the shared recipe.
  Per-frame density is therefore **capped by fragment length**, not by total
  payload size — bigger payloads produce *more frames*, not denser ones.

  Sparrow exposes only two density presets (no fine control); one setting drives
  both UR and BBQR caps. **IMPORTANT — the two encodings measure their cap in
  different units:**

  - **UR**: the cap is **bytes of the CBOR message** per fragment. The bytewords
    body is ~2 chars/byte, plus a `ur:<type>/<seq>-<len>/` header, so the QR
    string is roughly `2 × cap + ~25` chars. (This is the part it's easy to get
    wrong — 400 is *not* 400 QR characters.)
  - **BBQR**: the cap is **characters of the base32/zlib-encoded text** per part
    (`io/bbqr/BBQREncoder.encode`: ZLIB deflate → base32 → split into
    ceil(len/cap) ~equal chunks padded to a multiple of 8, each with an 8-char
    `B$...` header). So the QR string is ~`cap + 8` chars.

  All caps are upper bounds — frames scale DOWN with payload, and payloads larger
  than the cap add MORE frames, not a bigger QR. Measured per-frame QR sizes
  (uppercased, EC-L, margin 2):

  | Encoding / density | cap | per-frame QR string | per-frame QR (max) |
  |---|---|---|---|
  | UR LOW | 80 bytes | ~217 chars | ~v7 (45×45) |
  | UR NORMAL (default) | 400 bytes | ~834 chars | **~v16–17 (81–85)** |
  | BBQR LOW (Coldcard-Q only) | 1000 chars | ~1008 chars | ~v18 (89×89) |
  | BBQR NORMAL (Coldcard-Q only) | 2000 chars | ~2008 chars | ~v27 (125×125) |

  (UR-NORMAL frame version drifts v16↔v17 as the `<seq>-<len>/` header grows with
  frame count; e.g. a 98-frame PSBT lands on v17/85×85.)

  → The **densest animated frame Sparrow can show is BBQR NORMAL (~v27, 125×125)**;
  the densest **UR** animated frame (the SeedSigner-relevant path) is ~v16–17
  (81–85). Design split: UR = many medium frames, BBQR = few large frames (hence
  BBQR is reserved for big-display/good-camera devices). Even so, the densest
  *single* QR overall is still the static PDF backup descriptor (3-of-5 → v19),
  denser than any individual UR animated frame.

### BBQR encode internals (Sparrow `io/bbqr/BBQREncoder` + `BBQREncoding`)

Reverse-engineered exactly (replicated in `common/bbqr.py`):

- **Part string** = 8-char header + body chunk. Header =
  `"B$"` + encoding-code + type-code + base36(numParts) + base36(index).
  The two base36 fields are **lowercase** (`BigInteger.toString(36)`),
  2 chars, zero-padded (`String.format("%2s").replace(' ','0')`). Type code
  `P` = PSBT. The whole part is uppercased later by the shared `getQrCode`
  step, so on-screen it reads `B$ZP…` — base36 decoders are case-insensitive.
- **Encoding `Z` (zlib)**: `new Deflater(Z_BEST_COMPRESSION, windowBits=10,
  nowrap=true)` → **raw DEFLATE, 1 KB window** → RFC-4648 base32, padding
  stripped. Python equivalent: `zlib.compressobj(9, DEFLATED, -10)`. If deflate
  fails to shrink the data, Sparrow falls back to encoding `2` (plain base32).
  (Compressed *bytes* may differ from JZlib's match choices, but the stream is
  valid and decodes under `Inflater(10, true)` — the format is identical.)
- **Chunk math** (cap measured in **chars of the encoded body**):
  `numParts = ceil(len/cap)`; `chunkSize = ceil(len/numParts)` rounded **up**
  to a multiple of `partModulo` (8 for base32, so each chunk base32-decodes
  independently); body sliced into `numParts` contiguous chunks of that size.
- Measured (2-of-3 P2WSH, 100 inputs → 39,197-byte PSBT; zlib body 31,319
  chars): **NORMAL** (cap 2000) → 16 frames, **v26 (121×121)**; **LOW**
  (cap 1000) → 32 frames, **v16 (81×81)**. Generator:
  `generators/animated_bbqr_psbt_qr.py` (5 fps GIF + `_parts.txt`).

### On-screen render size (pixels)

`QRDisplayDialog.getQrCode` calls zxing
`QRCodeWriter.encode(fragment, QR_CODE, qrSize, qrSize, MARGIN=2)` with
`qrSize = getQRSize()`:

- `DEFAULT_QR_SIZE = 580`
- `REDUCED_QR_SIZE = 520` (used when `AppServices.isReducedWindowHeight()`)

The same dialog also shows a **single-part** payload (e.g. a whole multisig
descriptor that fits in one fragment) as one non-animated frame — still at
`qrSize`, so an on-screen static descriptor "Show QR" popup is **580×580** too,
the same canvas as the animated frames. (The separate **PDF backup** path,
`io/PdfUtils`, embeds its QR at `QR_WIDTH=QR_HEIGHT=480` instead — that 480 size
applies only to the PDF, not the on-screen window.)

So **every animated frame is the same 580×580 px** (520 on short screens),
*independent of QR version* — the symbol is integer-scaled to the largest
`multiple` that fits `(modules + 2·quietZone)` inside 580 and centered, with the
remaining margin acting as the quiet zone (zxing `QRCodeWriter.renderResult`:
`multiple = 580 / (modules + 4)`, `pad = (580 − modules·multiple) / 2`). E.g.
v26 → multiple 4, symbol 484 px, pad 48; v16 → multiple 6, symbol 486 px,
pad 47. `common/qr.py` `sparrow_qr(payload, render_size=580)` reproduces this;
without `render_size` it emits a native 1 px/module bitmap (much larger and
version-dependent — do NOT use that for Sparrow-faithful samples).

### Frame rate

- `ANIMATION_PERIOD_MILLIS = 200d` → **5 frames/second** default.
- Scroll-wheel adjustable; clamped between `period/2` and `period*10`, i.e.
  **100 ms (10 fps) to 2000 ms (0.5 fps)**.

## Cross-check / fidelity proof

Both surfaces emit `ur:crypto-output/...`, which SeedSigner's own decoder
consumes natively: `decode_qr.py` routes `ur:crypto-output/` →
`urtypes.crypto.Output.from_cbor(cbor).descriptor()`. `btc-datagen`'s generator
round-trips its UR back through SeedSigner's `DecodeQR` to confirm fidelity.

## Reproduction parameters that matter

- Script type / derivation: `wsh(sortedmulti(...))`, BIP48 `m/48h/<coin>h/0h/2h`
  (P2WSH); nested would be `.../1h` with `sh(wsh(...))`.
- `sortedmulti` (not `multi`) — Sparrow's default.
- Key expression suffix `/<0;1>/*` (multipath, receive+change).
- Error correction **L**, quiet zone **2**, **uppercased** payload, smallest version.
