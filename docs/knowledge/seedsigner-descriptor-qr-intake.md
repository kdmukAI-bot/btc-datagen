# What SeedSigner reads as a wallet descriptor QR

A descriptor QR only tests something if SeedSigner loads it as a descriptor. Several
encodings that look equivalent don't get that far, and the device rewrites what it does
load before checking it. Everything below is read from SeedSigner's
`models/decode_qr.py` (`DecodeQR.detect_segment_type`, `is_wallet_descriptor`,
`get_wallet_descriptor`) and `views/scan_views.py` (`ScanView.run`).

## Which QR contents count as a descriptor

`ScanView` takes the descriptor branch only when `DecodeQR.is_wallet_descriptor` is true.
That holds for:

| QR content | Detected as |
|---|---|
| `ur:crypto-output/...` | `OUTPUT__UR` |
| `ur:bytes/...` holding a multisig setup file (it must contain `policy:`, `format:`, and `derivation:`) | `BYTES__UR` |
| JSON starting `{"label"` and containing `"descriptor":` (a Specter wallet export) | `WALLET__SPECTER` |
| Text starting `pNofM ` (one part of a Specter export split across QRs) | `WALLET__SPECTER` |
| Text containing `multisig setup file` | `WALLET__CONFIGFILE` |
| Any other text containing `sortedmulti` | `WALLET__GENERIC` |

Two traps follow from that list:

- **`ur:crypto-account` decodes but never loads.** `get_wallet_descriptor` can read a
  descriptor out of one (it takes `output_descriptors[0]`), but `is_wallet_descriptor`
  leaves the type out, so `ScanView` falls through every branch to "Not Yet
  Implemented". Ship a descriptor as `crypto-output`.
- **Plain text is a descriptor only if it says `sortedmulti`.** A `multi()` descriptor as
  plain text is not detected as one. To deliver a `multi()` descriptor, wrap it in a
  Specter wallet export with `label` as the first key
  (`{"label":"...","descriptor":"..."}`, since detection anchors on `{"label"`), or
  encode it as `crypto-output` with script expression tag 406 (`multi`) instead of 407
  (`sortedmulti`).

## The device rewrites the descriptor before using it

After decoding, `ScanView` rewrites key endings so the descriptor covers both the receive
and change branches:

1. If any key with an origin (`[fingerprint/path]`) ends in `/0/*`, each such `/0/*`
   becomes `/{0,1}/*`. Keys with no ending are then left as they are.
2. Otherwise, every key with an origin and no ending at all gets `/{0,1}/*` appended.
   This is the common case for a UR, whose keys usually carry no child path.

Any other ending passes through unchanged: `/<0;1>/*`, a bare `/*`, `/2/*`, or
`/<0;2>/*`. A key is rewritten only if its origin path marks hardened levels with `h`
or `'`: a key with no origin, or with an uppercase `H` origin, keeps its ending. So the
descriptor the device checks is not always the text that was encoded, and the two can
behave differently.

## Encoding limits on this side

- **A UR can't express a multipath key.** urtypes' keypath components are an index or a
  wildcard, with no `<a;b>` pair, so a descriptor with a key like `/<0;2>/*` can only ship
  as text. A single child path (`/0/*`, `/*`) is expressible through the key's
  `children` keypath.
- **Never upper-case a text descriptor.** UR QRs are upper-cased for alphanumeric-mode
  density (see `sparrow-qr-formats.md`), but xpubs are case-sensitive, so a text or JSON
  descriptor must be encoded verbatim (`text_qr(..., uppercase=False)`).

## Checking what the device does with one

Don't reason from the encoder's side. Feed the exact QR content (upper-cased for a UR,
verbatim for text) to SeedSigner's own `DecodeQR`, apply `ScanView`'s rewrite taken from
the same checkout, then run that build's descriptor check against the psbt.
`tools/verify.py` proves each shipped descriptor QR decodes back to that content. Decode
with SeedSigner's urtypes rather than this repo's: the two are different versions.
