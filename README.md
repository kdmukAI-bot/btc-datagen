# btc-datagen

A generator for **Bitcoin test data** — QR codes and PSBTs — used to exercise
scanners and signing flows such as SeedSigner's QR operations, plus a static
**demo site** that serves those QRs to a phone so someone can drive a real
SeedSigner hands-on.

Everything uses **deterministic throwaway keys**. They are insecure by design and
stored in plain text. Never put real bitcoin on anything generated here.

## Why this exists

Two jobs:

1. **Test data.** Realistic, demanding inputs that match what real wallets
   produce. The first target is **Sparrow Wallet**, because much of the user base
   drives SeedSigner from Sparrow. Sparrow has no scriptable CLI (its terminal
   mode is an interactive TUI), so instead of automating Sparrow we **replicate
   its exact QR output format** — verified against the Sparrow source. See
   [docs/knowledge/sparrow-qr-formats.md](docs/knowledge/sparrow-qr-formats.md).
2. **A demo site.** At a conference table you want to hand someone a URL, not a
   laptop. The site walks a first-timer through scanning a transaction, loading a
   seed, signing, and optionally verifying an address — with the QRs sized to be
   scannable off a phone screen.

Nothing here is broadcastable. Inputs reference synthetic funding transactions
that exist on no chain; the PSBTs are structurally valid and fully signable, and
that is all they need to be.

## Layout

```
fixtures/             reusable plaintext test data (regenerate via tools/build_fixtures.py)
  test_seeds.json     named throwaway BIP39 seeds (mnemonic + fingerprint)
  test_wallets.json   wallets: descriptor, both descriptor URs, cosigners, addresses
common/
  script_types.py     the 7 script types SeedSigner supports, in one table
  keys.py             signers from mnemonics (embit)
  descriptor.py       descriptor text + ur:crypto-output / ur:crypto-account
  psbt.py             PSBT builder for every script type + output shape
  scenarios.py        the demo transaction matrix
  qr.py               Sparrow-fidelity QR rasterization + bare-matrix export
  seedqr.py           SeedQR / CompactSeedQR payload encoding
  bbqr.py             BBQR encoder (byte-for-byte replica of Sparrow's)
  fixtures.py         fixture loaders
  ur2/                vendored UR2 codec (from SeedSigner; byte-identical fountain)
generators/           standalone artifact generators (PNG/GIF into output/)
site/                 the demo site's source (index.html, app.js, styles.css)
site/dist/            built site — gitignored, produced by tools/build_site.py
tools/
  build_fixtures.py   (re)generate fixtures deterministically
  build_site.py       build the static site into site/dist/
  serve.py            local dev server (binds all interfaces, for phone testing)
  verify.py           end-to-end verification of the BUILT artifacts
docs/knowledge/       reverse-engineering notes & format references
```

## Setup

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/pip install -r requirements-dev.txt   # only needed for tools/verify.py
```

`requirements-dev.txt` needs the system zbar library (`apt install libzbar0`).

## The demo site

```bash
.venv/bin/python -m tools.build_fixtures     # once, or after changing fixtures
.venv/bin/python -m tools.build_site         # both networks, ~1 min, 3.8 MiB
.venv/bin/python -m tools.serve 8777         # prints a LAN URL for your phone
```

Then open the printed LAN address on a phone and point a SeedSigner at it.
`--quick` skips input counts above 5 for fast UI iteration; `--network main`
builds one network only.

### What the site does

Two paths, because they're two different device features.

**Sign a transaction** (the default) — a guided flow with progressive disclosure:
each step ends in one big call to action that reveals the next, so a first-timer
never has to work out what to do.

1. **Scan the transaction** — animated (or static) QR, with format, density and
   speed controls.
2. **Load the seed** — CompactSeedQR by default, standard SeedQR available, plus
   the words in plain text. For multisig, pick which cosigner you're signing as.
3. **Load the wallet descriptor** — multisig only, and only when the transaction
   has a change or self-transfer output. This is *not* address verification: it's
   what lets the device recognise its own change while you review the
   transaction. Offered as both `ur:crypto-output` and `ur:crypto-account`.

**Verify an address** — a separate SeedSigner tool, so a separate view. Load a
descriptor, then point *Tools › Verify Address* at an address QR. In the signing
flow above the device verifies change **on board**; you never scan an address at
it there. Conflating the two is the easy mistake.

The banner doubles as the site title — tap it to get back to the start — and a
short dialog lands the test-data point once on first load.

### Playback defaults

Sparrow's **"Normal" is the higher-density option** (more data per frame); "Low"
packs less in and is easier to scan. Density is sticky per format:

| | Default |
|---|---|
| Format | UR (`ur:crypto-psbt`) |
| UR density | Normal — 400-byte fragments |
| BBQR density | Low — 1000-char parts (BBQR Normal lands around v27, too dense to default to) |
| Frame rate | 5 fps, adjustable 0.5–10 |
| SeedQR type | CompactSeedQR |

### UR animations include fountain parts

The BC-UR multi-part encoder is **rateless**, and shipping only the obvious part
of it is a trap. The first `seq_len` parts are the *pure* fragments (sequence
numbers 1..N, plain slices of the message). Everything after that is a *mixed*
part: an XOR of a pseudorandomly chosen fragment subset, numbered N+1, N+2, …
forever. Sparrow just keeps calling `nextPart()`, so a real Sparrow animation
never repeats.

Emitting only the pure fragments and looping them — which is what this did at
first — produces a working animation that **never exercises the fountain
XOR-decode path**, the most intricate part of any UR decoder. So the build ships
the pure set plus up to 32 mixed parts and the browser cycles that; the frame
counter distinguishes `Part 3 of 7` from `Fountain part 9 (mixed)`.

BBQR has no fountain coding — it really is a fixed set of slices that a sender
loops, so every BBQR part is "pure".

### The transaction matrix

Static hosting means every PSBT is precomputed, so "configurable" is a bounded
matrix (80 scenarios) rather than arbitrary runtime construction:

- **Full cross at 3 inputs** — all 7 script types × 4 output shapes.
  Single sig: native segwit, nested segwit, taproot, legacy P2PKH.
  Multisig: P2WSH, P2SH-P2WSH, legacy P2SH.
  Shapes: send-with-change, full spend, self-transfer, three-recipients+change.
- **Input-count sweep** on native-segwit single sig and 2-of-3 P2WSH:
  1 / 2 / 5 / 20 / 30 / 100 inputs. 30 is the usual stress test; 100 is extreme.
- Both networks. Each scenario ships 4 QR variants (UR/BBQR × Normal/Low).

The **default** flow is 3 inputs, native segwit single sig, one external
recipient plus change and the fee — two UR frames at Normal density, about as
easy as an animated scan gets.

### Why QRs ship as module matrices

The build emits each QR as a **bare module matrix** (packed bits, row-major, no
quiet zone) rather than payload text, and the browser just blits the modules.
That means there is no JS QR encoder whose settings could drift from Sparrow's,
and the on-screen white border stays a front-end concern. Two rendering rules in
`site/app.js` decide whether a scan actually works:

- **Integer module scaling only**, in device pixels. A fractional scale gives
  some modules an extra pixel and that asymmetry wrecks decoding.
- **One scale per animation.** Frames can differ by a QR version, so the scale
  locks to the largest frame and smaller ones are centred — otherwise the symbol
  resizes mid-scan and the camera re-hunts.

The on-screen quiet zone is 4 modules (spec minimum) rather than Sparrow's 2.
That's display-only and doesn't touch the encoded payload.

## Verification

```bash
.venv/bin/python -m tools.verify          # representative sample
.venv/bin/python -m tools.verify --all    # every scenario, every variant
```

This checks the artifacts that actually ship, not a fresh in-memory rebuild, so a
serialization bug can't hide behind correct intermediate values. Per scenario it:

1. renders every shipped QR matrix back to an image and **decodes it with an
   independent decoder (zbar)**, proving the bits are a readable QR;
2. feeds the decoded payloads back through the UR / BBQR decoders and asserts the
   reconstructed PSBT is byte-identical;
3. asserts the PSBT still signs with its intended seed;
4. parses it with **SeedSigner's own `PSBTParser`** and checks policy and amounts.

> Use zbar, not OpenCV. OpenCV's built-in `QRCodeDetector` silently fails on
> dense symbols — it could not read a v16 QR that zbar reads perfectly,
> *including one produced by the reference encoder itself* — so it is worthless
> as a correctness gate.

## Standalone generators

```bash
.venv/bin/python -m generators.sparrow_descriptor_qr          # all wallets
.venv/bin/python -m generators.animated_psbt_qr 2of3_p2wsh 100 normal
.venv/bin/python -m generators.seed_qrs
```

These write PNG/GIF artifacts into `output/` (gitignored) for use outside the
site. Both QR generators verify their own output by decoding it back through the
vendored UR codec.

## Fixtures included

Seeds: `alice bob carol dave erin frank grace` (mix of 24- and 12-word, entropy =
SHA256 of a domain-separated name — deterministic but realistic).

Wallets, each built for mainnet **and** testnet: `ss_native_segwit`,
`ss_nested_segwit`, `ss_taproot`, `ss_legacy`, `2of3_p2wsh`, `3of5_p2wsh`,
`2of3_p2sh_p2wsh`, `2of3_p2sh`.

The two networks genuinely differ — coin type `0h` vs `1h` in the path, xpub vs
tpub version bytes in the descriptor and its UR, and different addresses — and
SeedSigner's own network setting has to match. Mainnet is the site default so a
demo attendee never has to change device settings.

## Sparrow fidelity (measured)

**Static descriptor QR** — single-part `ur:crypto-output`, uppercased (→
alphanumeric mode), EC level L, margin 2:

| Wallet | UR length | QR |
|---|---|---|
| 2of3_p2wsh | 677 chars | v15, 77×77 |
| 3of5_p2wsh | 1097 chars | v19, 93×93 |
| 2of3_p2sh_p2wsh | 683 chars | v15, 77×77 |

**Animated `ur:crypto-psbt`** — fragment cap is in CBOR **bytes** (Normal=400,
Low=80), uppercased per frame, EC-L, margin 2, 5 fps default:

| Density | fragment | per-frame QR |
|---|---|---|
| Normal | 400 B | ~v16–17 (81–85) |
| Low | 80 B | ~v7 (45×45) |

A 100-input 2-of-3 PSBT is 39,197 bytes → 123 frames at Normal, 490 at Low.
BBQR caps are in **chars** of the encoded body (Normal=2000, Low=1000).

`sortedmulti`, not `multi` — these are UR script-expression tags **407** and
**406** respectively, they are not interchangeable, and they derive *different
addresses* from the same keys. Sparrow means sortedmulti.

## License

MIT — see [LICENSE](LICENSE). The vendored UR2 codec in `common/ur2/` is from the
[SeedSigner](https://github.com/SeedSigner/seedsigner) project (also MIT); its
original license is preserved at `common/ur2/LICENSE`.
