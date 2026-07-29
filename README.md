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
   laptop — and they may only have the device in their hands for twenty seconds.
   The site is four big buttons and QRs sized to be scanned off a phone screen.

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
site/                 the demo site's source (index.html, app.js, styles.css,
                      seedsigner-logo.svg)
site/dist/            built site — gitignored, produced by tools/build_site.py
tools/
  build_fixtures.py   (re)generate fixtures deterministically
  build_site.py       build the static site into site/dist/
  serve.py            local dev server (binds all interfaces, for phone testing)
  verify.py           end-to-end verification of the BUILT artifacts
  smoke_site.mjs      headless-browser check of the page itself
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
.venv/bin/python -m tools.build_site         # both networks, ~1-2 min
.venv/bin/python -m tools.serve 8777         # prints a LAN URL for your phone
```

Then open the printed LAN address on a phone and point a SeedSigner at it.
`--quick` skips input counts above 5 for fast UI iteration; `--network main`
builds one network only.

### What the site does

Someone at a demo table may have the device in their hands for twenty seconds, so
the site is built for one glance and one tap. The landing page is a warning line
and four buttons, nothing else:

- **Sign a transaction** — the main event. One scrolling page: *Scan the
  transaction* (QR first, right under the banner), then *Load the seed*, then for
  multisig *Load the wallet descriptor*. Numbered headings and hard dividers mark
  the sections; there are no next-step buttons, because those were only
  re-implementing the scrollbar.
- **Load a seed** — the SeedQRs on their own, CompactSeedQR by default.
- **Verify an address** — a descriptor plus an address to check against it.
- **Sign a message** — `signmessage {path} ascii:{message}`.

Every optional control (format, density, speed, pause, UR type) is folded into a
collapsed *QR options* disclosure. The defaults are what a demo wants; the knobs
are there for when something won't scan.

The wallet-descriptor step belongs to **signing**, not address verification, and
the distinction is easy to get wrong: during signing the device verifies its own
change **on board** — it needs the wallet policy to recognise a change output,
and you never scan an address at it. *Verify Address* is a separate device tool,
so it gets a separate view.

The banner doubles as the site title; tapping the SeedSigner logo returns to the
landing page.

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

### UR animations include fountain parts, and never loop back

The BC-UR multi-part encoder is **rateless**. The first `seq_len` parts are the
*pure* fragments (sequence numbers 1..N, plain slices of the message).
Everything after that is a *mixed* part: an XOR of a pseudorandomly chosen
fragment subset, numbered N+1, N+2, … forever. Sparrow just keeps calling
`nextPart()`, so a real animation runs 1..N and then **stays in fountain mode
indefinitely — it never returns to part 1**.

Two shortcuts are tempting and both are wrong:

- **Ship only the pure fragments and loop them.** Produces a working animation
  that never exercises the fountain XOR-decode path — the most intricate part of
  any UR decoder — so the test data silently fails to test the interesting half
  of the implementation.
- **Ship pure + mixed and cycle the whole list.** The animation jumps back to
  part 1, which no real encoder does.

So the build ships the pure set plus a mixed tail, and the browser plays the pure
prefix once before looping *within the tail* (`QrPlayer.advance` in
`site/app.js`). The frame counter distinguishes `Part 3 of 7` from
`Fountain part 9 (mixed)`.

That playback rule makes the tail's size load-bearing: a scanner that missed a
pure fragment will only ever see mixed parts again, so if the tail held too few
distinct parts to solve for what was missed, the animation would spin forever
without completing — a hang at a demo table rather than a slow scan. A rateless
code needs roughly `seq_len` distinct parts, so the tail targets 1:1 with the
pure count (floor 16, ceiling 256).

BBQR has no fountain coding — it really is a fixed set of slices that a sender
loops — so every BBQR part is "pure" and that case wraps normally.

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

And because correct data can still be served by a broken page:

```bash
npm install && npx playwright install chromium   # one-off
node tools/smoke_site.mjs http://localhost:8777/
```

That drives the real page in headless Chromium at desktop and phone sizes. It is
not decoration — the first run caught two bugs that no data-level check could
see: an author-origin `display: flex` beating the UA stylesheet's
`[hidden] { display: none }`, which left a white fullscreen overlay covering the
whole page; and a step of the guided flow that was marked `hidden` in the markup
with nothing ever unhiding it.

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

A 100-input 2-of-3 PSBT is 39,197 bytes → 98 pure frames at Normal, 490 at Low
(plus the fountain tail).
BBQR caps are in **chars** of the encoded body (Normal=2000, Low=1000).

`sortedmulti`, not `multi` — these are UR script-expression tags **407** and
**406** respectively, they are not interchangeable, and they derive *different
addresses* from the same keys. Sparrow means sortedmulti.

## License

MIT — see [LICENSE](LICENSE). The vendored UR2 codec in `common/ur2/` is from the
[SeedSigner](https://github.com/SeedSigner/seedsigner) project (also MIT); its
original license is preserved at `common/ur2/LICENSE`.
