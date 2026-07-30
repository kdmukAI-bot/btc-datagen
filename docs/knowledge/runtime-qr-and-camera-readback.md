# Generating QRs in the browser, and reading them back with a camera

Why the demo site stopped shipping pre-rendered animated QR frames, what that
cost, and what only showed up once a real SeedSigner was pointed at it.

Related: `qr-scannability-and-verification.md` (rendering rules and the
verification-oracle problem), `ur2-crc32-truncation.md` (a bug this work
uncovered), `sparrow-qr-formats.md` (the wire formats).

## Why a frame list cannot be a fountain

The BC-UR multi-part encoder is **rateless**. Parts 1..N are the pure message
fragments; every part after that is a fresh XOR of a pseudorandomly chosen
subset, numbered N+1, N+2, … forever. A real encoder never repeats and never
returns to part 1.

Any finite list of frames therefore lies somewhere. Shipping only the pure
fragments and looping them leaves the fountain XOR-decode path — the most
intricate part of any UR decoder — completely unexercised. Shipping pure + a
mixed tail and cycling the whole thing jumps back to part 1, which no encoder
does. Shipping pure + tail and looping *within the tail* (what this site did for
a while) is closest, but the tail still repeats, sequence numbers and all, in
about 3.6 seconds on a small PSBT.

The only faithful option is to run an encoder. cUR compiled to WASM is the same
codec the ESP32 firmware runs, so the browser now produces frames byte-identical
to a device's rather than merely equivalent — and the site ships a 53 KB base64
PSBT where it used to ship up to 296 KB of rendered matrices.

## What that costs: a second QR encoder to keep honest

The old invariant was structural — "Python pre-renders Sparrow-exact matrices,
so there is no JS QR encoder to validate". Runtime encoding also means runtime
rasterization, which means a second encoder (Nayuki's qrcodegen) that can drift
from python-qrcode. Two findings:

**`boostEcl` must be off.** qrcodegen will silently promote error correction
above the level you asked for when the chosen version has spare room. The result
is a perfectly valid, perfectly scannable QR carrying a different number of data
codewords than Sparrow would show. Nothing visible fails. The round-trip test
pins it by decoding the output and asserting the EC level comes back L.

**The mask will not match, and that is fine.** qrcodegen and python-qrcode
choose different masks for roughly 40% of frames. Two independent causes:

- python-qrcode scores candidate masks on a matrix with the format and version
  modules blanked to light (`makeImpl(test=True, …)`); qrcodegen scores with the
  real format bits drawn.
- python-qrcode implements penalty rule 3 as a fixed 11-module window pattern
  (`10111010000` / `00001011101`); qrcodegen uses the run-based finder-pattern
  formulation.

Both are defensible readings of the spec, and the mask is invisible to a
decoder — same data, same version, same EC level, every mask decodes
identically. Chasing byte-equality would mean porting one library's quirks
(including the test-mode blanking) into C to make two encoders agree on an
arbitrary choice.

So the gate asserts what is observable instead: same UR parts as the Python
reference, same QR version and module count, and every frame decoded back to
its own payload at EC level L in alphanumeric mode. See
`tools/wasm/roundtrip_test.mjs`.

## The layout ceiling is computable, not a guess

The canvas must lock one module scale for a whole animation, or the symbol
resizes mid-scan and the camera re-hunts. With a finite frame list you take the
max. With an endless one you have to predict it.

It turns out to be exact rather than statistical. Every fountain part carries
the same fragment length, so the only thing that grows a part is the **sequence
number** — as a decimal in the URI path, and as a CBOR integer inside the part
(1 byte below 24, 2 below 256, 3 below 65536, 5 beyond). Rasterizing one real
part at a six-digit sequence number gives the ceiling for any run shorter than
55 hours at 5 fps. The front end keeps a runtime guard that re-layouts if a
frame ever exceeds it: one visible resize beats a clipped QR.

## Reading it back: the progress display was wrong, and only hardware said so

The camera step decodes the device's animated QR with k_quirc (SeedSigner's own
decoder, compiled to WASM) and reassembles with cUR's fountain decoder.

The first progress display drew one cell per fragment and lit the cells for
fragments **read directly off the screen**, on the reasoning that cUR reports
how many fragments it holds but not which, so filling cells by count would be
inventing positional detail.

Against a real SeedSigner it displayed nothing at all. The percentage climbed;
not one cell ever lit.

The reason is the same rateless property that motivated all of this. A device
shows its pure fragments **once** — under a second at 5 fps for a small
transaction — and then runs the fountain indefinitely. Unless the camera happens
to acquire focus and lock within that first second, every frame you catch is a
mixed one. The decoder recovers fragments steadily by XOR, and none of them was
ever seen in pure form.

The fix is to treat the cells as a **count meter** rather than a positional map:
cell *i* lights when the decoder holds *i+1* fragments. A segmented bar is not
read positionally, so nothing is claimed that isn't true, and the number that
was actually interesting — how much was *reconstructed* rather than read — moved
to the caption, where it is a good thing to point at during a demo.

Two general lessons:

- **Design a progress display against the traffic pattern it will actually
  see.** The positional version was correct, honest, and empty. The correctness
  of a display is not separable from whether it displays anything.
- **The rateless property bites twice.** It is why a frame list cannot be
  faithful, and it is why a scanner almost never sees a pure fragment. Both are
  the same fact seen from either end of the link.

## Verification split

Neither half is sufficient alone, and it is worth being explicit about which
covers what:

| gate | what it proves |
|---|---|
| `tools/verify.py` | the shipped *parameters* produce readable, correct frames — regenerated in Python, decoded with zbar (an independent decoder), reassembled to the exact PSBT. Also that the shipped sighash digests are the ones a real signature commits to. |
| `tools/wasm/roundtrip_test.mjs` | the browser's encoder agrees with Python's, its output decodes at the right EC level and mode, and the signature verifier accepts valid signatures **and rejects** tampered, under-threshold, and wrong-transaction ones. |
| `tools/smoke_site.mjs` | the camera path works end to end in a real browser, with a canvas MediaStream standing in for the camera, driven by the same encoder at the same 5 fps. |

And, as always: **hardware is the only oracle that counts.** Every one of those
passed while the progress bar sat empty on a phone.
