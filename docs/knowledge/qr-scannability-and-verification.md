# Making a rendered QR scannable — and verifying that it is

Notes from building the demo site's "handmade" SeedQR, where the code is
deliberately distressed (marker dabs, paper grain, worn print) and still has to
be read by a real SeedSigner. Everything here is measured, mostly by getting it
wrong first.

Related: `sparrow-qr-formats.md` (encoding fidelity),
`browser-canvas-and-css-gotchas.md` (the rendering traps that aren't QR-specific).

## The verification oracle is the hard part

**A pristine-PNG decode is NOT representative of a camera.** This cost the most
time. Rendering the card and handing the raw bitmap to zbar reported *every* card
as undecodable while a real SeedSigner read them without hesitation.

The render is a perfect, noise-free, high-resolution bitmap containing fine
dotted hairlines and paper grit at full contrast. A camera never sees that: the
lens defocuses slightly, the sensor integrates over a pixel area, and the capture
is far coarser than a dpr-3 framebuffer. All of that is a low-pass filter, and
for QR binarization low-pass is **helpful** — it averages grain and hairlines
away and leaves the module structure.

So the gate is a *simulated capture*: downscale, blur slightly, lift brightness
(SeedSigner runs auto-exposure high). See `camsim` in the session scratch or
rebuild it — the shape is:

```python
img.convert('L').resize((w, h), LANCZOS).filter(GaussianBlur(0.8..1.6))
# then optionally ImageEnhance.Brightness(...).enhance(1.0..1.5)
```

Keep the pristine decode around as a *stricter-than-reality* signal, but never
let it gate. **Hardware is the only oracle that counts**; the simulation exists
to catch regressions between hardware passes.

### zbar mangles byte-mode payloads, and the mangling is data-dependent

libzbar applies a charset conversion to byte-mode QR data and hands back text.
The root cause and the native-path fix are documented in
`seedsigner-raspi-lvgl/docs/knowledge/native-zbar-binary-mode-for-byte-qr.md`.

The detail that bit here, in a **pyzbar** test harness: the charset it guesses
**depends on the bytes**. Most CompactSeedQR entropy comes back latin-1-decoded
and re-encoded as UTF-8, but one fixture seed (`erin`) begins `97 c2`, which is a
valid Shift-JIS double-byte sequence (→ U+732F), so zbar guessed Shift-JIS
instead. A harness that only reverses latin-1 reports that one seed as a decode
failure while the QR is perfect.

Reverse the round trip against several encodings before declaring a mismatch:

```python
for enc in ('latin-1', 'shift_jis', 'cp932'):
    if data.decode('utf-8').encode(enc) == expected: ...
```

### Screenshot what is actually displayed

Twice, a "failure" was the harness photographing the wrong thing:

- once the element screenshot captured a **closed overlay** sitting over the QR;
- once the canvas was `visibility: hidden` because the visible artwork had moved
  to CSS stand-in faces, so the screenshot was of something the user never sees.

If the pixel path changes, the harness has to follow it.

### "Everything fails" means the harness or a structural break

When a parameter sweep shows *every* variant failing — including the known-good
baseline — stop tuning the parameter. Either the harness is broken or something
structural (a leaked canvas clip, a hidden element) is destroying the symbol. A
real parameter problem shows a *boundary*, not a wall.

## What a QR actually tolerates

**Marks that are too big are far safer than marks that are too small.** A decoder
samples near each cell's centre. An oversized dab cannot reach a neighbouring
cell's sample point (that would need a radius of a full cell), so overflow is
cheap; an undersized dot fails to cover its *own* centre, which is fatal. Bias
any hand-drawn look large. Shipped: marker dabs 0.95–1.30 cells wide.

**Colour is only safe while it is dark.** Binarization is on luminance, so a
marker colour must stay low-lightness against the paper. Purple/blue/green/maroon
at ~26–34% L are fine; a yellow or orange highlighter would look completely
plausible and scan terribly.

**Finder patterns are structural, not error-corrected.** A decoder locates the
symbol by scanning for the 1:1:3:1:1 dark/light ratio through them. Data modules
can lose ink and be reconstructed; a chewed-up finder pattern means the symbol is
never found at all. A factorial over {print darkness} × {speck colour} × {speck
size} found exactly one failing combination: **large AND paper-white** specks,
which punch holes that binarize as light. Large grey specks decode; small white
ones decode. Fine two-tone noise (like the paper grain) is the safe way to soften
flat print.

**Quiet zone can be tighter than the spec** in practice — 3 modules works here,
and the printed SeedSigner templates carry none at all, relying on surrounding
paper. Treat any reduction as scanning-relevant and re-verify.

## Rendering rules that decide whether it reads at all

- **Integer module scaling only**, computed in *device* pixels:
  `scale = floor(availCss * dpr / grid)`. A fractional scale gives some modules
  an extra pixel and the asymmetry wrecks decoding. (SeedSigner's own
  `models/qr_density.py` documents the same principle for the device.)
- **One scale per animation.** Frames in a set can differ by a QR version; lock
  to the largest and centre the smaller ones, or the symbol resizes mid-scan and
  the camera re-hunts.
- **Never rotate or CSS-filter the canvas.** Either resamples the bitmap and
  destroys the whole-pixel module grid. Anything decorative — tint, grain,
  creases, even the hand-written label — must be drawn *inside* the canvas;
  only the surrounding card may be styled in CSS.
- **Upper-case UR/BBQR payloads** to reach QR alphanumeric mode (~45% denser),
  but **never** anything case-sensitive. Upper-casing a base58 address destroys
  it. SeedSigner's `signmessage` payload is detected with a lowercase
  `startswith`, so that must not be upper-cased either.

## UR fountain playback

The BC-UR multi-part encoder is **rateless**: parts 1..N are the pure fragments,
everything after is an XOR of a pseudorandom subset, numbered N+1, N+2, … forever.
A real encoder never returns to part 1.

Two shortcuts are both wrong:

- shipping only the pure fragments and looping them gives a working animation
  that **never exercises the fountain XOR-decode path** — the most intricate part
  of any UR decoder;
- shipping pure+mixed and cycling the whole list makes the animation jump back to
  part 1, which no encoder does.

Ship the pure set plus a mixed tail, play the prefix once, then loop *within the
tail*. That makes the tail's size load-bearing: a scanner that missed a pure
fragment only ever sees mixed parts afterwards, so a tail too small to solve for
what was missed would spin forever rather than complete. Size it ~1:1 with the
pure count.

Remaining gap: the tail itself repeats, sequence numbers and all. Fixing it
properly means a runtime encoder — see `docs/TODO.md`.
