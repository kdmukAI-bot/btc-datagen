# TODO

## Compile cUR to WASM for live UR encoding (and decoding)

**Problem.** UR animations are pre-generated at build time, so the browser plays
a finite sequence: the pure fragments once, then a fixed mixed tail on loop. Each
mixed part is a genuine, distinct fountain part with a real sequence number, but
once the tail is exhausted it replays the same parts — sequence numbers and all.
A real encoder calls `nextPart()` forever and never repeats. On a small PSBT the
tail is 16 frames, so at 5 fps the loop is visible in about 3.6 seconds.

**Fix.** Compile [cUR](https://github.com/kdmukAI-bot/cUR) (fork of odudex/cUR;
vendored at `seedsigner-micropython-builder/deps/cUR`) to WASM with Emscripten
and encode in the browser. It has both encoder and decoder, plus the CBOR types
we need — and it's the same codec the ESP32 firmware runs, so output is
byte-identical to the device rather than merely equivalent.

Follow the build pattern already proven in
`seedsigner-lvgl-screens/tools/apps/web_runner/build.sh` (Docker + pinned emsdk,
no host toolchain).

**Wins beyond fidelity:**

- Payload shrinks a lot. We currently ship pre-rendered frame matrices — up to
  296 KB for the 100-input case at UR Low. With a runtime encoder we ship only
  the base64 PSBT (~53 KB for that same case) and generate frames on demand.
- Density stops being a build-time axis. Fragment size could become a live
  slider instead of two pre-baked presets.
- The same WASM module unlocks the **camera-scan phase**: decode SeedSigner's
  signed-PSBT animated QR back in the browser. Both features share one build, so
  the toolchain cost is paid once.

**Note on the QR rasterizer.** Runtime encoding means the browser would also have
to rasterize QR symbols, which today is done in Python so that Sparrow's exact
settings (uppercase → alphanumeric mode, EC level L, smallest fitting version)
cannot drift. Either port that carefully or keep a build-time check that compares
WASM-generated fragments against the Python ones.

**Cheaper interim options** if the loop is the only concern:

- Raise the mixed-tail multiplier (currently ~1:1 with the pure count, floor 16,
  ceiling 256) so the loop is long enough not to read as one.
- Drop the floor of 16 so tiny payloads don't get a disproportionately long tail.

Both are one-line changes in `MIXED_PARTS_*` in `tools/build_site.py`.

## Mirrors

Only GitHub exists for this repo. House convention is GitHub + GitLab + Codeberg
+ Forgejo; the other three need creating via their own APIs before a plain push
will work.
