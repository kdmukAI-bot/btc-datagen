# TODO

## Mirrors

Only GitHub exists for this repo. House convention is GitHub + GitLab + Codeberg
+ Forgejo; the other three need creating via their own APIs before a plain push
will work.

## Report the ur2 CRC32 truncation upstream

`docs/knowledge/ur2-crc32-truncation.md` documents a bug fixed here in
`common/ur2/crc32.py`: the bytewords checksum was encoded at minimal width, so
roughly one part in 256 came out a byte short and was rejected by any decoder.

SeedSigner's vendored copy — `src/seedsigner/helpers/ur2/crc32.py` — has the
identical `crc32n`. On the Pi Zero path (where the Python UR encoder is the one
in use, rather than cUR) that means ~0.4% of the frames a device shows when
displaying a signed PSBT are malformed and get discarded by whatever is
scanning. The cost is a marginally slower scan, never a failure, which is
exactly why it has gone unnoticed. Worth a one-line PR.

## Nice to have: report which fragments the UR decoder holds

`ur_decoder_received_parts_count()` gives a count, not a set, so the scan
progress meter fills left to right rather than showing which fragments have
landed. An accessor returning the received indexes would let the display show
the real, scattered arrival pattern — see the note in
`docs/knowledge/runtime-qr-and-camera-readback.md` about why the positional
version was reverted. Small addition to cUR (`fountain_decoder.c` already keeps
`received_part_indexes`), and SeedSigner's own scan UI would want the same
thing.

## Nice to have: fragment size as a live slider

Now that UR frames are generated in the browser rather than pre-rendered,
density is no longer a build-time axis — `max_fragment` is just a number passed
to the encoder. The two presets could become a slider without changing anything
in the build. Left alone for now because two big buttons beat a slider at a demo
table.
