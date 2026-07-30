# The UR bytewords checksum was being truncated, and the fountain hid it

A bug in the vendored `common/ur2` UR implementation: roughly **1 animated UR
frame in 256 was malformed**, and had been for as long as the site has existed.
It never failed a test, never failed a hardware scan, and was only found by
encoding the same PSBT with a second implementation and diffing the strings.

Related: `sparrow-qr-formats.md` (the UR wire format),
`qr-scannability-and-verification.md` (why the existing gates could not see it).

## The bug

BCR-2020-005 specifies the bytewords checksum as a **4-byte big-endian CRC32**
appended to the CBOR before bytewords encoding. `common/ur2/crc32.py` had:

```python
def crc32n(buf):
    n = crc32(buf)
    return n.to_bytes((bit_length(n) + 7) // 8, 'big')   # minimal width
```

`int.to_bytes` with a computed minimal width **drops leading zero bytes**. Any
checksum below 2²⁴ — a zero high byte, one part in 256 — encoded as three bytes
instead of four. Below 2¹⁶, two bytes. And so on.

A decoder takes the last four bytes as the checksum, so a three-byte checksum
means the body it hands the CBOR parser is one byte short. The CBOR then
declares an 80-byte fragment and supplies 79, and the parser rejects the frame.

Measured on the site's own fixtures: **7 of 731 parts (0.96%)**.

The same file's `int_to_bytes()` sits eight lines below with the identical
minimal-width expression *commented out* and replaced by `to_bytes(4, 'big')` —
so this exact trap had already been hit once, in one function, and not swept for
elsewhere.

## Why nothing caught it

Three separate things conspired, and each is worth recognising on its own.

**The fountain is error-correcting, so corruption reads as latency.** A UR
animation is rateless: a decoder that rejects a frame simply waits for another.
Losing 1% of frames costs a fraction of a second and completes normally. Every
round-trip test in `tools/verify.py` passed, because they all asked "does the
PSBT come back?" and not "did every frame parse?". Redundancy is exactly what
makes a defect like this survive: **a system that heals cannot report its own
injuries.**

**The checksum validation was commented out.** `bytewords.decode()` had:

```python
    # if checksum != body_checksum:
    #     raise ValueError('Invalid Bytewords.')
```

Almost certainly disabled *because of this bug* — someone hit sporadic checksum
failures and silenced the check rather than chasing the cause. That turned a
loud, specific error into silent corruption. The check is now re-enabled, which
is only safe because `crc32n` is fixed; doing it in the other order would just
have reproduced the original failures.

**Comparing an implementation to itself proves nothing.** Python encoded and
Python decoded, so a shared assumption about checksum width was invisible. The
bug appeared within minutes of encoding the same PSBT with cUR and diffing:
cUR's part carried one extra `ae` byteword — `ae` is 0x00, the dropped high byte
of the checksum — and everything else was identical.

## The general lesson

**Fixed-width wire fields must be encoded at fixed width.** `int.to_bytes` with
a computed length is a trap wherever the value is a checksum, a length prefix,
a sequence number or a fingerprint: it works for 255 out of 256 values and then
silently shortens the message. Grep for `bit_length` near `to_bytes` in any
serialization code.

## Blast radius beyond this repo

SeedSigner's own vendored copy — `src/seedsigner/helpers/ur2/crc32.py` — has the
**identical** `crc32n`. Where the Python UR encoder is the one in use (the Pi
Zero path; the ESP32 build uses cUR instead), that means roughly 1 in 256 of the
frames a device puts on screen when displaying a signed PSBT is malformed and
will be discarded by whatever is scanning it. The visible cost is a slightly
slower scan, never a failure, which is precisely why it has gone unnoticed.

cUR is unaffected — it writes the checksum as four bytes.
