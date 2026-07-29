"""BBQR encoder — byte-for-byte replica of Sparrow's io/bbqr/BBQREncoder.

Sparrow's "Show QR" dialog can emit a PSBT as BBQR instead of UR when every
keystore is a Coldcard-Q-class device. This module reproduces that exact wire
format so the parts are indistinguishable from a real Sparrow BBQR animation.

Format (reverse-engineered from Sparrow source, see
docs/knowledge/sparrow-qr-formats.md):

  * Each part = 8-char header + body chunk.
  * Header  = "B$" + encoding-code + type-code + base36(numParts) + base36(index)
              where the two base36 fields are lowercase, 2 chars, zero-padded
              (BBQRHeader.encodeToBase36 -> BigInteger.toString(36) + "%2s").
  * Encoding "Z" (zlib): raw DEFLATE then RFC-4648 base32, padding stripped.
              Sparrow: `new Deflater(Z_BEST_COMPRESSION, windowBits=10, nowrap=true)`
              -> Python `zlib.compressobj(9, DEFLATED, -10)` (raw, 1 KB window).
              If deflate doesn't shrink the data, Sparrow falls back to "2".
  * Encoding "2" (base32): RFC-4648 base32 of the raw bytes, padding stripped.
  * Type "P" = PSBT.
  * Splitting (BBQREncoder.encode): the cap (maxFragmentLength) is measured in
    CHARACTERS of the encoded body. numParts = ceil(len / cap); chunkSize =
    ceil(len / numParts) rounded UP to a multiple of partModulo (8 for base32),
    then the body is sliced into numParts contiguous chunks of that size.

The compressed bytes themselves may differ from JZlib's by a few bytes (any
two conformant DEFLATE encoders can choose different matches), but the stream
is valid raw-DEFLATE/window-10 and decodes under Sparrow's Inflater(10, true)
and SeedSigner's BBQR decoder — the *format* is identical.
"""
import base64
import math
import zlib

# Sparrow QRDensity -> maxBbqrFragmentLength (chars of the encoded body).
BBQR_FRAGMENT_CHARS = {"normal": 2000, "low": 1000}

_PART_MODULO = {"Z": 8, "2": 8, "H": 2}  # BBQREncoding.getPartModulo
_B36_DIGITS = "0123456789abcdefghijklmnopqrstuvwxyz"


def _to_base36(n: int) -> str:
    if n == 0:
        return "0"
    out = ""
    while n:
        n, r = divmod(n, 36)
        out = _B36_DIGITS[r] + out
    return out


def _b36_2(n: int) -> str:
    """BBQRHeader.encodeToBase36: lowercase base36, left-padded to 2 with '0'."""
    return _to_base36(n).rjust(2, "0")


def _b32(data: bytes) -> str:
    """RFC-4648 base32, uppercase, trailing '=' padding stripped (Sparrow)."""
    return base64.b32encode(data).decode("ascii").rstrip("=")


def _deflate(data: bytes) -> bytes:
    """Raw DEFLATE, 1 KB window — matches Sparrow's Deflater(BEST, 10, nowrap)."""
    co = zlib.compressobj(9, zlib.DEFLATED, -10)
    return co.compress(data) + co.flush()


def _encode_body(data: bytes):
    """Return (encoding_code, encoded_body) — ZLIB unless it fails to shrink."""
    deflated = _deflate(data)
    if len(deflated) < len(data):
        return "Z", _b32(deflated)
    return "2", _b32(data)


def encode(data: bytes, type_code: str, max_fragment_chars: int):
    """Split `data` into Sparrow BBQR parts.

    Returns (parts, encoding_code). Each part is the full BBQR string Sparrow
    feeds to its QR writer *before* the shared uppercase step (sparrow_qr does
    the uppercasing at rasterization, exactly as Sparrow's getQrCode does).
    """
    encoding, encoded = _encode_body(data)
    part_modulo = _PART_MODULO[encoding]

    length = len(encoded)
    desired = max_fragment_chars
    num_chunks = (length + desired - 1) // desired          # ceil
    if num_chunks == 1:
        chunk_size = desired
    else:
        chunk_size = math.ceil(length / num_chunks)
    modulo = chunk_size % part_modulo
    if modulo > 0:
        chunk_size += part_modulo - modulo

    parts, start = [], 0
    for i in range(num_chunks):
        end = min(start + chunk_size, length)
        header = "B$" + encoding + type_code + _b36_2(num_chunks) + _b36_2(i)
        parts.append(header + encoded[start:end])
        start = end
    return parts, encoding


def decode(parts: list) -> bytes:
    """Inverse of encode() — reassemble + decompress (round-trip self-test)."""
    ordered = sorted(parts, key=lambda p: int(p[6:8], 36))
    encoding = ordered[0][2]
    body = "".join(p[8:] for p in ordered)
    pad = (-len(body)) % 8
    raw = base64.b32decode(body + "=" * pad)
    if encoding == "Z":
        return zlib.decompress(raw, -10)
    return raw
