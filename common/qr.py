"""Sparrow-fidelity QR rasterization.

Mirrors Sparrow's zxing settings exactly (see docs/knowledge/sparrow-qr-formats.md):
  * payload is UPPERCASED (-> QR alphanumeric mode, ~45% denser)
  * error correction level L (zxing default)
  * quiet-zone margin 2 modules
  * smallest QR version that fits

Two render modes:
  * render_size=None  -> native 1 px/module (+ 2-module quiet zone) bitmap.
  * render_size=N     -> reproduce zxing QRCodeWriter.renderResult: integer-scale
    the bare symbol and center it on an N x N white canvas. Sparrow's
    QRDisplayDialog calls encode(fragment, QR_CODE, qrSize, qrSize, MARGIN=2)
    with qrSize = DEFAULT_QR_SIZE=580 (REDUCED_QR_SIZE=520 on short screens), so
    every frame is the SAME 580x580 regardless of version — that is exactly what
    a Sparrow user sees on screen.
"""
import base64

import qrcode
from qrcode.constants import ERROR_CORRECT_L
from PIL import Image

# Sparrow control/QRDisplayDialog DEFAULT_QR_SIZE / REDUCED_QR_SIZE (animated, px).
SPARROW_QR_SIZE = 580
SPARROW_QR_SIZE_REDUCED = 520
# Sparrow io/PdfUtils QR_WIDTH / QR_HEIGHT (static PDF-backup descriptor QR, px).
SPARROW_PDF_QR_SIZE = 480
QUIET_ZONE = 2


def _new_qr():
    """A borderless encoder with Sparrow's settings (EC level L, version fit)."""
    return qrcode.QRCode(version=None, error_correction=ERROR_CORRECT_L,
                         border=0, box_size=1)


def _pack(qr):
    """Serialize a made QRCode's modules to (base64 packed bits, version, modules).

    Bits are row-major and contiguous, 1 = dark; bit i lives at
    `byte[i >> 3] >> (7 - (i & 7)) & 1`, for `modules * modules` bits total.
    """
    modules = qr.modules_count
    packed = bytearray((modules * modules + 7) // 8)
    i = 0
    for row in qr.modules:
        for cell in row:
            if cell:
                packed[i >> 3] |= 1 << (7 - (i & 7))
            i += 1
    return base64.b64encode(packed).decode("ascii"), qr.version, modules


def qr_matrix(payload: str, uppercase: bool = True):
    """Bare-symbol matrix for a text payload — no quiet zone baked in.

    The browser adds its own margin, so it can control the on-screen white
    border independently of the encoded data (see site/app.js).

    `uppercase` reproduces Sparrow's trick of upper-casing UR/BBQR payloads to
    reach QR alphanumeric mode (~45% denser). It MUST be left off for anything
    case-sensitive — a base58 Bitcoin address is destroyed by upper-casing, and
    while all-caps bech32 is technically legal, shipping the address verbatim is
    the only form every wallet agrees on.
    """
    qr = _new_qr()
    qr.add_data(payload.upper() if uppercase else payload)
    qr.make(fit=True)
    return _pack(qr)


def qr_matrix_bytes(payload: bytes):
    """Bare-symbol matrix for a binary payload (QR byte mode, e.g. CompactSeedQR)."""
    qr = _new_qr()
    qr.add_data(payload)
    qr.make(fit=True)
    return _pack(qr)


def sparrow_qr(payload: str, render_size: int = None):
    """Return (PIL image, version, modules) for a single UR/BBQR fragment.

    `payload` is uppercased here exactly as Sparrow does before encoding. When
    `render_size` is given, the image is produced like zxing's QRCodeWriter:
    the bare symbol is scaled by the largest integer `multiple` that fits a
    (modules + 2*quiet_zone) grid inside render_size, then centered on a
    render_size x render_size white canvas (so the effective quiet zone is the
    centering pad, matching Sparrow's on-screen output pixel-for-pixel).
    """
    border = QUIET_ZONE if render_size is None else 0
    box_size = 1 if render_size is not None else 10
    qr = qrcode.QRCode(version=None, error_correction=ERROR_CORRECT_L,
                       border=border, box_size=box_size)
    qr.add_data(payload.upper())
    qr.make(fit=True)
    version, modules = qr.version, qr.modules_count

    if render_size is None:
        image = qr.make_image(fill_color="black", back_color="white").get_image()
        return image, version, modules

    bare = qr.make_image(fill_color="black", back_color="white").get_image().convert("RGB")
    qr_dim = modules + QUIET_ZONE * 2                 # zxing qrWidth/qrHeight
    output = max(render_size, qr_dim)
    multiple = output // qr_dim                       # integer scale (zxing)
    scaled_px = modules * multiple
    canvas = Image.new("RGB", (output, output), "white")
    pad = (output - scaled_px) // 2                   # zxing left/top padding
    canvas.paste(bare.resize((scaled_px, scaled_px), Image.NEAREST), (pad, pad))
    return canvas, version, modules
