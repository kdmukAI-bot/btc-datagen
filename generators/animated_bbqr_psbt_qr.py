"""Animated BBQR PSBT QR generator (Sparrow-fidelity).

The BBQR counterpart to generators/animated_psbt_qr.py. Builds the same large
multisig PSBT and encodes it as an animated BBQR sequence — the format Sparrow's
"Show QR" dialog uses when every keystore is a Coldcard-Q-class device (the
`keystore.getWalletModel().selectBbqr()` path). Output is a 5 fps looping GIF
plus the individual BBQR parts, playable on screen and scannable by a BBQR
decoder.

Sparrow density (control/QRDensity, BBQR cap is in CHARACTERS of the encoded
body, unlike UR which caps in CBOR bytes): NORMAL=2000, LOW=1000. Each frame is
uppercased, EC=L, margin=2; animation runs at 200 ms/frame (5 fps). NORMAL
frames land ~v27 (125x125), LOW ~v18 (89x89). See common/bbqr.py and
docs/knowledge/sparrow-qr-formats.md.

Run:
  .venv/bin/python -m generators.animated_bbqr_psbt_qr                    # 2of3, 100 inputs, normal
  .venv/bin/python -m generators.animated_bbqr_psbt_qr 3of5_p2wsh 60 low
  .venv/bin/python -m generators.animated_bbqr_psbt_qr 2of3_p2wsh 100 both
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common.fixtures import load_wallets, wallet_cosigners
from common.psbt import build_multisig_psbt
from common.bbqr import encode as bbqr_encode, decode as bbqr_decode, BBQR_FRAGMENT_CHARS
from common.qr import sparrow_qr, SPARROW_QR_SIZE
from generators.animated_psbt_qr import _normalize

OUTPUT_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "output")

ANIMATION_MS = 200          # Sparrow ANIMATION_PERIOD_MILLIS -> 5 fps
BBQR_TYPE_PSBT = "P"        # BBQRType.PSBT


def generate(wallet_name: str, num_inputs: int, density: str):
    wallets = load_wallets()
    wallet = wallets[wallet_name]
    cosigners = wallet_cosigners(wallet)
    psbt = build_multisig_psbt(cosigners, wallet["threshold"], wallet["script_type"], num_inputs)
    raw = psbt.serialize()

    fragment_chars = BBQR_FRAGMENT_CHARS[density]
    parts, encoding = bbqr_encode(raw, BBQR_TYPE_PSBT, fragment_chars)

    # Round-trip self-test: reassembled BBQR must reproduce the PSBT bytes.
    assert bbqr_decode(parts) == raw, "BBQR round-trip mismatch"

    images, version, modules = [], None, None
    for part in parts:
        img, version, modules = sparrow_qr(part, render_size=SPARROW_QR_SIZE)
        images.append(img)

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    stem = os.path.join(OUTPUT_DIR, f"psbt_{wallet_name}_{num_inputs}in_bbqr_{density}")
    frames = _normalize(images)
    frames[0].save(stem + ".gif", save_all=True, append_images=frames[1:],
                   duration=ANIMATION_MS, loop=0)
    with open(stem + "_parts.txt", "w") as f:
        f.write("\n".join(parts) + "\n")
    with open(stem + "_psbt.txt", "w") as f:
        f.write(psbt.to_string() + "\n")          # base64 PSBT

    num_frames = len(parts)
    loop_seconds = num_frames * ANIMATION_MS / 1000
    enc_name = {"Z": "zlib+base32", "2": "base32"}[encoding]
    print(f"=== animated BBQR PSBT: {wallet_name} ({wallet['policy']} {wallet['script_type']}) ===")
    print(f"  inputs           : {num_inputs}")
    print(f"  raw PSBT         : {len(raw):,} bytes  (base64 {len(psbt.to_string()):,})")
    print(f"  BBQR encoding    : {encoding} ({enc_name})")
    print(f"  BBQR density     : {density} ({fragment_chars}-char fragments)")
    print(f"  body chars       : {sum(len(p) - 8 for p in parts):,}")
    print(f"  frames           : {num_frames}  per-frame QR v{version} ({modules}x{modules} modules)")
    print(f"  render size      : {SPARROW_QR_SIZE}x{SPARROW_QR_SIZE} px (Sparrow DEFAULT_QR_SIZE)")
    print(f"  animation        : {ANIMATION_MS} ms/frame = {1000/ANIMATION_MS:.0f} fps "
          f"(~{loop_seconds:.1f}s/loop)")
    print(f"  GIF              : {stem}.gif")
    print(f"  parts            : {stem}_parts.txt")
    print(f"  base64 PSBT      : {stem}_psbt.txt")
    print()


def main():
    args = sys.argv[1:]
    wallet_name = args[0] if len(args) > 0 else "2of3_p2wsh"
    num_inputs = int(args[1]) if len(args) > 1 else 100
    density = args[2] if len(args) > 2 else "normal"
    densities = ["normal", "low"] if density == "both" else [density]
    for d in densities:
        generate(wallet_name, num_inputs, d)


if __name__ == "__main__":
    main()
