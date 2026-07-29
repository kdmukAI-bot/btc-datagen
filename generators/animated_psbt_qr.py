"""Animated UR PSBT QR generator (Sparrow-fidelity).

Builds a large multisig PSBT from a fixture wallet and fountain-encodes it as an
animated ur:crypto-psbt/... — the same encoding Sparrow's "Show QR" dialog uses
when sending a PSBT to an airgap signer. Output is a 5 fps looping GIF plus the
individual frames, so it can be played on screen and scanned by SeedSigner.

Sparrow density (control/QRDensity + QRDisplayDialog): the UR fragment length is
in BYTES of the CBOR message — NORMAL=400, LOW=80 — uppercased per frame, EC=L,
margin=2. NORMAL frames come out ~v16 (81x81); animation runs at 200 ms/frame
(5 fps). See docs/knowledge/sparrow-qr-formats.md.

Run:
  .venv/bin/python -m generators.animated_psbt_qr                       # 2of3, 100 inputs, normal
  .venv/bin/python -m generators.animated_psbt_qr 3of5_p2wsh 60 normal
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from urtypes.crypto import PSBT as URPSBT

from common.fixtures import load_wallets, wallet_cosigners
from common.psbt import build_multisig_psbt
from common.ur2.ur import UR
from common.ur2.ur_encoder import UREncoder
from common.qr import sparrow_qr, SPARROW_QR_SIZE

OUTPUT_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "output")

# Sparrow QRDensity: max UR fragment length, in BYTES of the CBOR message.
UR_FRAGMENT_BYTES = {"normal": 400, "low": 80}
ANIMATION_MS = 200          # Sparrow ANIMATION_PERIOD_MILLIS -> 5 fps
MIN_FRAGMENT_BYTES = 10     # Sparrow MIN_FRAGMENT_LENGTH


def _normalize(images: list):
    """Paste every frame onto a common white canvas so the GIF dimensions are
    uniform (the final pure fragment can be one QR version smaller)."""
    pil = [im.convert("RGB") for im in images]
    w = max(i.width for i in pil)
    h = max(i.height for i in pil)
    out = []
    for i in pil:
        if i.size == (w, h):
            out.append(i)
        else:
            from PIL import Image
            canvas = Image.new("RGB", (w, h), "white")
            canvas.paste(i, ((w - i.width) // 2, (h - i.height) // 2))
            out.append(canvas)
    return out


def generate(wallet_name: str, num_inputs: int, density: str):
    wallets = load_wallets()
    wallet = wallets[wallet_name]
    cosigners = wallet_cosigners(wallet)
    psbt = build_multisig_psbt(cosigners, wallet["threshold"], wallet["script_type"], num_inputs)
    raw = psbt.serialize()

    ur = UR("crypto-psbt", URPSBT(raw).to_cbor())
    fragment_bytes = UR_FRAGMENT_BYTES[density]
    encoder = UREncoder(ur, fragment_bytes, 0, MIN_FRAGMENT_BYTES)
    num_frames = encoder.fountain_encoder.seq_len()    # pure fragments, decoder-complete
    parts = [encoder.next_part() for _ in range(num_frames)]

    images, version, modules = [], None, None
    for part in parts:
        img, version, modules = sparrow_qr(part, render_size=SPARROW_QR_SIZE)
        images.append(img)

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    stem = os.path.join(OUTPUT_DIR, f"psbt_{wallet_name}_{num_inputs}in_{density}")
    frames = _normalize(images)
    frames[0].save(stem + ".gif", save_all=True, append_images=frames[1:],
                   duration=ANIMATION_MS, loop=0)
    with open(stem + "_parts.txt", "w") as f:
        f.write("\n".join(parts) + "\n")
    with open(stem + "_psbt.txt", "w") as f:
        f.write(psbt.to_string() + "\n")          # base64 PSBT

    loop_seconds = num_frames * ANIMATION_MS / 1000
    print(f"=== animated PSBT: {wallet_name} ({wallet['policy']} {wallet['script_type']}) ===")
    print(f"  inputs           : {num_inputs}")
    print(f"  raw PSBT         : {len(raw):,} bytes  (base64 {len(psbt.to_string()):,})")
    print(f"  UR density       : {density} ({fragment_bytes}-byte fragments)")
    print(f"  frames           : {num_frames}  per-frame QR v{version} ({modules}x{modules} modules)")
    print(f"  render size      : {SPARROW_QR_SIZE}x{SPARROW_QR_SIZE} px (Sparrow DEFAULT_QR_SIZE)")
    print(f"  animation        : {ANIMATION_MS} ms/frame = {1000/ANIMATION_MS:.0f} fps "
          f"(~{loop_seconds:.1f}s/loop)")
    print(f"  GIF              : {stem}.gif")
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
