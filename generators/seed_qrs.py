"""Standard SeedQR + CompactSeedQR generator for the test fixture seeds.

Replicates SeedSigner's own encoders (models/encode_qr.py) exactly so the output
is byte-identical to what the device produces:

  * Standard SeedQR : each BIP39 word's 4-digit wordlist index, concatenated,
                      encoded in QR NUMERIC mode (12w -> 48 digits, 24w -> 96).
  * CompactSeedQR   : the 11-bit indices concatenated, checksum bits dropped,
                      packed into raw bytes, encoded in QR BYTE mode
                      (= the BIP39 entropy; 16 bytes for 12w, 32 for 24w).

Both use error correction level L, version fit (SeedSigner helpers/qr.py).
Throwaway test seeds only.

Run:
  .venv/bin/python -m generators.seed_qrs
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import qrcode
from qrcode.constants import ERROR_CORRECT_L

from common.fixtures import load_seeds
from common.seedqr import standard_seedqr_digits, compact_seedqr_bytes

OUTPUT_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                          "output", "seed_qrs")


def _render(data):
    """SeedSigner-style QR: EC level L, version fit. `data` is str (numeric) or bytes."""
    qr = qrcode.QRCode(version=1, error_correction=ERROR_CORRECT_L, box_size=10, border=3)
    qr.add_data(data)
    qr.make(fit=True)
    return qr.make_image(fill_color="black", back_color="white"), qr.version, qr.modules_count


def generate(seed: dict):
    words = seed["mnemonic"].split()
    name = seed["name"]
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    digits = standard_seedqr_digits(words)
    std_img, std_v, std_m = _render(digits)
    std_img.save(os.path.join(OUTPUT_DIR, f"seedqr_{name}_standard.png"))

    entropy = compact_seedqr_bytes(words)
    assert entropy.hex() == seed["entropy_hex"], f"{name}: compact entropy mismatch"
    cmp_img, cmp_v, cmp_m = _render(entropy)
    cmp_img.save(os.path.join(OUTPUT_DIR, f"seedqr_{name}_compact.png"))

    with open(os.path.join(OUTPUT_DIR, f"seedqr_{name}.txt"), "w") as f:
        f.write(f"name: {name}\nwords: {len(words)}\nmnemonic: {seed['mnemonic']}\n")
        f.write(f"standard_seedqr_digits: {digits}\n")
        f.write(f"compact_seedqr_entropy_hex: {entropy.hex()}\n")

    print(f"  {name:6s} {len(words)}w  standard: v{std_v} ({std_m}x{std_m}, numeric, {len(digits)} digits)"
          f"   compact: v{cmp_v} ({cmp_m}x{cmp_m}, byte, {len(entropy)} bytes)")


def main():
    print("Generating SeedQRs (EC=L, version-fit; matches SeedSigner encoders):")
    for seed in load_seeds().values():
        generate(seed)
    print(f"\nOutput: {OUTPUT_DIR}")


if __name__ == "__main__":
    main()
