"""Sparrow-fidelity multisig descriptor-backup QR generator.

Reproduces exactly the SINGLE static QR Sparrow shows for a multisig wallet
descriptor: an uppercased, single-part ur:crypto-output/... at EC level L,
margin 2. This is the demanding static descriptor QR a Sparrow user gets; use it
to stress-test a scanner.

Rendered at 580x580 px to match Sparrow's on-screen "Show QR" popup
(control/QRDisplayDialog, DEFAULT_QR_SIZE=580 — a single-part UR shows as one
non-animated frame, same canvas as the animated dialog). The "Save PDF..."
backup (io/PdfUtils.saveOutputDescriptor) embeds the same QR at 480x480
(QR_WIDTH/QR_HEIGHT) instead — pass render_size=SPARROW_PDF_QR_SIZE for that.

See docs/knowledge/sparrow-qr-formats.md for the reverse-engineering.

Run:
  .venv/bin/python -m generators.sparrow_descriptor_qr            # all wallets
  .venv/bin/python -m generators.sparrow_descriptor_qr 3of5_p2wsh # one wallet
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from urtypes.crypto import Output

from common.fixtures import load_wallets, wallet_cosigners
from common.descriptor import crypto_output_ur, expected_output_tags
from common.ur2.ur import UR  # noqa: F401 (kept for parity / future use)
from common.ur2.ur_decoder import URDecoder
from common.qr import sparrow_qr, SPARROW_QR_SIZE

OUTPUT_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "output")


def roundtrip_ok(ur_string: str, script_type: str) -> bool:
    """Decode the UR exactly as SeedSigner's OUTPUT__UR path does and confirm
    the script-expression tags survived (e.g. sortedmulti was not downgraded)."""
    decoder = URDecoder()
    decoder.receive_part(ur_string)
    if not decoder.is_complete():
        return False
    tags = [se.tag for se in Output.from_cbor(decoder.result_message().cbor).script_expressions]
    return tags == expected_output_tags(script_type)


def generate(wallet_name: str, wallet: dict):
    cosigners = wallet_cosigners(wallet)
    ur_string = crypto_output_ur(wallet["threshold"], cosigners, wallet["script_type"])
    image, version, modules = sparrow_qr(ur_string, render_size=SPARROW_QR_SIZE)

    stem = os.path.join(OUTPUT_DIR, f"descriptor_{wallet_name}")
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    image.save(stem + ".png")
    with open(stem + "_descriptor.txt", "w") as f:
        f.write(wallet["descriptor"] + "\n")
    with open(stem + "_ur.txt", "w") as f:
        f.write(ur_string + "\n")

    ok = roundtrip_ok(ur_string, wallet["script_type"])
    print(f"=== {wallet_name}  ({wallet['policy']} {wallet['script_type']}, {wallet['network']}) ===")
    print(f"  UR length      : {len(ur_string)} chars (single-part, uppercased)")
    print(f"  QR             : v{version}, {modules}x{modules} modules, EC=L, border=2")
    print(f"  render size    : {SPARROW_QR_SIZE}x{SPARROW_QR_SIZE} px (Sparrow QRDisplayDialog popup; PDF backup is 480)")
    print(f"  PNG            : {stem}.png")
    print(f"  UR decode check: {'OK' if ok else 'FAILED'}")
    print()


def main():
    wallets = load_wallets()
    names = sys.argv[1:] or list(wallets)
    for name in names:
        if name not in wallets:
            print(f"unknown wallet '{name}'. available: {', '.join(wallets)}")
            continue
        generate(name, wallets[name])


if __name__ == "__main__":
    main()
