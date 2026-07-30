"""End-to-end verification of the BUILT site in site/dist/.

This checks the artifacts that actually ship, not a fresh in-memory rebuild —
so a bug in the packing/serialization layer can't hide behind correct
intermediate values. For each scenario it:

  1. renders every QR matrix back to an image and **decodes it with an
     independent QR decoder** (zbar), proving the bits are a readable QR and
     not just plausible-looking noise;
  2. feeds the decoded payloads back through the UR / BBQR decoders and asserts
     the reconstructed PSBT is byte-identical to the scenario's PSBT;
  3. asserts the PSBT still signs with its intended seed;
  4. checks the shipped sighash digests are the ones a signature over this
     transaction actually commits to, by signing and verifying against them;
  5. parses it with **SeedSigner's own PSBTParser** and checks the policy and
     amounts match what the generator intended.

BBQR frames ship pre-rendered and are read straight out of site/dist/. UR
frames do not exist on disk any more — the browser generates them at runtime —
so step 1 regenerates them here from the PARAMETERS the site ships (the base64
PSBT and the fragment size) and checks those. This half of the guarantee is
"the parameters we ship produce readable, correct frames"; the other half, "the
browser's encoder agrees with Python's", is tools/wasm/roundtrip_test.mjs.
Neither is sufficient alone.

Requires the dev extras (see requirements-dev.txt) and, for step 5, a seedsigner
checkout. The decoder choice matters: OpenCV's built-in QRCodeDetector silently
fails on dense codes (it could not read a v16 symbol that zbar reads perfectly,
including one produced by the reference encoder itself), so it is not usable as
a correctness gate here.

Run:  python -m tools.verify              # representative sample, fast
      python -m tools.verify --all        # every scenario and every frame
"""
import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import base64
import numpy as np
from PIL import Image
from pyzbar.pyzbar import decode as zbar_decode
from embit import bip32, bip39, ec
from embit.networks import NETWORKS
from embit.psbt import PSBT
from urtypes.crypto import PSBT as URPSBT

from common import bbqr
from common.fixtures import load_seeds
from common.qr import qr_matrix
from common.seedqr import standard_seedqr_digits, compact_seedqr_bytes
from common.ur2.ur import UR
from common.ur2.ur_decoder import URDecoder
from common.ur2.ur_encoder import UREncoder

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DIST = os.path.join(ROOT, "site", "dist")

RENDER_SCALE = 4
RENDER_QUIET = 4

SEEDSIGNER_SRC = "/home/kdmukai/dev/seedsigner/src"


def load(rel):
    with open(os.path.join(DIST, rel)) as f:
        return json.load(f)


def matrix_image(frame) -> "np.ndarray":
    """Reconstruct a shipped frame into a white-bordered grayscale image."""
    m = frame["m"]
    bits = base64.b64decode(frame["b"])
    grid = np.ones((m + 2 * RENDER_QUIET, m + 2 * RENDER_QUIET), dtype=np.uint8) * 255
    for r in range(m):
        base = r * m
        for c in range(m):
            i = base + c
            if (bits[i >> 3] >> (7 - (i & 7))) & 1:
                grid[r + RENDER_QUIET, c + RENDER_QUIET] = 0
    return np.kron(grid, np.ones((RENDER_SCALE, RENDER_SCALE), dtype=np.uint8))


def decode_frame(frame) -> str:
    img = Image.fromarray(matrix_image(frame))
    results = zbar_decode(img)
    if not results:
        raise AssertionError(f"QR frame (v{frame['v']}, {frame['m']} modules) did not decode")
    return results[0].data.decode("utf-8")


def reassemble(payloads: list, fmt: str) -> bytes:
    """Decoded QR payloads -> raw PSBT bytes."""
    if fmt == "ur":
        decoder = URDecoder()
        for p in payloads:
            decoder.receive_part(p.lower())
        if not decoder.is_complete():
            raise AssertionError("UR decoder never completed")
        return bytes(URPSBT.from_cbor(decoder.result_message().cbor).data)
    # BBQR parts are uppercased for the QR's alphanumeric mode; the header's
    # base36 index fields are lowercase in the wire format, so restore them.
    return bbqr.decode([p[:2] + p[2:4] + p[4:8].lower() + p[8:] for p in payloads])


def root_key(mnemonic: str, network: str):
    return bip32.HDKey.from_seed(bip39.mnemonic_to_seed(mnemonic),
                                 version=NETWORKS[network]["xprv"])


def verify_sighashes(data, seeds, entry) -> list:
    """Prove the shipped verification block describes this exact transaction.

    site/psbt.js does no sighash construction of its own — it verifies a
    returned signature against the digest shipped here. That makes these digests
    load-bearing in a way nothing else in the build is: a wrong one turns a
    correct signature into a red cross on screen at a demo table, and there is
    no second opinion in the browser to catch it.

    So: sign the PSBT for real, then verify each signature against the SHIPPED
    digest rather than against a freshly computed one. Recomputing would only
    prove embit agrees with itself.
    """
    verify = data.get("verify")
    if not verify:
        return ["scenario ships no verification block"]

    psbt = PSBT.from_string(data["psbt_base64"])
    problems = []
    if psbt.tx.serialize().hex() != verify["unsigned_tx"]:
        problems.append("verify.unsigned_tx does not match the PSBT's transaction")
    if psbt.tx.txid().hex() != verify["txid"]:
        problems.append("verify.txid does not match the PSBT's transaction")

    network = "main" if entry["network"] == "main" else "test"
    signer = entry["signing_seeds"][0]
    psbt.sign_with(root_key(seeds[signer]["mnemonic"], network), sighash=None)

    for i, inp in enumerate(psbt.inputs):
        digest = bytes.fromhex(verify["inputs"][i]["sighash"])
        if verify["taproot"]:
            # Key-path spend: embit finalizes straight into the witness, and the
            # signature is checked against the tweaked output key from the
            # scriptPubKey — not the internal key in the derivation fields.
            witness = inp.final_scriptwitness
            if witness is None or not witness.items:
                problems.append(f"input {i}: taproot input produced no witness")
                continue
            key = ec.PublicKey.from_xonly(bytes.fromhex(verify["inputs"][i]["keys"][0]["pubkey"]))
            if not key.schnorr_verify(ec.SchnorrSig.parse(witness.items[0][:64]), digest):
                problems.append(f"input {i}: shipped sighash does not match the schnorr signature")
            continue

        if not inp.partial_sigs:
            problems.append(f"input {i}: no signature was produced")
            continue
        for pubkey, sig in inp.partial_sigs.items():
            # The trailing byte is the sighash flag, not part of the DER.
            if not pubkey.verify(ec.Signature.parse(sig[:-1]), digest):
                problems.append(f"input {i}: shipped sighash does not match the signature "
                                f"from {pubkey.sec().hex()[:16]}")
    return problems


def ur_frames(raw: bytes, ref: dict, full: bool) -> list:
    """Regenerate the UR frames the browser will produce from `ref`.

    The site ships the fragment size, not the frames. Feeding that parameter
    back through the same encoder the build used is what makes this a check on
    the shipped artifact rather than on a coincidence — get the fragment size
    wrong in the index and these frames stop reassembling.

    Runs one part past the pure set even in sampled mode: the last pure fragment
    is padded and the first mixed part is full-width, and those are the two
    frames most likely to differ in QR version from their neighbours.
    """
    encoder = UREncoder(UR("crypto-psbt", URPSBT(raw).to_cbor()),
                        ref["max_fragment"], 0, ref["min_fragment"])
    if encoder.is_single_part():
        return [encoder.next_part()]
    count = ref["count"] + (ref["count"] if full else 1)
    return [encoder.next_part() for _ in range(count)]


def verify_scenario(entry, seeds, full: bool, parser_cls, seed_cls, ss_network):
    data = load(f"data/scenario/{entry['id']}.json")
    psbt = PSBT.from_string(data["psbt_base64"])
    raw = psbt.serialize()
    problems = []

    # --- QR round-trip, through a real decoder --------------------------------
    variants = [(f, d) for f in entry["qr"] for d in entry["qr"][f]]
    if not full:
        # One dense and one sparse variant is enough for the sampled pass.
        variants = [("ur", "normal"), ("bbqr", "low")]
    for fmt, density in variants:
        ref = entry["qr"][fmt][density]
        try:
            if ref.get("runtime"):
                parts = ur_frames(raw, ref, full)
                frames = [dict(zip(("b", "v", "m"), qr_matrix(p))) for p in parts]
                if ref["modules"] < max(f["m"] for f in frames):
                    problems.append(
                        f"{fmt}/{density}: shipped module ceiling {ref['modules']} is "
                        f"below an actual frame ({max(f['m'] for f in frames)}) — the "
                        f"canvas would clip the QR")
            else:
                frames = load(ref["file"])["frames"]
            texts = [decode_frame(f) for f in frames]
            if reassemble(texts, fmt) != raw:
                problems.append(f"{fmt}/{density}: reassembled PSBT differs")
        except AssertionError as e:
            problems.append(f"{fmt}/{density}: {e}")

    # --- the sighash digests shipped for the scan-back step ------------------
    #
    # These are what the browser checks a returned signature against, so a wrong
    # digest means the site would reject a perfectly good signature (or, worse,
    # accept one over something else). Signing the PSBT and verifying the result
    # against the shipped digest is the direct test.
    problems += verify_sighashes(data, seeds, entry)

    # --- still signable -------------------------------------------------------
    network = "main" if entry["network"] == "main" else "test"
    signer = entry["signing_seeds"][0]
    added = PSBT.from_string(data["psbt_base64"]).sign_with(
        root_key(seeds[signer]["mnemonic"], network))
    if added != entry["num_inputs"]:
        problems.append(f"signing added {added} sigs, expected {entry['num_inputs']}")

    # --- SeedSigner's own parser agrees --------------------------------------
    if parser_cls is not None:
        p = parser_cls(PSBT.from_string(data["psbt_base64"]),
                       seed_cls(seeds[signer]["mnemonic"].split()),
                       ss_network(entry["network"]))
        s = data["summary"]
        if p.input_amount != s["input_amount"]:
            problems.append(f"PSBTParser input {p.input_amount} != {s['input_amount']}")
        if p.fee_amount != s["fee"]:
            problems.append(f"PSBTParser fee {p.fee_amount} != {s['fee']}")
        expect_multisig = entry["sig_type"] == "multisig"
        if p.is_multisig != expect_multisig:
            problems.append(f"PSBTParser multisig={p.is_multisig}, expected {expect_multisig}")
    return problems


def verify_seed(entry, seeds):
    data = load(entry["file"])
    words = data["mnemonic"].split()
    problems = []
    if decode_frame(data["standard"]["qr"]["frames"][0]) != standard_seedqr_digits(words):
        problems.append("standard SeedQR payload mismatch")
    if compact_seedqr_bytes(words).hex() != data["compact"]["payload_hex"]:
        problems.append("compact SeedQR payload mismatch")
    if data["mnemonic"] != seeds[entry["name"]]["mnemonic"]:
        problems.append("mnemonic does not match the fixture")
    return problems


def verify_wallet(entry):
    data = load(entry["file"])
    problems = []
    for ur_type, spec in data["descriptor_urs"].items():
        decoded = decode_frame(spec["qr"]["frames"][0])
        # UR payloads are shipped uppercased (alphanumeric mode); bytewords
        # decoders are case-insensitive, so compare case-insensitively.
        if decoded.lower() != spec["payload"].lower():
            problems.append(f"descriptor QR does not decode to its ur:{ur_type}")
    for branch, items in data["addresses"].items():
        for item in items:
            # Addresses must survive VERBATIM — upper-casing would destroy a
            # base58 address, so this asserts exact case.
            decoded = decode_frame(item["qr"]["frames"][0])
            if decoded != item["address"]:
                problems.append(
                    f"{branch}/{item['index']} address QR mismatch: "
                    f"decoded {decoded!r} != {item['address']!r}")
    return problems


def load_seedsigner():
    """SeedSigner's PSBTParser, if a checkout is available."""
    if not os.path.isdir(SEEDSIGNER_SRC):
        return None, None, None
    sys.path.insert(0, SEEDSIGNER_SRC)
    try:
        from seedsigner.models.psbt_parser import PSBTParser
        from seedsigner.models.seed import Seed
        from seedsigner.models.settings import SettingsConstants
    except ImportError as e:
        print(f"  (skipping SeedSigner cross-check: {e})")
        return None, None, None
    def network(n):
        return SettingsConstants.MAINNET if n == "main" else SettingsConstants.TESTNET
    return PSBTParser, Seed, network


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--all", action="store_true",
                    help="verify every scenario and every QR variant (slow)")
    args = ap.parse_args()

    if not os.path.isdir(DIST):
        sys.exit(f"{DIST} not found — run `python -m tools.build_site` first.")

    index = load("data/index.json")
    seeds = load_seeds()
    parser_cls, seed_cls, ss_network = load_seedsigner()
    if parser_cls:
        print("Cross-checking against SeedSigner's PSBTParser\n")

    scenarios = index["scenarios"]
    if not args.all:
        # One per (script type, output shape) plus every stress case: covers the
        # matrix without decoding tens of thousands of frames.
        seen, sampled = set(), []
        for s in scenarios:
            key = (s["script_type"], s["output_shape"], s["network"])
            if key not in seen or s["num_inputs"] >= 20:
                seen.add(key)
                sampled.append(s)
        scenarios = sampled

    failures = 0
    for i, entry in enumerate(scenarios, 1):
        problems = verify_scenario(entry, seeds, args.all, parser_cls, seed_cls, ss_network)
        status = "OK" if not problems else "FAIL"
        print(f"  [{i:>3}/{len(scenarios)}] {entry['id']:<46s} {status}")
        for p in problems:
            failures += 1
            print(f"        - {p}")

    print()
    for entry in index["seeds"]:
        problems = verify_seed(entry, seeds)
        print(f"  seed   {entry['name']:<44s} {'OK' if not problems else 'FAIL'}")
        for p in problems:
            failures += 1
            print(f"        - {p}")

    print()
    for entry in index["wallets"]:
        problems = verify_wallet(entry)
        print(f"  wallet {entry['name']:<44s} {'OK' if not problems else 'FAIL'}")
        for p in problems:
            failures += 1
            print(f"        - {p}")

    print(f"\n{'PASS — no problems found' if not failures else f'FAILED — {failures} problem(s)'}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
