"""End-to-end verification of the BUILT site in site/dist/.

This checks the artifacts that actually ship, not a fresh in-memory rebuild,
so a bug in the packing/serialization layer can't hide behind correct
intermediate values. For each scenario it:

  1. renders every QR matrix back to an image and **decodes it with an
     independent QR decoder** (zbar), proving the bits are a readable QR and
     not just plausible-looking noise;
  2. feeds the decoded payloads back through the UR / BBQR decoders and asserts
     the reconstructed PSBT is byte-identical to the scenario's PSBT;
  3. asserts the PSBT still signs with its intended seed;
  4. checks the shipped sighash digests are the ones a signature over this
     transaction actually commits to, by signing and verifying against them,
     and that the shipped reference signatures are the ones that signing
     produced;
  5. parses it with **SeedSigner's own PSBTParser** and checks the policy and
     amounts match what the generator intended.

BBQR frames ship pre-rendered and are read straight out of site/dist/. UR
frames do not exist on disk any more (the browser generates them at runtime),
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
      python -m tools.verify --derivations --seedsigner ~/seedsigner/src

The SeedSigner checkout is --seedsigner, else $SEEDSIGNER_SRC, else SEEDSIGNER_SRC
below. --derivations checks only the Validate derivations test group: each psbt must
parse with no validator, as dev parses it, and, on a checkout that has the validator,
come out exactly as its scenario def says (the refusal, its validator result and the
path the screen draws, or a clean parse and whether the change is marked distant).
"""
import argparse
import json
import os
import sys
from types import SimpleNamespace

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import base64
import numpy as np
from PIL import Image
from pyzbar.pyzbar import decode as zbar_decode
from embit import ec
from embit.psbt import PSBT
from urtypes.crypto import PSBT as URPSBT

from common import bbqr
from common import scenarios as scenario_defs
from common.fixtures import load_seeds
from common.keys import root_key
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


def verify_sighashes(data, seeds, entry) -> list:
    """Prove the shipped verification block describes this exact transaction.

    site/psbt.js does no sighash construction of its own; it verifies a
    returned signature against the digest shipped here. That makes these digests
    critical in a way nothing else in the build is: a wrong one turns a correct
    signature into a red cross on screen at a demo table, and there is no second
    opinion in the browser to catch it.

    So: sign the PSBT for real, then verify each signature against the SHIPPED
    digest rather than against a freshly computed one. Recomputing would only
    prove embit agrees with itself.

    The same signatures are compared with the shipped reference signatures,
    which the browser holds a device's signature to byte for byte. That
    comparison is embit against embit, so it cannot prove the nonce derivation
    right; what it catches is the build attaching a reference to the wrong key
    or input, which would show every honest scan as "not the expected
    signature".
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
        shipped = {k["pubkey"]: k.get("signature") for k in verify["inputs"][i]["keys"]}
        if verify["taproot"]:
            # Key-path spend: embit finalizes straight into the witness, and the
            # signature is checked against the tweaked output key from the
            # scriptPubKey, not the internal key in the derivation fields.
            witness = inp.final_scriptwitness
            if witness is None or not witness.items:
                problems.append(f"input {i}: taproot input produced no witness")
                continue
            key = ec.PublicKey.from_xonly(bytes.fromhex(verify["inputs"][i]["keys"][0]["pubkey"]))
            if not key.schnorr_verify(ec.SchnorrSig.parse(witness.items[0][:64]), digest):
                problems.append(f"input {i}: shipped sighash does not match the schnorr signature")
            if witness.items[0].hex() != shipped.get(key.xonly().hex()):
                problems.append(f"input {i}: shipped reference signature is not the one "
                                f"signing produced")
            continue

        if not inp.partial_sigs:
            problems.append(f"input {i}: no signature was produced")
            continue
        for pubkey, sig in inp.partial_sigs.items():
            # The trailing byte is the sighash flag, not part of the DER.
            if not pubkey.verify(ec.Signature.parse(sig[:-1]), digest):
                problems.append(f"input {i}: shipped sighash does not match the signature "
                                f"from {pubkey.sec().hex()[:16]}")
            if sig.hex() != shipped.get(pubkey.sec().hex()):
                problems.append(f"input {i}: shipped reference signature for "
                                f"{pubkey.sec().hex()[:16]} is not the one signing produced")
    return problems


def ur_frames(raw: bytes, ref: dict, full: bool) -> list:
    """Regenerate the UR frames the browser will produce from `ref`.

    The site ships the fragment size, not the frames. Feeding that parameter
    back through the same encoder the build used is what makes this a check on
    the shipped artifact rather than on a coincidence: get the fragment size
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
                        f"below an actual frame ({max(f['m'] for f in frames)}); the "
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
        # SeedSigner PR #995 renames input_amount to verified_input_amount
        parsed_input = p.verified_input_amount if hasattr(p, "verified_input_amount") else p.input_amount
        if parsed_input != s["input_amount"]:
            problems.append(f"PSBTParser input {parsed_input} != {s['input_amount']}")
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
            # Addresses must survive VERBATIM: upper-casing would destroy a
            # base58 address, so this asserts exact case.
            decoded = decode_frame(item["qr"]["frames"][0])
            if decoded != item["address"]:
                problems.append(
                    f"{branch}/{item['index']} address QR mismatch: "
                    f"decoded {decoded!r} != {item['address']!r}")
    return problems


def verify_scenario_descriptor(entry):
    """A test scenario's own descriptor (PR #1087): each format's QR must decode to its
    payload. A UR ships upper-cased, so it compares without case; text must survive
    verbatim, since upper-casing it would corrupt the xpubs. What the device then does
    with the descriptor is checked against SeedSigner itself, outside CI."""
    descriptor = load(f"data/scenario/{entry['id']}.json").get("descriptor")
    if descriptor is None:
        return []
    problems = []
    for fmt, spec in descriptor["formats"].items():
        decoded = decode_frame(spec["qr"]["frames"][0])
        if fmt.startswith("crypto-"):
            matches = decoded.lower() == spec["payload"].lower()
        else:
            matches = decoded == spec["payload"]
        if not matches:
            problems.append(f"descriptor QR does not decode to its {fmt} payload")
    return problems


def load_seedsigner(src: str):
    """SeedSigner's PSBTParser, if a checkout is available at `src`."""
    if not os.path.isdir(src):
        return None, None, None
    sys.path.insert(0, src)
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


def load_derivation_checks():
    """SeedSigner's derivation path validator and the refusals it raises, or None on a
    checkout from before Validate derivations. Call after load_seedsigner."""
    try:
        from seedsigner.helpers.embit_utils import get_display_derivation_path
        from seedsigner.models import psbt_parser
        from seedsigner.models.derivation_path_validator import DerivationPathValidator
    except ImportError:
        return None
    refusals = {
        DerivationPathValidator.STATUS__NONSTANDARD:
            psbt_parser.PSBTNonstandardDerivationPathError,
        DerivationPathValidator.STATUS__ANOTHER_SCRIPT_TYPE:
            psbt_parser.PSBTDerivationPathScriptTypeMismatchError,
        DerivationPathValidator.STATUS__ANOTHER_NETWORK:
            psbt_parser.PSBTDerivationPathNetworkMismatchError,
    }
    # Refusals added later in the branch's life; an older checkout lacks them
    for status, name in (("change_follows_nonstandard", "PSBTChangeFollowsNonstandardInputError"),
                         ("mixed_networks", "PSBTDerivationPathMixedNetworksError")):
        if hasattr(psbt_parser, name):
            refusals[status] = getattr(psbt_parser, name)
    return SimpleNamespace(
        validator=DerivationPathValidator,
        display=get_display_derivation_path,
        refusals=refusals)


def verify_derivations(entry, check, seeds, parser_cls, seed_cls, ss_network, dv) -> list:
    """Hold one Validate derivations scenario to its def's `check`."""
    data = load(f"data/scenario/{entry['id']}.json")
    seed = seed_cls(seeds[entry["signing_seeds"][0]]["mnemonic"].split())
    network = ss_network(entry["network"])

    def parse(**kwargs):
        return parser_cls(PSBT.from_string(data["psbt_base64"]), seed, network, **kwargs)

    def distant(p):
        return any(c["address_index_beyond_window"] for c in p.change_data)

    problems = []
    # With the setting off the parser gets no validator, which is what dev does: every
    # psbt in the group parses, and none is marked distant.
    try:
        if distant(parse()):
            problems.append("without a validator: change marked distant, which dev does not do")
    except Exception as e:
        problems.append(f"without a validator: {type(e).__name__}: {e}")
    if dv is None:
        return problems

    expected = dv.refusals.get(check["status"])
    try:
        p = parse(derivation_path_validator=dv.validator())
    except tuple(dv.refusals.values()) as e:
        if expected is None or type(e) is not expected:
            want = expected.__name__ if expected else "a clean parse"
            return problems + [f"with a validator: {type(e).__name__}, expected {want}"]
        result = getattr(e, "validation_result", None)
        if result is None:
            # A refusal with no single path to show, such as mixed networks
            return problems
        for field in ("status", "offending_level_index", "indicated_network",
                      "indicated_policy_type"):
            want = check[field]
            if field == "status":
                # The refusal can differ from the shown path's own status: change that
                # follows a nonstandard input shows the change's nonstandard path
                want = check.get("path_status", want)
            if field == "indicated_network" and want is not None:
                want = ss_network(want)
            if getattr(result, field) != want:
                problems.append(f"with a validator: {field} {getattr(result, field)!r}, "
                                f"expected {want!r}")
        # Nonstandard Path and the change refusal show a long path on two lines
        two_lines = (result.status == dv.validator.STATUS__NONSTANDARD
                     or check["status"] == "change_follows_nonstandard")
        max_lines = 2 if two_lines else 1
        text = dv.display(result.derivation_path, result.offending_level_index,
                          max_lines=max_lines)
        if text != check["text"]:
            problems.append(f"with a validator: screen shows {text!r}, expected "
                            f"{check['text']!r}")
        return problems
    except Exception as e:
        return problems + [f"with a validator: {type(e).__name__}: {e}"]

    if expected is not None:
        problems.append(f"with a validator: parsed, expected {expected.__name__}")
    elif distant(p) != check["distant"]:
        problems.append(f"with a validator: change marked distant is {distant(p)}, "
                        f"expected {check['distant']}")
    return problems


def main_derivations(index, seeds, parser_cls, seed_cls, ss_network):
    if parser_cls is None:
        sys.exit("--derivations needs a SeedSigner checkout; pass --seedsigner PATH.")
    dv = load_derivation_checks()
    if dv is None:
        print("This checkout has no derivation path validator, so only the parse without "
              "one, as dev parses, is checked.\n")
    checks = {s.id: s.derivation_check for s in scenario_defs.test_scenarios()
              if s.pr == "1090"}
    entries = [s for s in index["scenarios"] if s["id"] in checks]
    if len(entries) != len(checks):
        sys.exit(f"site/dist has {len(entries)} of the group's {len(checks)} scenarios; "
                 f"rebuild the site.")
    failures = 0
    for i, entry in enumerate(entries, 1):
        problems = verify_derivations(entry, checks[entry["id"]], seeds, parser_cls,
                                      seed_cls, ss_network, dv)
        print(f"  [{i:>2}/{len(entries)}] {entry['id']:<46s} {'OK' if not problems else 'FAIL'}")
        for problem in problems:
            failures += 1
            print(f"        - {problem}")
    print(f"\n{'PASS: no problems found' if not failures else f'FAILED: {failures} problem(s)'}")
    return 1 if failures else 0


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--all", action="store_true",
                    help="verify every scenario and every QR variant (slow)")
    ap.add_argument("--seedsigner", metavar="PATH",
                    help="SeedSigner's src directory (default: $SEEDSIGNER_SRC, then "
                         f"{SEEDSIGNER_SRC})")
    ap.add_argument("--derivations", action="store_true",
                    help="check only the Validate derivations group against SeedSigner")
    args = ap.parse_args()

    if not os.path.isdir(DIST):
        sys.exit(f"{DIST} not found; run `python -m tools.build_site` first.")

    index = load("data/index.json")
    seeds = load_seeds()
    src = args.seedsigner or os.environ.get("SEEDSIGNER_SRC") or SEEDSIGNER_SRC
    parser_cls, seed_cls, ss_network = load_seedsigner(os.path.expanduser(src))
    if args.derivations:
        return main_derivations(index, seeds, parser_cls, seed_cls, ss_network)
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

    # Cheap (one single-frame QR or two each), so every test scenario, sampled or not
    print()
    for entry in index["scenarios"]:
        if not entry.get("test"):
            continue
        problems = verify_scenario_descriptor(entry)
        if problems:
            print(f"  descriptor {entry['id']:<40s} FAIL")
        for p in problems:
            failures += 1
            print(f"        - {p}")
    print("  test scenario descriptors checked")

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

    print(f"\n{'PASS: no problems found' if not failures else f'FAILED: {failures} problem(s)'}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
