"""Emit the reference data tools/wasm/roundtrip_test.mjs checks itself against.

Reads the BUILT site in site/dist/, so the fixtures describe what actually
ships rather than a fresh in-memory rebuild.

Two independent bodies of reference data:

**UR/QR cases.** Once the browser generates UR frames at runtime, the old
guarantee — "Python pre-renders Sparrow-exact matrices, so there is no encoder
in the browser to keep faithful" — is gone. These restore it as a checked
property: Python produces the UR parts and their QR versions for a sample of
real transactions, and the test asserts the WASM module agrees. The fountain
sequence is the delicate half; the mixed parts only match if cUR's Xoshiro256
sampler is seeded and stepped exactly like common/ur2's, which is the sort of
thing that is either right or wildly wrong.

**Signed-PSBT cases.** Real signatures produced by embit, plus the negative
cases that give the positives meaning: unsigned, tampered (one bit flipped
inside a signature), under-threshold, and a perfectly valid signature over the
WRONG transaction. A verifier that cannot reject those is decoration.

Run:  python -m tools.wasm.reference            (writes to the default path)
      python -m tools.wasm.reference --out X.json
"""
import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

import base64

from embit import bip32, bip39
from embit.networks import NETWORKS
from embit.psbt import PSBT
from embit.transaction import Witness
from urtypes.crypto import PSBT as URPSBT

from common.fixtures import load_seeds
from common.qr import qr_matrix
from common.ur2.ur import UR
from common.ur2.ur_encoder import UREncoder
from tools.build_site import FORMATS, MIN_FRAGMENT_BYTES

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DIST = os.path.join(ROOT, "site", "dist")
DEFAULT_OUT = os.path.join(ROOT, "tools", "wasm", "reference.json")

# Parts to generate past the pure set. Enough to be well inside the fountain,
# where any disagreement in the sampler shows up; the pure prefix alone would
# pass with a completely wrong mixed-part implementation.
MIXED_TAIL = 24

# Sequence numbers to spot-check far downstream. A demo left running reaches
# five-digit sequence numbers, and that is also where the UR string grows a
# character and can push the QR to the next version — so it is worth proving the
# two encoders still agree out there rather than only near the start.
FAR_SEQ_NUMS = [500, 5000, 50000]


def load_index() -> dict:
    with open(os.path.join(DIST, "data", "index.json")) as f:
        return json.load(f)


def scenario_psbt(scenario_id: str) -> bytes:
    with open(os.path.join(DIST, "data", "scenario", f"{scenario_id}.json")) as f:
        return PSBT.from_string(json.load(f)["psbt_base64"]).serialize()


def encoder_for(raw: bytes, max_fragment: int, first_seq_num: int = 0) -> UREncoder:
    ur = UR("crypto-psbt", URPSBT(raw).to_cbor())
    return UREncoder(ur, max_fragment, first_seq_num, MIN_FRAGMENT_BYTES)


def build_case(scenario_id: str, raw: bytes, density: str, max_fragment: int) -> dict:
    encoder = encoder_for(raw, max_fragment)
    seq_len = 1 if encoder.is_single_part() else encoder.fountain_encoder.seq_len()
    count = 1 if encoder.is_single_part() else seq_len + MIXED_TAIL

    parts, frames = [], []
    for _ in range(count):
        part = encoder.next_part()
        b64, version, modules = qr_matrix(part)     # uppercases, exactly as shipped
        parts.append(part)
        frames.append({"m": modules, "v": version, "b": b64})

    # Far-downstream spot checks. Each starts its own encoder at `n`, which also
    # asserts the fountain is a pure function of the sequence number rather than
    # of how many parts happen to have been pulled already.
    far = []
    if not encoder.is_single_part():
        for n in FAR_SEQ_NUMS:
            part = encoder_for(raw, max_fragment, n).next_part()
            b64, version, modules = qr_matrix(part)
            far.append({"seq": n, "part": part,
                        "frame": {"m": modules, "v": version, "b": b64}})

    return {
        "id": scenario_id,
        "density": density,
        "psbt_base64": base64.b64encode(raw).decode("ascii"),
        "max_fragment": max_fragment,
        "seq_len": seq_len,
        "single_part": encoder.is_single_part(),
        "parts": parts,
        "frames": frames,
        "far": far,
    }


# --- signed-PSBT cases for site/psbt.js --------------------------------------

# One case per signing shape the verifier has a distinct code path for.
SIGNING_SCENARIOS = [
    "ss_native_segwit-change-3in",   # ECDSA, segwit — the common case
    "ss_legacy-change-3in",          # ECDSA, legacy sighash
    "ss_taproot-change-3in",         # Schnorr, key-path, sig in the witness
    "2of3_p2wsh-change-3in",         # multiple signatures per input
]


def root_key(mnemonic: str, network: str):
    return bip32.HDKey.from_seed(bip39.mnemonic_to_seed(mnemonic),
                                 version=NETWORKS[network]["xprv"])


def sign_psbt(b64: str, mnemonics: list, network: str) -> str:
    psbt = PSBT.from_string(b64)
    for mnemonic in mnemonics:
        # sighash=None means "sign with whatever the PSBT asks for", which is
        # what a real signer does; the default would refuse anything but DEFAULT.
        psbt.sign_with(root_key(mnemonic, network), sighash=None)
    return psbt.to_string()


def tamper(b64: str) -> str:
    """Flip one bit deep inside the first input's signature.

    A verifier that only checks structure passes this happily, which is exactly
    why it is here: the negative cases are what prove the check can say no.

    The bit is chosen inside the signature VALUE, never its framing — byte 10 of
    a DER signature is inside `r` (the header is `30 <len> 02 20`), and byte 10
    of a Schnorr signature is inside `R`. So the result stays a well-formed,
    parseable signature that simply is not a signature over this transaction,
    which is the failure worth catching. Corrupting the DER framing instead
    would be caught by the parser and prove nothing about the curve check.

    Rewritten through embit rather than by pattern-matching raw bytes, so a
    taproot PSBT (whose signature lives in the witness, with no DER framing to
    search for) is handled by the same code.
    """
    psbt = PSBT.from_string(b64)
    inp = psbt.inputs[0]

    if inp.partial_sigs:
        pubkey, sig = next(iter(inp.partial_sigs.items()))
        raw = bytearray(sig)
        raw[10] ^= 0x01
        inp.partial_sigs[pubkey] = bytes(raw)
    elif inp.final_scriptwitness is not None:
        items = [bytearray(i) for i in inp.final_scriptwitness.items]
        items[0][10] ^= 0x01
        inp.final_scriptwitness = Witness([bytes(i) for i in items])
    else:
        raise AssertionError("nothing signed to tamper with")
    return psbt.to_string()


def build_signing_cases(index: dict) -> list:
    seeds = load_seeds()
    by_id = {s["id"]: s for s in index["scenarios"]}
    cases = []

    for scenario_id in SIGNING_SCENARIOS:
        entry = by_id.get(scenario_id)
        if entry is None:
            print(f"  (skipping {scenario_id}: not in this build)")
            continue
        with open(os.path.join(DIST, "data", "scenario", f"{scenario_id}.json")) as f:
            data = json.load(f)
        network = "main" if entry["network"] == "main" else "test"
        verify = data["verify"]
        b64 = data["psbt_base64"]

        cosigners = entry["signing_seeds"]
        threshold = entry["threshold"] or 1
        enough = [seeds[n]["mnemonic"] for n in cosigners[:threshold]]

        cases.append({"label": f"{scenario_id} signed", "verify": verify,
                      "psbt_base64": sign_psbt(b64, enough, network),
                      "expect": {"txMatches": True, "complete": True,
                                 "anyInvalid": False},
                      "expect_signers": cosigners[:threshold]})

        cases.append({"label": f"{scenario_id} unsigned", "verify": verify,
                      "psbt_base64": b64,
                      "expect": {"txMatches": True, "complete": False,
                                 "anyInvalid": False}})

        cases.append({"label": f"{scenario_id} tampered", "verify": verify,
                      "psbt_base64": tamper(sign_psbt(b64, enough, network)),
                      "expect": {"txMatches": True, "complete": False,
                                 "anyInvalid": True}})

        if threshold > 1:
            cases.append({"label": f"{scenario_id} one of {threshold}",
                          "verify": verify,
                          "psbt_base64": sign_psbt(b64, enough[:1], network),
                          "expect": {"txMatches": True, "complete": False,
                                     "partial": True, "anyInvalid": False}})

    # A correctly signed PSBT for a DIFFERENT transaction, checked against the
    # first scenario's expectations. Every signature in it is cryptographically
    # valid — only the transaction is wrong — so this is the case that proves
    # the unsigned-transaction comparison is doing real work rather than riding
    # along behind the signature check.
    if len(cases) >= 2:
        first = next(c for c in cases if c["label"].endswith("signed"))
        other = next((c for c in cases[1:]
                      if c["label"].endswith("signed")
                      and c["verify"]["txid"] != first["verify"]["txid"]), None)
        if other is not None:
            cases.append({"label": "signed, but a different transaction",
                          "verify": first["verify"],
                          "psbt_base64": other["psbt_base64"],
                          "expect": {"txMatches": False, "complete": False}})
    return cases


def pick_scenarios(index: dict) -> list:
    """One small, one middling and the largest transaction on offer.

    Size is what moves the interesting variables: seq_len, whether a payload is
    single-part at all, and how many digits the sequence number carries.
    """
    scenarios = sorted(index["scenarios"], key=lambda s: s["psbt_bytes"])
    if not scenarios:
        return []
    picks = {scenarios[0]["id"]: scenarios[0],
             scenarios[len(scenarios) // 2]["id"]: scenarios[len(scenarios) // 2],
             scenarios[-1]["id"]: scenarios[-1]}
    return list(picks.values())


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", default=DEFAULT_OUT)
    args = ap.parse_args()

    if not os.path.isdir(DIST):
        sys.exit(f"{DIST} not found — run `python -m tools.build_site` first.")

    index = load_index()
    cases = []
    for scenario in pick_scenarios(index):
        raw = scenario_psbt(scenario["id"])
        for density, max_fragment in FORMATS["ur"]["densities"].items():
            case = build_case(scenario["id"], raw, density, max_fragment)
            cases.append(case)
            print(f"  {scenario['id']:<44s} {density:<7s} "
                  f"{len(raw):>7,}B  seq_len {case['seq_len']:>3}  "
                  f"{len(case['parts'])} parts")

    print()
    signing = build_signing_cases(index)
    for case in signing:
        print(f"  {case['label']}")

    with open(args.out, "w") as f:
        json.dump({"min_fragment": MIN_FRAGMENT_BYTES, "cases": cases,
                   "signing": signing}, f)
    print(f"\nWrote {args.out} ({os.path.getsize(args.out) / 1024:.0f} KiB)")


if __name__ == "__main__":
    main()
