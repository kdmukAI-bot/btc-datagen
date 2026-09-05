"""The demo transaction matrix.

Static hosting means every PSBT has to exist before anyone loads the page, so
"configurable" is a bounded matrix presented as pickers rather than arbitrary
runtime construction. The matrix is deliberately shaped rather than a full cross
product (which would be ~340 cases, most of them redundant):

  * a **full cross** of all seven script types x all four output shapes at the
    default input count: this is the "what does each wallet type look like"
    axis, and it's the one people actually poke at;
  * an **input-count sweep** on the two representative types only, because input
    count is really a QR-payload-size axis and doesn't interact with script type
    in any way a demo reveals. 30 inputs is the usual stress test; 100 is the
    extreme.

Both are built for both networks.
"""
from dataclasses import dataclass, field

from common import script_types

DEFAULT_NUM_INPUTS = 3

# Wallet fixture to use for each script type (base name; `_testnet` is appended
# for the test network).
WALLET_FOR_SCRIPT_TYPE = {
    "P2WPKH": "ss_native_segwit",
    "P2SH-P2WPKH": "ss_nested_segwit",
    "P2TR": "ss_taproot",
    "P2PKH": "ss_legacy",
    "P2WSH": "2of3_p2wsh",
    "P2SH-P2WSH": "2of3_p2sh_p2wsh",
    "P2SH": "2of3_p2sh",
}

# Input counts swept on the two representative script types.
SWEEP_SCRIPT_TYPES = ["P2WPKH", "P2WSH"]
SWEEP_INPUT_COUNTS = [1, 2, 5, 20, 30, 100]

OUTPUT_SHAPE_LABELS = {
    "change": "Send with change",
    "full_spend": "Full spend (no change)",
    "self_transfer": "Self-transfer",
    "multi_recipient": "Three recipients + change",
}

OUTPUT_SHAPE_BLURBS = {
    "change": "One external recipient, the remainder back to the wallet as change, "
              "plus the network fee.",
    "full_spend": "Sweeps the whole balance to one external recipient, no change "
                  "output at all.",
    "self_transfer": "Pays back to the wallet's own receive address rather than a "
                     "third party. SeedSigner counts both outputs as change.",
    "multi_recipient": "A batched payment: three separate external recipients plus "
                       "change.",
}


@dataclass
class Scenario:
    id: str
    wallet: str
    script_type: str
    num_inputs: int
    output_shape: str
    network: str
    title: str
    blurb: str
    is_default: bool = False
    tags: list = field(default_factory=list)
    # Adversarial / malformed test scenarios. None on the ordinary demo
    # transactions. `pr` groups them by the SeedSigner PR they exercise (each PR
    # gets its own picker toggle); `attack` selects the forgery builder;
    # `load_seed` overrides which seed the "Load the seed" step presents (the
    # point of the wrong-seed case); `expected*` describe what the device should
    # do so the sample is useful to run on hardware.
    pr: str = None                     # "1013" | "1032"
    attack: str = None
    load_seed: str = None
    expected: str = None
    expected_screen: str = None


def _make(script_type, shape, num_inputs, network, is_default=False):
    info = script_types.get(script_type)
    base_wallet = WALLET_FOR_SCRIPT_TYPE[script_type]
    wallet = base_wallet if network == "main" else f"{base_wallet}_testnet"
    suffix = "" if network == "main" else "-testnet"
    sid = f"{base_wallet}-{shape}-{num_inputs}in{suffix}"
    inputs_label = f"{num_inputs} input" + ("s" if num_inputs != 1 else "")
    title = f"{info.label}: {OUTPUT_SHAPE_LABELS[shape]}"
    blurb = f"{inputs_label}. {OUTPUT_SHAPE_BLURBS[shape]}"
    tags = [info.sig_type, info.label]
    if num_inputs >= 20:
        tags.append("stress test")
    return Scenario(id=sid, wallet=wallet, script_type=script_type,
                    num_inputs=num_inputs, output_shape=shape, network=network,
                    title=title, blurb=blurb, is_default=is_default, tags=tags)


def all_scenarios(networks=("main", "test")) -> list:
    out, seen = [], set()
    for network in networks:
        # Full cross at the default input count.
        for script_type in script_types.SCRIPT_TYPES:
            for shape in OUTPUT_SHAPE_LABELS:
                is_default = (network == "main" and script_type == "P2WPKH"
                              and shape == "change")
                s = _make(script_type, shape, DEFAULT_NUM_INPUTS, network, is_default)
                out.append(s)
                seen.add(s.id)
        # Input-count sweep on the representative types.
        for script_type in SWEEP_SCRIPT_TYPES:
            for n in SWEEP_INPUT_COUNTS:
                s = _make(script_type, "change", n, network)
                if s.id not in seen:
                    out.append(s)
                    seen.add(s.id)
    return out


def default_scenario(scenarios: list) -> Scenario:
    return next(s for s in scenarios if s.is_default)


# --- adversarial / malformed test scenarios ----------------------------------
#
# Hidden behind per-PR "show test scenarios" toggles in the picker. These are NOT
# part of the demo; each exists to run against a build of the named PR on real
# hardware and watch the device reject it. Deliberately small and curated, and
# mainnet only (the checks are network-agnostic and the demo defaults to mainnet).

# The seed the forgeries impersonate: the honest signer of the single-sig test
# wallets and a cosigner of the multisig one, so "load this seed" is unambiguous.
TEST_VICTIM_SEED = "alice"
# A seed that is NOT a key in the native-segwit test wallet, for "Seed Can't Sign".
TEST_DECOY_SEED = "bob"

# One picker toggle per PR, in listing order. `blurb` heads the group so a tester
# knows what the whole set probes.
TEST_PR_GROUPS = [
    {
        "pr": "1013",
        "label": "PR #1013: ownership scan",
        "url": "https://github.com/seedsigner/seedsigner/pull/1013",
        "blurb": ("Re-derive every claim of this seed's fingerprint and reject a psbt "
                  "that names our fingerprint on a key the seed cannot derive."),
    },
    {
        "pr": "1032",
        "label": "PR #1032: change output ownership",
        "url": "https://github.com/seedsigner/seedsigner/pull/1032",
        "blurb": ("An output counts as change only when the script rebuilt from this "
                  "seed matches what the output commits to. Contradictions and "
                  "malformed derivation bookkeeping are refused."),
    },
]

# script_type -> (short family name, wallet fixture base name), for PR #1013.
TEST_SCRIPT_FAMILIES = [
    ("P2WPKH", "Native SegWit"),
    ("P2TR", "Taproot"),
    ("P2WSH", "Multisig (2-of-3)"),
]

_ATTACK_DEFS = {  # PR #1013
    "fake_change": {
        "label": "Fake change attack",
        "expected_screen": "Suspicious Transaction / Likely an Attack!",
        "expected": "Device should refuse it as likely an attack.",
        # Single-key families (native segwit, taproot): the scriptPubKey is
        # repointed at the attacker, so the funds really leave.
        "blurb": ("An output is dressed up as change back to your own wallet, but the "
                  "key it names is one your seed does not own, so the funds actually "
                  "leave to an attacker. The device re-derives the key and the claim "
                  "collapses."),
        # Multisig: the real change script is left in place (the funds return to
        # your own 2-of-3); only the ownership claim is forged. This is the case
        # 0.8.7 misses, because it checks the script, not the claimed key.
        "blurb_multisig": ("The output really is your own change, back to your 2-of-3, "
                           "so no funds move. But the psbt annotates it with a key your "
                           "seed cannot derive, a false ownership claim that nothing in "
                           "0.8.7 objects to."),
    },
    "bad_input": {
        "label": "Malformed input ownership",
        "expected_screen": "Transaction Problem",
        "expected": "Device should reject it as a malformed transaction.",
        "blurb": ("An input claims your fingerprint on a key your seed does not derive. "
                  "It gains an attacker nothing (it is unsignable either way), so the "
                  "device treats it as broken data rather than an attack."),
    },
    "wrong_seed": {
        "label": "Wrong seed loaded",
        "expected_screen": "Seed Can't Sign",
        "expected": "Device should say this seed can't sign it.",
        "blurb": ("A perfectly ordinary, honest transaction, for a wallet this seed is "
                  "not part of. Load the decoy seed and the device finds no input it "
                  "can sign."),
    },
}


def _make_test(attack, script_type, family):
    info = script_types.get(script_type)
    base_wallet = WALLET_FOR_SCRIPT_TYPE[script_type]
    d = _ATTACK_DEFS[attack]
    slug = script_type.lower().replace("-", "_")
    sid = f"test-{attack.replace('_', '-')}-{slug}"
    # Some forgeries behave differently for multisig (see fake_change: single-key
    # families redirect the funds, multisig does not), so a per-family blurb wins.
    blurb = d["blurb_multisig"] if (info.is_multisig and "blurb_multisig" in d) else d["blurb"]
    load_seed = TEST_DECOY_SEED if attack == "wrong_seed" else TEST_VICTIM_SEED
    return Scenario(
        id=sid, wallet=base_wallet, script_type=script_type,
        num_inputs=DEFAULT_NUM_INPUTS, output_shape="change", network="main",
        title=f"⚠ {d['label']} ({family})", blurb=blurb, is_default=False,
        tags=["test", d["label"], info.label],
        pr="1013", attack=attack, load_seed=load_seed,
        expected=d["expected"], expected_screen=d["expected_screen"],
    )


# PR #1032 / stage D5: output ownership. Each entry pins the forgery builder
# (common/attack_psbt.build_d5_psbt), the wallet it runs on, and the device screen
# it should route to. Contradictions land on the attack warning; the structural
# refusals (surplus paths, mixed maps) land on the plain "Transaction Problem".
_D5_ATTACK_SCREEN = "Suspicious Transaction / Likely an Attack!"
_D5_PROBLEM_SCREEN = "Transaction Problem"
_D5_REFUSE = "Device should refuse it as likely an attack."
_D5_MALFORMED = "Device should reject it as a malformed transaction."

_D5_DEFS = [
    {"kind": "contradiction_singlesig", "script_type": "P2WPKH", "family": "Native SegWit",
     "label": "Fake change pays another key",
     "screen": _D5_ATTACK_SCREEN, "expected": _D5_REFUSE,
     "blurb": ("It is labeled as change back to this seed, but the scriptPubKey pays a "
               "key you do not own, so the funds really leave.")},
    {"kind": "contradiction_multisig", "script_type": "P2WSH", "family": "Multisig (2-of-3)",
     "label": "Fake change to a foreign multisig",
     "screen": _D5_ATTACK_SCREEN, "expected": _D5_REFUSE,
     "blurb": ("It is labeled as change back to this seed, but it pays an attacker's "
               "2-of-3 that holds none of your keys, so the funds really leave.")},
    {"kind": "contradiction_multisig_unclaimed", "script_type": "P2WSH", "family": "Multisig (2-of-3)",
     "label": "Change hidden behind relabeled fingerprints",
     "screen": _D5_ATTACK_SCREEN, "expected": _D5_REFUSE,
     "blurb": ("It really is your own change output, but every derivation fingerprint is "
               "relabeled to a stranger's, hiding that it belongs to you.")},
    {"kind": "surplus_singlesig", "script_type": "P2WPKH", "family": "Native SegWit",
     "label": "Surplus derivation paths (single-key)",
     "screen": _D5_PROBLEM_SCREEN, "expected": _D5_MALFORMED,
     "blurb": ("It is a valid change output back to this seed, but it lists two "
               "derivation paths for a single-key script.")},
    {"kind": "surplus_multisig", "script_type": "P2WSH", "family": "Multisig (2-of-3)",
     "label": "Surplus derivation paths (multisig)",
     "screen": _D5_PROBLEM_SCREEN, "expected": _D5_MALFORMED,
     "blurb": ("It is a valid 2-of-3 change output, but it lists four derivation paths "
               "for a script that has only three keys.")},
    {"kind": "surplus_taproot", "script_type": "P2TR", "family": "Taproot",
     "label": "Surplus internal keys (taproot)",
     "screen": _D5_PROBLEM_SCREEN, "expected": _D5_MALFORMED,
     "blurb": ("It is a valid taproot change output, but it claims two internal keys "
               "where there can be only one.")},
    {"kind": "mixed_types", "script_type": "P2WPKH", "family": "Native SegWit",
     "label": "Mixed derivation path types",
     "screen": _D5_PROBLEM_SCREEN, "expected": _D5_MALFORMED,
     "blurb": ("It is a valid change output, but its scope lists derivation paths in "
               "both the ecdsa and taproot maps, which no script type can use.")},
]


def _make_d5(d):
    info = script_types.get(d["script_type"])
    base_wallet = WALLET_FOR_SCRIPT_TYPE[d["script_type"]]
    slug = d["kind"].replace("_", "-")
    return Scenario(
        id=f"test-1032-{slug}", wallet=base_wallet, script_type=d["script_type"],
        num_inputs=DEFAULT_NUM_INPUTS, output_shape="change", network="main",
        title=f"⚠ {d['label']} ({d['family']})", blurb=d["blurb"], is_default=False,
        tags=["test", d["label"], info.label],
        pr="1032", attack=d["kind"], load_seed=TEST_VICTIM_SEED,
        expected=d["expected"], expected_screen=d["screen"],
    )


def test_scenarios() -> list:
    """Adversarial / malformed transactions for exercising the hardening PRs on device."""
    out = []
    # PR #1013: both forgeries across the three families, plus one wrong-seed case
    # (not script-type-sensitive, so native segwit stands in for it).
    for attack in ("fake_change", "bad_input"):
        for script_type, family in TEST_SCRIPT_FAMILIES:
            out.append(_make_test(attack, script_type, family))
    out.append(_make_test("wrong_seed", "P2WPKH", "Native SegWit"))
    # PR #1032 / D5: output-ownership contradictions and malformed derivation data.
    out.extend(_make_d5(d) for d in _D5_DEFS)
    return out
