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
    pr: str = None                     # "1013" | "1032" | "1041" | "1042" | "1042b"
    attack: str = None
    load_seed: str = None
    expected: str = None
    expected_screen: str = None
    # What the device does with this psbt, so the banner can phrase it correctly:
    #   refuse  aborts to a warning screen (expected_screen names it)
    #   error   aborts to the generic error screen (unsupported input)
    #   spend   parses fine; the output is shown as a payment out, not change
    #   change  parses fine; the output is shown as change (a documented limit)
    #   display parses fine; the point is what the device puts on screen
    outcome: str = None


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
    {
        "pr": "1041",
        "label": "PR #1041: outputs exceed inputs",
        "url": "https://github.com/seedsigner/seedsigner/pull/1041",
        "blurb": ("A transaction cannot pay out more than it takes in. embit computes "
                  "the fee as inputs minus outputs and does not check the sign, so "
                  "without this the device reviews the transaction quoting a negative "
                  "fee."),
    },
    {
        "pr": "1042",
        "label": "PR #1042: OP_RETURN push encodings",
        "url": "https://github.com/seedsigner/seedsigner/pull/1042",
        "blurb": ("Honest transactions, no forgery. Each carries an OP_RETURN encoded a "
                  "different legal way. The payload is read at a fixed offset that only "
                  "OP_PUSHDATA1 satisfies, so every other encoding loses or gains a byte "
                  "at the front. Fixes issue #963."),
    },
    {
        # TODO: swap the label and url for the follow-up PR's number once it is opened.
        "pr": "1042b",
        "label": "OP_RETURN display and accounting (follow-up to #1042)",
        "url": "https://github.com/seedsigner/seedsigner/pull/1042",
        "blurb": ("What the device does with an OP_RETURN once it has parsed it. Only the "
                  "last of several survives the parse, any sats attached to one are added "
                  "to no total so the amounts on screen stop reconciling against the "
                  "inputs, and the payload is drawn with no bound on its size."),
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
        expected=d["expected"], expected_screen=d["expected_screen"], outcome="refuse",
    )


# PR #1032: output ownership. Each entry pins the forgery builder
# (common/attack_psbt.build_d5_psbt), the wallet it runs on, and the expected
# outcome. Most refuse to a warning screen; some parse fine but classify the
# output (spend, or change for one documented limitation). `screen` is the label
# a tester looks for; `outcome` tells the banner how to phrase it.
_D5_ATTACK_SCREEN = "Suspicious Transaction / Likely an Attack!"
_D5_PROBLEM_SCREEN = "Transaction Problem"
_D5_ERROR_SCREEN = "Generic error screen"
_D5_SPEND_RESULT = "Shown as a payment, not change"
_D5_CHANGE_RESULT = "Shown as change (a limitation)"

_D5_REFUSE = "Device should refuse it as likely an attack."
_D5_MALFORMED = "Device should reject it as a malformed transaction."
_D5_ERROR = "Device should abort to the generic error screen."
_D5_SPEND = "Device should show the output as a payment out, not change."
_D5_CHANGE = "Without a descriptor the device shows it as change; load the descriptor to catch it."

# Icon by outcome: a warning triangle where the device stops, an arrow where the
# output leaves as a spend, an info mark where it is (mis)counted as change.
_D5_ICON = {"refuse": "⚠", "error": "⚠", "spend": "→", "change": "ℹ"}

_D5_DEFS = [
    # --- refusals: ownership contradictions (attack warning) -----------------
    {"kind": "contradiction_singlesig", "script_type": "P2WPKH", "family": "Native SegWit",
     "label": "Fake change pays another key", "outcome": "refuse",
     "screen": _D5_ATTACK_SCREEN, "expected": _D5_REFUSE,
     "blurb": ("It is labeled as change back to this seed, but the scriptPubKey pays a "
               "key you do not own, so the funds really leave.")},
    {"kind": "contradiction_pays_us_claims_other", "script_type": "P2WPKH", "family": "Native SegWit",
     "label": "Change claims a stranger's key", "outcome": "refuse",
     "screen": _D5_ATTACK_SCREEN, "expected": _D5_REFUSE,
     "blurb": ("It really is your change and the script pays your key, but the derivation "
               "entry claims a stranger's fingerprint. Any wrong ownership claim is refused.")},
    {"kind": "contradiction_taproot_claims_other", "script_type": "P2TR", "family": "Taproot",
     "label": "Taproot change claims a stranger", "outcome": "refuse",
     "screen": _D5_ATTACK_SCREEN, "expected": _D5_REFUSE,
     "blurb": ("The taproot version of the above: the output pays your internal key, but "
               "the entry claims a stranger's fingerprint.")},
    {"kind": "contradiction_multisig", "script_type": "P2WSH", "family": "Multisig (2-of-3)",
     "label": "Fake change to a foreign multisig", "outcome": "refuse",
     "screen": _D5_ATTACK_SCREEN, "expected": _D5_REFUSE,
     "blurb": ("It is labeled as change back to this seed, but it pays an attacker's "
               "2-of-3 that holds none of your keys, so the funds really leave.")},
    {"kind": "contradiction_multisig_unclaimed", "script_type": "P2WSH", "family": "Multisig (2-of-3)",
     "label": "Change hidden behind relabeled fingerprints", "outcome": "refuse",
     "screen": _D5_ATTACK_SCREEN, "expected": _D5_REFUSE,
     "blurb": ("It really is your own change output, but every derivation fingerprint is "
               "relabeled to a stranger's, hiding that it belongs to you.")},
    {"kind": "contradiction_multisig_decoy_first", "script_type": "P2WSH", "family": "Multisig (2-of-3)",
     "label": "Decoy key listed first", "outcome": "refuse",
     "screen": _D5_ATTACK_SCREEN, "expected": _D5_REFUSE,
     "blurb": ("A genuine multisig change output, plus a decoy entry, a key you own that "
               "is not in the script, listed first. The recorded key is not in the "
               "committed script.")},
    {"kind": "contradiction_multisig_bad_script", "script_type": "P2WSH", "family": "Multisig (2-of-3)",
     "label": "Supplied script is not the committed one", "outcome": "refuse",
     "screen": _D5_ATTACK_SCREEN, "expected": _D5_REFUSE,
     "blurb": ("Only the scriptPubKey is repointed at a stranger's 2-of-3; the supplied "
               "witness script and every entry are kept, so the script no longer hashes "
               "to what the output commits to.")},

    # --- refusals: malformed derivation bookkeeping ("Transaction Problem") ---
    {"kind": "surplus_singlesig", "script_type": "P2WPKH", "family": "Native SegWit",
     "label": "Surplus derivation paths (single-key)", "outcome": "refuse",
     "screen": _D5_PROBLEM_SCREEN, "expected": _D5_MALFORMED,
     "blurb": ("It is a valid change output back to this seed, but it lists two "
               "derivation paths for a single-key script.")},
    {"kind": "surplus_multisig", "script_type": "P2WSH", "family": "Multisig (2-of-3)",
     "label": "Surplus derivation paths (multisig)", "outcome": "refuse",
     "screen": _D5_PROBLEM_SCREEN, "expected": _D5_MALFORMED,
     "blurb": ("It is a valid 2-of-3 change output, but it lists four derivation paths "
               "for a script that has only three keys.")},
    {"kind": "surplus_taproot", "script_type": "P2TR", "family": "Taproot",
     "label": "Surplus internal keys (taproot)", "outcome": "refuse",
     "screen": _D5_PROBLEM_SCREEN, "expected": _D5_MALFORMED,
     "blurb": ("It is a valid taproot change output, but it claims two internal keys "
               "where there can be only one.")},
    {"kind": "mixed_types", "script_type": "P2WPKH", "family": "Native SegWit",
     "label": "Mixed derivation path types", "outcome": "refuse",
     "screen": _D5_PROBLEM_SCREEN, "expected": _D5_MALFORMED,
     "blurb": ("It is a valid change output, but its scope lists derivation paths in "
               "both the ecdsa and taproot maps, which no script type can use.")},

    # --- aborts to the generic error screen ----------------------------------
    {"kind": "unsupported_script_type", "script_type": "P2WPKH", "family": "bare p2pk",
     "label": "Unsupported script type", "outcome": "error",
     "screen": _D5_ERROR_SCREEN, "expected": _D5_ERROR,
     "blurb": ("The inputs and change use bare pay-to-pubkey, which the device does not "
               "support. It aborts rather than guess. No dedicated screen for this yet.")},

    # --- accepted, output correctly shown as a spend -------------------------
    {"kind": "multisig_external_spend", "script_type": "P2WSH", "family": "Multisig (2-of-3)",
     "label": "Payment to another multisig", "outcome": "spend",
     "screen": _D5_SPEND_RESULT, "expected": _D5_SPEND,
     "blurb": ("An honest payment to a different multisig, fully annotated with that "
               "wallet's own keys. None are yours, so it is a plain external spend.")},
    {"kind": "multisig_change_no_paths", "script_type": "P2WSH", "family": "Multisig (2-of-3)",
     "label": "Change with no derivation paths", "outcome": "spend",
     "screen": _D5_SPEND_RESULT, "expected": _D5_SPEND,
     "blurb": ("Your real multisig change, with the derivation entries omitted (BIP-174 "
               "allows it). With no path to derive, the device cannot see your key in "
               "the script, so it over-reports the output as leaving.")},
    {"kind": "multisig_change_no_script", "script_type": "P2WSH", "family": "Multisig (2-of-3)",
     "label": "Change with no script", "outcome": "spend",
     "screen": _D5_SPEND_RESULT, "expected": _D5_SPEND,
     "blurb": ("Your real multisig change, with the witness script omitted. With no "
               "script there is no m-of-n to match, so the output is shown as a spend.")},
    {"kind": "taproot_scripttree_internal", "script_type": "P2TR", "family": "Taproot",
     "label": "Taproot change with a script tree", "outcome": "spend",
     "screen": _D5_SPEND_RESULT, "expected": _D5_SPEND,
     "blurb": ("Taproot change you own through the key path, but the address commits to a "
               "script tree the device does not yet parse, so it cannot confirm the "
               "output and shows it as a spend.")},
    {"kind": "taproot_scripttree_leaf", "script_type": "P2TR", "family": "Taproot",
     "label": "Taproot script-path change", "outcome": "spend",
     "screen": _D5_SPEND_RESULT, "expected": _D5_SPEND,
     "blurb": ("A script-path-only taproot address whose leaf holds your key. Same "
               "limitation: the tree is unparsed, so the output is shown as a spend.")},
    {"kind": "diff_quorum_xpubs", "script_type": "P2WSH", "family": "Multisig (2-of-3)",
     "label": "Different quorum, global xpubs", "outcome": "spend",
     "screen": _D5_SPEND_RESULT, "expected": _D5_SPEND,
     "blurb": ("The output pays a 2-of-3 that holds your key but swaps one cosigner for "
               "an outsider. With the wallet's global xpubs present, the mismatch is "
               "caught and the output is shown as a spend.")},
    {"kind": "diff_quorum_outsider_xpub", "script_type": "P2WSH", "family": "Multisig (2-of-3)",
     "label": "Different quorum, outsider xpub supplied", "outcome": "spend",
     "screen": _D5_SPEND_RESULT, "expected": _D5_SPEND,
     "blurb": ("The same different-quorum output, with the outsider's xpub also in the "
               "global xpubs. Every key resolves, but the cosigner set still differs, so "
               "it is shown as a spend.")},

    # --- accepted, shown as change (documented limitation) -------------------
    {"kind": "diff_quorum_no_xpubs", "script_type": "P2WSH", "family": "Multisig (2-of-3)",
     "label": "Different quorum, no global xpubs", "outcome": "change",
     "screen": _D5_CHANGE_RESULT, "expected": _D5_CHANGE,
     "blurb": ("The same different-quorum output, but with no global xpubs. Without them "
               "the device cannot compare cosigners, so the matching shape lets it be "
               "shown as your change though it pays a different wallet. Load the "
               "descriptor to catch it.")},
]


def _make_d5(d):
    info = script_types.get(d["script_type"])
    base_wallet = WALLET_FOR_SCRIPT_TYPE[d["script_type"]]
    slug = d["kind"].replace("_", "-")
    return Scenario(
        id=f"test-1032-{slug}", wallet=base_wallet, script_type=d["script_type"],
        num_inputs=DEFAULT_NUM_INPUTS, output_shape="change", network="main",
        title=f"{_D5_ICON[d['outcome']]} {d['label']} ({d['family']})",
        blurb=d["blurb"], is_default=False,
        tags=["test", d["label"], info.label],
        pr="1032", attack=d["kind"], load_seed=TEST_VICTIM_SEED,
        expected=d["expected"], expected_screen=d["screen"], outcome=d["outcome"],
    )


# --- negative fee ------------------------------------------------------------
#
# Not a forgery: every key claim in this psbt is honest and the change output is
# genuinely ours. Only the arithmetic is impossible, the outputs move more than
# the inputs hold. The check is a single comparison on the parsed fee, so it is
# script-type agnostic and one family is enough to exercise it.

_NEGATIVE_FEE_SCRIPT_TYPE = "P2WPKH"


def _make_negative_fee() -> Scenario:
    info = script_types.get(_NEGATIVE_FEE_SCRIPT_TYPE)
    return Scenario(
        id="test-1041-negative-fee",
        wallet=WALLET_FOR_SCRIPT_TYPE[_NEGATIVE_FEE_SCRIPT_TYPE],
        script_type=_NEGATIVE_FEE_SCRIPT_TYPE,
        num_inputs=DEFAULT_NUM_INPUTS, output_shape="change", network="main",
        title=f"\u26a0 Outputs exceed inputs ({info.label})",
        blurb=("An ordinary change transaction with its change output inflated past "
               "what the inputs hold, so the fee comes out negative. Nothing about "
               "the keys is false; the transaction is simply impossible and no "
               "network would relay it."),
        is_default=False,
        tags=["test", "Negative fee", info.label],
        pr="1041", attack="negative_fee", load_seed=TEST_VICTIM_SEED,
        expected="Device should reject it as a malformed transaction.",
        expected_screen="Transaction Problem", outcome="refuse",
    )


# --- OP_RETURN push encodings / PR #1042 --------------------------------------------------
#
# Nothing here is forged. These are transactions a coordinator legitimately
# produces; what varies is how the OP_RETURN output is encoded and how much it
# carries. The builder is common/op_return_psbt.py, which documents each case.
#
# Single-sig native segwit throughout: OP_RETURN handling is script-type
# agnostic, and the single-sig flow keeps the tester on the screen that matters
# instead of walking a descriptor step first.

_OP_RETURN_SCRIPT_TYPE = "P2WPKH"

_OP_RETURN_SCREEN = "OP_RETURN"

# The push-encoding cases, for #1042. Ordered the way a tester should work through
# them: the two that show the mis-slice most plainly first, then the remaining
# encodings, then the control that must look identical either way, then the empty edge
# case. The cases for the display and accounting follow-up are in _OP_RETURN_DISPLAY_DEFS
# below; they fail on defects #1042 does not touch, so mixing them in would read as
# failures against it.
_OP_RETURN_DEFS = [
    {"kind": "direct_push", "label": "Payload loses its first byte",
     "expected": "Device should show the payload with its leading C intact.",
     "blurb": ("A 40 byte message, pushed the way Bitcoin Core encodes one: the push opcode "
               "is itself the length, so the prefix is two bytes rather than three. The "
               "device reads it at a fixed three and shows the message a byte short.")},

    {"kind": "binary", "label": "Binary payload, shown as hex",
     "expected": "Device should show hex starting 8081 82, not 8182 83.",
     "blurb": ("75 bytes that are not text, so the device shows them as hex. The payload "
               "starts 80 81 82 and the device shows it starting 81 82 83, a byte in, with "
               "nothing about a wall of hex to say so. 75 bytes is the largest a direct "
               "push can carry.")},

    {"kind": "multi_push", "label": "Two pushes in one script",
     "expected": "Device should show both pushes with no opcode left between them.",
     "blurb": ("One OP_RETURN script holding two pushes rather than one. Unusual but legal; "
               "the data the transaction commits to is both of them.")},

    {"kind": "pushdata2", "label": "300 bytes needs a two-byte length",
     "expected": "Device should show the payload with no stray leading byte.",
     "blurb": ("300 bytes, which needs a two byte length on the push. The device reads past "
               "only one of them, leaving the other stuck on the front of the payload, and "
               "draws the rest off the bottom of the screen.")},

    {"kind": "pushdata1", "label": "80 bytes, the old relay ceiling",
     "expected": "Device should look exactly as it did before the fix.",
     "blurb": ("80 bytes pushed with OP_PUSHDATA1, the encoding the device already reads "
               "correctly, and the largest payload relay policy allowed before Bitcoin Core "
               "v30. It fills the screen down to the button.")},

    {"kind": "empty", "label": "Bare OP_RETURN, no payload",
     "expected": "Device should show the screen, reporting no data.",
     "blurb": ("An OP_RETURN output that pushes nothing at all. The output is still there "
               "and still unspendable.")},
]


# --- OP_RETURN display and accounting / follow-up to #1042 -------------------
#
# These parse correctly even with the push-opcode fix in place. What they exercise is
# everything after the parse: how many OP_RETURNs survive it, whether their value is
# counted, and whether the screen can show a payload of any size.

_OP_RETURN_DISPLAY_DEFS = [
    {"kind": "two_outputs", "label": "Two OP_RETURN outputs",
     "expected": "Device should show both payloads, in output order.",
     "blurb": ("Two OP_RETURN outputs in one transaction. Several have always been "
               "consensus-valid, and Bitcoin Core v30 dropped the one-per-transaction relay "
               "limit. The device shows only the second of them.")},

    {"kind": "many_outputs", "label": "Five outputs, a burn hidden among them",
     "expected": "Device should show all five, and warn on the elided overview row.",
     "blurb": ("Five OP_RETURN outputs, the middle one destroying 10,000 sats. Past a "
               "handful the overview's flow diagram elides the middle rows into an ellipsis, "
               "which is where this burn falls. The device shows only the last of the five.")},

    {"kind": "nonzero_value", "label": "Sats burned on the OP_RETURN",
     "expected": "Device should show the burned amount and balance the totals.",
     "blurb": ("The OP_RETURN output carries 10,000 sats, which the transaction destroys. "
               "The device adds that to neither the spend nor the change total, so the amount "
               "never appears and inputs = spend + change + fee no longer balances.")},

    {"kind": "max_pages", "label": "Paged to the limit, nothing dropped",
     "expected": "Device should page to the end with no truncation warning.",
     "blurb": ("800 bytes, exactly as much as the paged screen will show. One byte more and "
               "the device would have to say it could not show all of it.")},

    {"kind": "large_burn", "label": "Too large to show, and burning sats",
     "expected": "Device should warn on every page and say what it could not show.",
     "blurb": ("4 KB of payload and 10,000 sats destroyed, on the same output. The device "
               "has to warn about the burn on every page of it while also saying how much of "
               "the payload it could not show.")},

    {"kind": "kitchen_sink", "label": "Everything at once",
     "expected": "Device should show all six outputs and balance the totals.",
     "blurb": ("One transaction carrying six OP_RETURN outputs: a readable payload, a binary "
               "one shown as hex, one long enough to page, one too large to page through, two "
               "pushes in a single script, and a bare OP_RETURN that also destroys sats.")},
]


def _make_op_return(d, pr: str = "1042") -> Scenario:
    info = script_types.get(_OP_RETURN_SCRIPT_TYPE)
    return Scenario(
        id=f"test-{pr}-{d['kind'].replace('_', '-')}",
        wallet=WALLET_FOR_SCRIPT_TYPE[_OP_RETURN_SCRIPT_TYPE],
        script_type=_OP_RETURN_SCRIPT_TYPE,
        num_inputs=DEFAULT_NUM_INPUTS, output_shape="change", network="main",
        title=f"\u2139 {d['label']}",
        blurb=d["blurb"], is_default=False,
        tags=["test", "OP_RETURN", info.label],
        pr=pr, attack=d["kind"], load_seed=TEST_VICTIM_SEED,
        expected=d["expected"], expected_screen=_OP_RETURN_SCREEN, outcome="display",
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
    # Outputs that exceed the inputs: one case, the check does not vary by type.
    out.append(_make_negative_fee())
    # PR #1042: OP_RETURN push encodings.
    out.extend(_make_op_return(d) for d in _OP_RETURN_DEFS)
    # Its follow-up: what the device does with an OP_RETURN once it has parsed it.
    out.extend(_make_op_return(d, pr="1042b") for d in _OP_RETURN_DISPLAY_DEFS)
    return out
