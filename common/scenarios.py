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
from common.attack_psbt import (NEGATIVE_FEE_OVERRUN, PR1047_CASES,
                                PR995_CLAIMED_INPUT_VALUE, PR995_REAL_INPUT_VALUE,
                                PR995_TAMPER_DELTA)
from common.psbt import FEE, IN_VALUE

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
    pr: str = None                     # "1013" | "1032" | "1044" | "1040" | "1046"
                                       # | "1047" | "995" | "1041" | "1060" | "1073"
                                       # | "949" | "dev"
    attack: str = None
    load_seed: str = None
    expected: str = None
    expected_screen: str = None
    # What the device does with this psbt, so the banner can phrase it correctly:
    #   refuse  aborts to a warning screen (expected_screen names it)
    #   warn    shows a warning screen (expected_screen names it), then lets the user
    #           continue to sign
    #   error   aborts to the generic error screen (unsupported input)
    #   spend   parses fine; the output is shown as a payment out, not change
    #   change  parses fine; the output is shown as change (correctly, or as a
    #           documented limit; expected_screen says which)
    outcome: str = None
    # Rendered under the site's "What's in this transaction?" table, only where that
    # table gets a number wrong. It reads the psbt's own fields, so for PR #995's
    # amount lies it makes the same mistake a device without the fix makes. The
    # blurb, shown in the banner above the QR, stays about the device.
    summary_note: str = None


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
        "pr": "1044",
        "label": "PR #1044: every claim held to the script",
        "url": "https://github.com/seedsigner/seedsigner/pull/1044",
        "blurb": ("A multisig output may claim this seed more than once. Every claim is "
                  "now held to the committed script, so a decoy key of ours is refused "
                  "wherever the psbt lists it, not only when it is listed first."),
    },
    {
        "pr": "1040",
        "label": "PR #1040: fingerprint consistency",
        "url": "https://github.com/seedsigner/seedsigner/pull/1040",
        "blurb": ("A key's derivation entry and the global xpub that derives it both name "
                  "a fingerprint. When they disagree the psbt contradicts itself and is "
                  "refused; an all-zero fingerprint is a missing value, not a second answer."),
    },
    {
        "pr": "1046",
        "label": "PR #1046: nested change with no redeem script",
        "url": "https://github.com/seedsigner/seedsigner/pull/1046",
        "blurb": ("A nested single sig output may leave out its redeem script, which "
                  "makes it look like plain p2sh and drops it out of the change check "
                  "entirely. Such an output is now rebuilt from this seed, whatever the "
                  "psbt claims about it, and either counted as change or refused."),
    },
    {
        "pr": "1047",
        "label": "PR #1047: input scripts",
        "url": "https://github.com/seedsigner/seedsigner/pull/1047",
        "blurb": ("A p2sh or p2wsh input commits to a script by its hash, so the psbt has "
                  "to supply that script and it has to hash correctly. An input carrying "
                  "a missing, wrong, or extra script is refused, whoever the input "
                  "belongs to."),
    },
    {
        "pr": "995",
        "label": "PR #995: input amounts",
        "url": "https://github.com/seedsigner/seedsigner/pull/995",
        "blurb": ("Fee is inputs minus outputs, so an input amount the device cannot prove "
                  "lets a coordinator display any fee it likes. Legacy inputs are the worst "
                  "case: their signatures commit no amount, so the lie survives signing and "
                  "the difference burns as miner fee."),
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
        "pr": "1060",
        "label": "PR #1060: input claims",
        "url": "https://github.com/seedsigner/seedsigner/pull/1060",
        "blurb": ("Anyone holding the account xpub can derive this seed's keys and write a "
                  "true claim of ours where it does not belong. A key of ours on an input "
                  "must now be one the input's script really uses. Milder findings wait "
                  "until the outputs are read, so an attack there is the one reported."),
    },
    {
        "pr": "1073",
        "label": "PR #1073: change paths",
        "url": "https://github.com/seedsigner/seedsigner/pull/1073",
        "blurb": ("Proving a change output pays this seed does not prove your wallet will "
                  "ever look for it. Change must now come back to the wallet the inputs "
                  "spend from, on its receive or change branch, at an ordinary address "
                  "index. Change far past the inputs' address indexes gets a warning."),
    },
    {
        "pr": "949",
        "label": "PR #949: silent payments",
        "url": "https://github.com/SeedSigner/seedsigner/pull/949",
        "blurb": ("Sending to and spending from silent payment addresses (BIP352, BIP375, "
                  "BIP376). The device works out every silent payment output itself from "
                  "this seed's input keys, and holds anything the psbt already claims to "
                  "that. Turn on Settings > BIP-352 silent payments first, or each of these "
                  "stops at Option Disabled."),
    },
    {
        "pr": "dev",
        "label": "dev: current behavior",
        "url": "https://github.com/seedsigner/seedsigner/tree/dev",
        "blurb": ("Not tied to a hardening PR. These record what the current dev build "
                  "does with a psbt, so what they document can change as PRs land."),
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


# PR #1032, #1044, and #1040: one def list per PR. Each entry pins the forgery
# builder (common/attack_psbt.build_test_psbt), the wallet it runs on, and the
# expected outcome. Most refuse to a warning screen; some parse fine but classify
# the output (spend, or change: correctly, or for a documented limitation).
# `screen` is the label a tester looks for; `outcome` tells the banner how to
# phrase it.
_ATTACK_SCREEN = "Suspicious Transaction / Likely an Attack!"
_PROBLEM_SCREEN = "Transaction Problem"
_ERROR_SCREEN = "Generic error screen"
_CANT_SIGN_SCREEN = "Seed Can't Sign"
_NOT_YET_SCREEN = "Not Yet Implemented"
_UNSAFE_PATH_SCREEN = "Suspicious Transaction / Unsafe Derivation Path"
_DISTANT_SCREEN = "Distant Address"
_SPEND_RESULT = "Shown as a payment, not change"
_CHANGE_RESULT = "Shown as change (a limitation)"
_CHANGE_OK_RESULT = "Shown as change (correct)"

_REFUSE = "Device should refuse it as likely an attack."
_MALFORMED = "Device should reject it as a malformed transaction."
_ERROR = "Device should abort to the generic error screen."
_SPEND = "Device should show the output as a payment out, not change."
_CHANGE = "Without a descriptor the device shows it as change; load the descriptor to catch it."
_CHANGE_OK = "Device should parse it and show the output as change."
_CHANGE_NO_XPUBS = "With no global xpubs there is nothing to compare, so the device shows it as change."
_UNVERIFIED = "Device should discard it: the input amounts cannot be confirmed."
_CANT_SIGN = "Device should say this seed can't sign it."
_UNSUPPORTED = "Device should refuse it as not yet supported."
_MIXED_WALLETS = "Device should discard it: it cannot tell which of the inputs' wallets is real."

# `expected` serves two readers: whoever maintains these definitions, and the
# tester holding the device. Most of them only restate `outcome` and the screen
# name, which the banner already prints, and on-screen text here is deliberately
# minimal, so those are not shipped to the site. An expectation reaches the page
# only when it says something a tester cannot read off the screen title: that a
# refusal is a known gap rather than the right answer, or what to load to catch
# what the device just missed.
_OBVIOUS_EXPECTATIONS = frozenset({
    _REFUSE, _MALFORMED, _ERROR, _SPEND, _CHANGE_OK, _UNVERIFIED, _CANT_SIGN,
    _UNSUPPORTED, _MIXED_WALLETS,
})


def tester_note(scenario) -> str:
    """The scenario's expectation, or None where it only restates the screen."""
    if scenario.expected in _OBVIOUS_EXPECTATIONS:
        return None
    return scenario.expected

# Icon by outcome: a warning triangle where the device stops or warns, an arrow where
# the output leaves as a spend, an info mark where it is (mis)counted as change.
_ICON = {"refuse": "⚠", "warn": "⚠", "error": "⚠", "spend": "→", "change": "ℹ"}

_PR1032_DEFS = [
    # --- refusals: ownership contradictions (attack warning) -----------------
    {"kind": "contradiction_singlesig", "script_type": "P2WPKH", "family": "Native SegWit",
     "label": "Fake change pays another key", "outcome": "refuse",
     "screen": _ATTACK_SCREEN, "expected": _REFUSE,
     "blurb": ("It is labeled as change back to this seed, but the scriptPubKey pays a "
               "key you do not own, so the funds really leave.")},
    {"kind": "contradiction_pays_us_claims_other", "script_type": "P2WPKH", "family": "Native SegWit",
     "label": "Change claims a stranger's key", "outcome": "refuse",
     "screen": _ATTACK_SCREEN, "expected": _REFUSE,
     "blurb": ("It really is your change and the script pays your key, but the derivation "
               "entry claims a stranger's fingerprint. Any wrong ownership claim is refused.")},
    {"kind": "contradiction_taproot_claims_other", "script_type": "P2TR", "family": "Taproot",
     "label": "Taproot change claims a stranger", "outcome": "refuse",
     "screen": _ATTACK_SCREEN, "expected": _REFUSE,
     "blurb": ("It really is your taproot change and the output pays your internal key, "
               "but the derivation entry claims a stranger's fingerprint. Any wrong "
               "ownership claim is refused.")},
    {"kind": "contradiction_multisig", "script_type": "P2WSH", "family": "Multisig (2-of-3)",
     "label": "Fake change to a foreign multisig", "outcome": "refuse",
     "screen": _ATTACK_SCREEN, "expected": _REFUSE,
     "blurb": ("It is labeled as change back to this seed, but it pays an attacker's "
               "2-of-3 that holds none of your keys, so the funds really leave.")},
    {"kind": "contradiction_multisig_unclaimed", "script_type": "P2WSH", "family": "Multisig (2-of-3)",
     "label": "Change hidden behind relabeled fingerprints", "outcome": "refuse",
     "screen": _ATTACK_SCREEN, "expected": _REFUSE,
     "blurb": ("It really is your own change output, but every derivation fingerprint is "
               "relabeled to a stranger's, hiding that it belongs to you.")},
    {"kind": "contradiction_multisig_decoy_first", "script_type": "P2WSH", "family": "Multisig (2-of-3)",
     "label": "Decoy key listed first", "outcome": "refuse",
     "screen": _ATTACK_SCREEN, "expected": _REFUSE,
     "blurb": ("A genuine multisig change output, plus a decoy entry, a key you own that "
               "is not in the script, listed first. The recorded key is not in the "
               "committed script.")},
    {"kind": "contradiction_multisig_bad_script", "script_type": "P2WSH", "family": "Multisig (2-of-3)",
     "label": "Supplied script is not the committed one", "outcome": "refuse",
     "screen": _ATTACK_SCREEN, "expected": _REFUSE,
     "blurb": ("Only the scriptPubKey is repointed at a stranger's 2-of-3; the supplied "
               "witness script and every entry are kept, so the script no longer hashes "
               "to what the output commits to.")},

    # --- refusals: malformed derivation bookkeeping ("Transaction Problem") ---
    {"kind": "surplus_singlesig", "script_type": "P2WPKH", "family": "Native SegWit",
     "label": "Surplus derivation paths (single-key)", "outcome": "refuse",
     "screen": _PROBLEM_SCREEN, "expected": _MALFORMED,
     "blurb": ("It is a valid change output back to this seed, but it lists two "
               "derivation paths for a single-key script.")},
    {"kind": "surplus_multisig", "script_type": "P2WSH", "family": "Multisig (2-of-3)",
     "label": "Surplus derivation paths (multisig)", "outcome": "refuse",
     "screen": _PROBLEM_SCREEN, "expected": _MALFORMED,
     "blurb": ("It is a valid 2-of-3 change output, but it lists four derivation paths "
               "for a script that has only three keys.")},
    {"kind": "surplus_taproot", "script_type": "P2TR", "family": "Taproot",
     "label": "Surplus internal keys (taproot)", "outcome": "refuse",
     "screen": _PROBLEM_SCREEN, "expected": _MALFORMED,
     "blurb": ("It is a valid taproot change output, but it claims two internal keys "
               "where there can be only one.")},
    {"kind": "mixed_types", "script_type": "P2WPKH", "family": "Native SegWit",
     "label": "Mixed derivation path types", "outcome": "refuse",
     "screen": _PROBLEM_SCREEN, "expected": _MALFORMED,
     "blurb": ("It is a valid change output, but its scope lists derivation paths in "
               "both the ecdsa and taproot maps, which no script type can use.")},

    # --- accepted, output correctly shown as a spend -------------------------
    {"kind": "multisig_external_spend", "script_type": "P2WSH", "family": "Multisig (2-of-3)",
     "label": "Payment to another multisig", "outcome": "spend",
     "screen": _SPEND_RESULT, "expected": _SPEND,
     "blurb": ("An honest payment to a different multisig, fully annotated with that "
               "wallet's own keys. None are yours, so it is a plain external spend.")},
    {"kind": "multisig_change_no_paths", "script_type": "P2WSH", "family": "Multisig (2-of-3)",
     "label": "Change with no derivation paths", "outcome": "spend",
     "screen": _SPEND_RESULT, "expected": _SPEND,
     "blurb": ("Your real multisig change, with the derivation entries omitted (BIP-174 "
               "allows it). With no path to derive, the device cannot see your key in "
               "the script, so it over-reports the output as leaving.")},
    {"kind": "multisig_change_no_script", "script_type": "P2WSH", "family": "Multisig (2-of-3)",
     "label": "Change with no script", "outcome": "spend",
     "screen": _SPEND_RESULT, "expected": _SPEND,
     "blurb": ("Your real multisig change, with the witness script omitted. With no "
               "script there is no m-of-n to match, so the output is shown as a spend.")},
    {"kind": "taproot_scripttree_internal", "script_type": "P2TR", "family": "Taproot",
     "label": "Taproot change with a script tree", "outcome": "spend",
     "screen": _SPEND_RESULT, "expected": _SPEND,
     "blurb": ("Taproot change you own through the key path, but the address commits to a "
               "script tree the device does not yet parse, so it cannot confirm the "
               "output and shows it as a spend.")},
    {"kind": "taproot_scripttree_leaf", "script_type": "P2TR", "family": "Taproot",
     "label": "Taproot script-path change", "outcome": "spend",
     "screen": _SPEND_RESULT, "expected": _SPEND,
     "blurb": ("A script-path-only taproot address whose leaf holds your key. The "
               "device does not yet parse script trees, so it cannot confirm the output "
               "and shows it as a spend.")},
    {"kind": "diff_quorum_xpubs", "script_type": "P2WSH", "family": "Multisig (2-of-3)",
     "label": "Different quorum, global xpubs", "outcome": "spend",
     "screen": _SPEND_RESULT, "expected": _SPEND,
     "blurb": ("The output pays a 2-of-3 that holds your key but swaps one cosigner for "
               "an outsider. With the wallet's global xpubs present, the mismatch is "
               "caught and the output is shown as a spend.")},
    {"kind": "diff_quorum_outsider_xpub", "script_type": "P2WSH", "family": "Multisig (2-of-3)",
     "label": "Different quorum, outsider xpub supplied", "outcome": "spend",
     "screen": _SPEND_RESULT, "expected": _SPEND,
     "blurb": ("The output pays a 2-of-3 that holds your key but swaps one cosigner for "
               "an outsider, and the outsider's xpub is in the global xpubs too. Every "
               "key resolves, but the cosigner set still differs, so it is shown as a "
               "spend.")},

    # --- accepted, shown as change (documented limitation) -------------------
    {"kind": "diff_quorum_no_xpubs", "script_type": "P2WSH", "family": "Multisig (2-of-3)",
     "label": "Different quorum, no global xpubs", "outcome": "change",
     "screen": _CHANGE_RESULT, "expected": _CHANGE,
     "blurb": ("The output pays a 2-of-3 that holds your key but swaps one cosigner for "
               "an outsider, and the psbt carries no global xpubs. Without them the "
               "device cannot compare cosigners, so the matching shape lets it be "
               "shown as your change though it pays a different wallet. Load the "
               "descriptor to catch it.")},
]


# PR #1044: the PR's own test matrix, a decoy entry (a key this seed owns that is
# not in the output's script) in each placement, plus the stranger-padding case
# that still lands on the surplus count. Decoy-first and stranger-padding are
# unchanged from #1032 and reuse its builders; the blurbs lead with what a #1032
# build does so a tester can tell the two apart.
_PR1044_DEFS = [
    {"kind": "contradiction_multisig_decoy_first", "script_type": "P2WSH", "family": "Multisig (2-of-3)",
     "label": "Decoy key listed first", "outcome": "refuse",
     "screen": _ATTACK_SCREEN, "expected": _REFUSE,
     "blurb": ("A genuine multisig change output, plus a decoy entry (a key you own that "
               "is not in the script) listed ahead of your real one. Already refused by "
               "#1032; unchanged here.")},
    {"kind": "decoy_last", "script_type": "P2WSH", "family": "Multisig (2-of-3)",
     "label": "Decoy key listed last", "outcome": "refuse",
     "screen": _ATTACK_SCREEN, "expected": _REFUSE,
     "blurb": ("A genuine multisig change output, plus a decoy entry (a key you own that "
               "is not in the script) listed after your real one. A #1032 build stops at "
               "the first verified entry and only the surplus count objects, a plain "
               "\"Transaction Problem\". Now every claim is held to the script and the "
               "decoy is refused as an attack.")},
    {"kind": "decoy_substituted", "script_type": "P2WSH", "family": "Multisig (2-of-3)",
     "label": "Decoy key in a cosigner's place", "outcome": "refuse",
     "screen": _ATTACK_SCREEN, "expected": _REFUSE,
     "blurb": ("A genuine multisig change output where a decoy entry (a key you own that "
               "is not in the script) replaces another cosigner's entry, so the output "
               "lists exactly three entries for three keys and the surplus count has nothing to say. A "
               "#1032 build shows this as change with no warning at all.")},
    {"kind": "surplus_multisig", "script_type": "P2WSH", "family": "Multisig (2-of-3)",
     "label": "Padded with a stranger's entry", "outcome": "refuse",
     "screen": _PROBLEM_SCREEN, "expected": _MALFORMED,
     "blurb": ("A genuine change output plus one extra entry claiming a stranger's "
               "fingerprint. Nothing of yours is misdescribed, so this still lands on "
               "the surplus count, unchanged from #1032.")},
]

# PR #1040: the two fingerprint records for one key must agree. The check needs
# the global xpubs to have anything to compare, so these builders add the
# wallet's; one leaves them out on purpose to show the limitation.
_PR1040_DEFS = [
    {"kind": "cosigner_mismatch", "script_type": "P2WSH", "family": "Multisig (2-of-3)",
     "label": "Cosigner fingerprint disagrees with its xpub", "outcome": "refuse",
     "screen": _PROBLEM_SCREEN, "expected": _MALFORMED,
     "blurb": ("Honest change, global xpubs present, but one cosigner's entry on the "
               "change output names a different fingerprint than that cosigner's xpub. "
               "The key and path are right, so only the consistency check objects. "
               "Earlier builds ignore the mislabel and show change.")},
    {"kind": "cosigner_mismatch_input", "script_type": "P2WSH", "family": "Multisig (2-of-3)",
     "label": "Cosigner fingerprint disagrees on an input", "outcome": "refuse",
     "screen": _PROBLEM_SCREEN, "expected": _MALFORMED,
     "blurb": ("Honest change, global xpubs present, but one cosigner's entry on an "
               "input names a different fingerprint than that cosigner's xpub. The check "
               "walks inputs and outputs alike.")},
    {"kind": "singlesig_xpub_mismatch", "script_type": "P2WPKH", "family": "Native SegWit",
     "label": "Global xpub fingerprint disagrees with its keys", "outcome": "refuse",
     "screen": _PROBLEM_SCREEN, "expected": _MALFORMED,
     "blurb": ("Honest single-sig change with the wallet's global xpub added, then the "
               "xpub's fingerprint mislabeled. Every key entry is correct and claims "
               "your seed; only the xpub record disagrees.")},
    {"kind": "mismatch_beneath_contradiction", "script_type": "P2WSH", "family": "Multisig (2-of-3)",
     "label": "Mismatch beneath a fake change", "outcome": "refuse",
     "screen": _ATTACK_SCREEN, "expected": _REFUSE,
     "blurb": ("The #1032 fake change (the output pays an attacker's 2-of-3 while "
               "claiming your key) with a cosigner mislabel on an input as well. The "
               "fingerprint check runs last, so the device must report the attack, "
               "not the mismatch.")},
    {"kind": "cosigner_missing", "script_type": "P2WSH", "family": "Multisig (2-of-3)",
     "label": "Cosigner fingerprint is all zeros", "outcome": "change",
     "screen": _CHANGE_OK_RESULT, "expected": _CHANGE_OK,
     "blurb": ("Honest change, global xpubs present, but one cosigner's entry on the "
               "change output carries the all-zero fingerprint a coordinator writes for a "
               "key it cannot identify. A missing value is not a second "
               "answer, so it is skipped and the output is correctly counted as change.")},
    {"kind": "cosigner_mismatch_no_xpubs", "script_type": "P2WSH", "family": "Multisig (2-of-3)",
     "label": "Mismatch with no global xpubs", "outcome": "change",
     "screen": _CHANGE_RESULT, "expected": _CHANGE_NO_XPUBS,
     "blurb": ("Honest change where one cosigner's entry on the change output names the "
               "wrong fingerprint, but the psbt carries no global xpubs. "
               "With no second record there is nothing to compare, so the mislabel "
               "goes unnoticed and the output is shown as change.")},
]

# PR #995: the fee a device that trusts the forged amount displays, and the fee
# the transaction really pays. The lie replaces one input's honest IN_VALUE with
# PR995_CLAIMED_INPUT_VALUE while the non_witness_utxo it carries really pays
# PR995_REAL_INPUT_VALUE. Derived, never hardcoded, so the two cannot drift.
_PR995_OUTPUT_TOTAL = DEFAULT_NUM_INPUTS * IN_VALUE - FEE
_PR995_SHOWN_INPUT_TOTAL = PR995_CLAIMED_INPUT_VALUE + (DEFAULT_NUM_INPUTS - 1) * IN_VALUE
_PR995_REAL_INPUT_TOTAL = PR995_REAL_INPUT_VALUE + (DEFAULT_NUM_INPUTS - 1) * IN_VALUE
_PR995_SHOWN_FEE = _PR995_SHOWN_INPUT_TOTAL - _PR995_OUTPUT_TOTAL
_PR995_REAL_FEE = _PR995_REAL_INPUT_TOTAL - _PR995_OUTPUT_TOTAL

_PR995_FEE_LIE_BLURB = (
    f"Input 0's non-witness UTXO hashes to its txid and proves the input is worth "
    f"{PR995_REAL_INPUT_VALUE:,} sats, but a witness UTXO slipped in beside it claims "
    f"only {PR995_CLAIMED_INPUT_VALUE:,}. A device without the fix believes the witness "
    f"UTXO and shows a {_PR995_SHOWN_FEE:,}-sat fee, while the transaction really pays "
    f"{_PR995_REAL_FEE:,} sats to the miner. The cross-check refuses the disagreement.")

_PR995_FEE_LIE_NOTE = (
    f"Like a device without the fix, this table counts input 0 at the witness UTXO's "
    f"{PR995_CLAIMED_INPUT_VALUE:,} sats, so its fee is wrong: input 0 is really worth "
    f"{PR995_REAL_INPUT_VALUE:,} and the real fee is {_PR995_REAL_FEE:,} sats.")

_PR995_NO_PREV_TX_BLURB = (
    "Every input carries a witness UTXO and no non-witness UTXO at all, so not one "
    "input amount here can be proven from the psbt. These particular amounts are "
    f"honest, so a device without the fix shows the correct {FEE:,}-sat fee, with "
    "nothing to back it. A legacy sighash commits to no amount, which is why a "
    "coordinator that did lie here would still collect a valid signature.")

_PR995_TAMPERED_BLURB = (
    "Input 0's non-witness UTXO has its amount edited, so it no longer hashes to the "
    "txid the outpoint claims to spend. A device without the fix never hashes it, so "
    f"it counts the edited amount and shows a {FEE + PR995_TAMPER_DELTA:,}-sat fee "
    f"where the real fee is {FEE:,}.")

_PR995_TAMPERED_NOTE = (
    f"Like a device without the fix, this table counts the edited "
    f"{IN_VALUE + PR995_TAMPER_DELTA:,} sats for input 0, so its fee is wrong: the "
    f"coin the txid names holds {IN_VALUE:,} and the real fee is {FEE:,} sats.")

_PR995_DEFS = [
    {"kind": "legacy_fee_lie", "script_type": "P2PKH", "family": "Legacy",
     "label": "Forged input amount (single-sig)", "outcome": "refuse",
     "screen": _ATTACK_SCREEN, "expected": _UNVERIFIED,
     "blurb": _PR995_FEE_LIE_BLURB, "summary_note": _PR995_FEE_LIE_NOTE},
    {"kind": "legacy_fee_lie_multisig", "script_type": "P2SH", "family": "Legacy multisig (2-of-3)",
     "label": "Forged input amount (multisig)", "outcome": "refuse",
     "screen": _ATTACK_SCREEN, "expected": _UNVERIFIED,
     "blurb": _PR995_FEE_LIE_BLURB, "summary_note": _PR995_FEE_LIE_NOTE},
    {"kind": "legacy_no_prev_tx", "script_type": "P2PKH", "family": "Legacy",
     "label": "No non-witness UTXO (single-sig)", "outcome": "refuse",
     "screen": _ATTACK_SCREEN, "expected": _UNVERIFIED,
     "blurb": _PR995_NO_PREV_TX_BLURB},
    {"kind": "legacy_no_prev_tx_multisig", "script_type": "P2SH", "family": "Legacy multisig (2-of-3)",
     "label": "No non-witness UTXO (multisig)", "outcome": "refuse",
     "screen": _ATTACK_SCREEN, "expected": _UNVERIFIED,
     "blurb": _PR995_NO_PREV_TX_BLURB},
    {"kind": "legacy_prev_tx_tampered", "script_type": "P2PKH", "family": "Legacy",
     "label": "Non-witness UTXO doesn't match its txid (single-sig)", "outcome": "refuse",
     "screen": _ATTACK_SCREEN, "expected": _UNVERIFIED,
     "blurb": _PR995_TAMPERED_BLURB, "summary_note": _PR995_TAMPERED_NOTE},

    # The two shapes that crash a build without the check rather than merely
    # misreporting the fee. Nothing is forged in either: both are simply psbts
    # that cannot say what an input is worth.
    {"kind": "legacy_outpoint_out_of_range", "script_type": "P2PKH", "family": "Legacy",
     "label": "Outpoint index does not exist", "outcome": "refuse",
     "screen": _PROBLEM_SCREEN, "expected": _MALFORMED,
     "blurb": ("Input 0's non-witness UTXO is genuine, but the input claims to "
               "spend an output one past the end of it, so no amount can be read for it "
               "at all. Checking the txid does not catch this, since the txid is "
               "correct and only the index is impossible. Without the check the first "
               "code to use that index is the code adding the amounts up, which fails "
               "on an unhandled error rather than reporting anything.")},
    {"kind": "legacy_no_utxo_data", "script_type": "P2PKH", "family": "Legacy",
     "label": "No input amount data at all", "outcome": "refuse",
     "screen": _PROBLEM_SCREEN, "expected": _MALFORMED,
     "blurb": ("Input 0 carries neither a non-witness UTXO nor a witness UTXO, so the "
               "psbt says nothing at all about what it is worth: there is not even a "
               "claim to disbelieve. Without the check this one also aborts on an "
               "unhandled error, part way through reading the input.")},
]


# PR #1046: nested single sig change whose redeem script is omitted. BIP-174 makes
# that field optional and BlueWallet's BIP-49 wallets really do leave it out, so the
# first case is an ordinary transaction rather than a forgery. Candidacy rests on
# three conditions: nested single sig inputs, an output that parses as plain p2sh,
# and an output that omits its redeem script. The last three cases pin those, each
# paying another wallet of this same seed so that the condition under test is the
# only thing keeping the output a spend.
_PR1046_DEFS = [
    {"kind": "nested_change_no_redeem", "script_type": "P2SH-P2WPKH", "family": "Nested SegWit",
     "label": "Own change, redeem script omitted", "outcome": "change",
     "screen": _CHANGE_OK_RESULT, "expected": _CHANGE_OK,
     "blurb": ("Your own nested single sig change, with the optional redeem script left "
               "out, which is what BlueWallet emits. Nothing is forged. Before the fix "
               "the output looked like plain p2sh, missed the change check and was shown "
               "as a payment out to a stranger; now it is counted as change.")},
    {"kind": "nested_change_repointed", "script_type": "P2SH-P2WPKH", "family": "Nested SegWit",
     "label": "Claims your key, pays an attacker", "outcome": "refuse",
     "screen": _ATTACK_SCREEN, "expected": _REFUSE,
     "blurb": ("Nested single sig change with its redeem script omitted, but the "
               "scriptPubKey repointed at an attacker's nested address. The derivation "
               "entry still truthfully names a key you own, so the claim and the script "
               "contradict each other. Before the fix this passed as an ordinary "
               "external spend and the contradiction was never looked at.")},
    {"kind": "nested_change_pays_us_lists_other", "script_type": "P2SH-P2WPKH", "family": "Nested SegWit",
     "label": "Pays your key, names someone else's", "outcome": "refuse",
     "screen": _ATTACK_SCREEN, "expected": _REFUSE,
     "blurb": ("Nested single sig change with its redeem script omitted. The output "
               "really is your change address, but its entry names a stranger's key and fingerprint at the same path. "
               "The rebuild uses the path, not the name, so the output is reached and "
               "the disagreement refused. Earlier builds, including the first revision "
               "of this PR, showed it as a payment out to your own address.")},
    {"kind": "bare_p2sh_two_entries", "script_type": "P2SH-P2WPKH", "family": "Nested SegWit",
     "label": "Bare p2sh listing two of your keys", "outcome": "refuse",
     "screen": _PROBLEM_SCREEN, "expected": _MALFORMED,
     "blurb": ("A bare p2sh output listing two derivation entries, both genuinely yours. "
               "One key cannot own two paths, so once the output is admitted to the "
               "rebuild the single sig surplus check refuses it. The first revision of this PR kept it out "
               "of the rebuild entirely and showed it as a payment out.")},
    {"kind": "bare_p2sh_unclaimed", "script_type": "P2SH-P2WPKH", "family": "Nested SegWit",
     "label": "Bare p2sh claiming nobody", "outcome": "spend",
     "screen": _SPEND_RESULT, "expected": _SPEND,
     "blurb": ("A bare p2sh output with no derivation entries at all, under nested "
               "single sig inputs. With its redeem script omitted it qualifies for the "
               "rebuild, but with no path to derive from there is nothing to compare "
               "against the scriptPubKey. Qualifying is not proof: it stays a payment "
               "out.")},
    {"kind": "other_wallet_nested_output", "script_type": "P2WPKH", "family": "Native SegWit",
     "label": "Native segwit inputs paying your nested wallet", "outcome": "spend",
     "screen": _SPEND_RESULT, "expected": _SPEND,
     "blurb": ("A payment from your native segwit wallet to your own nested segwit "
               "wallet, with the output's redeem script omitted. The output looks "
               "exactly like nested change with no redeem script, but the inputs are not nested single "
               "sig, so there is no rebuild to attempt. A payment out, correctly.")},
    {"kind": "other_wallet_native_output", "script_type": "P2SH-P2WPKH", "family": "Nested SegWit",
     "label": "Nested inputs paying your native segwit wallet", "outcome": "spend",
     "screen": _SPEND_RESULT, "expected": _SPEND,
     "blurb": ("A payment from your nested wallet to your own native segwit wallet. That "
               "output names its key directly rather than hiding it behind a script "
               "hash, so it never looks like plain p2sh and the exception does not "
               "apply. A payment out, correctly.")},
    {"kind": "other_wallet_legacy_multisig_output", "script_type": "P2SH-P2WPKH", "family": "Nested SegWit",
     "label": "Nested inputs paying a multisig you are in", "outcome": "spend",
     "screen": _SPEND_RESULT, "expected": _SPEND,
     "blurb": ("A payment from your nested wallet to a legacy 2-of-3 you are a cosigner "
               "of. It parses as plain p2sh just like nested change with no redeem "
               "script, but it supplies "
               "its redeem script, and a supplied script is exactly what the exception "
               "exists to cover the absence of. A payment out, correctly.")},
]


# PR #1047: every input must supply exactly the scripts its scriptPubKey commits to.
# The script type is not a free choice here, it is the variable under test, so each
# case reads its type from PR1047_CASES in common/attack_psbt.py rather than
# repeating it. `before` is what the PR's base, dev, does with the same psbt. It goes at
# the end of every blurb because that is what tells a tester whether the build in front
# of them has the fix. It is not a record of how releases behave, so re-measure it on
# dev whenever dev moves: #995 merging changed four of them.
_PR1047_MIXED = ("Before the fix the input's apparent type changed with the script "
                 "gone, so it aborted on \"Mixed inputs in the transaction\" instead.")
_PR1047_CRASH = ("Before the fix the extra witness script made the parser read this as "
                 "nested segwit multisig and then fail inside embit with a raw "
                 "\"Not a multisig script\" error.")
_PR1047_UNPROVEN = ("Before the fix the input missing its script read as legacy p2sh, "
                    "which must carry a non-witness UTXO. It has only a witness UTXO, so "
                    "it was refused on the attack screen instead.")
_PR1047_SILENT = "Before the fix the psbt parsed and the transaction was reviewed as normal."

_PR1047_DEFS = [
    # --- a script the input commits to is absent (correctness problem) -------
    {"kind": "missing_witness_p2wsh", "label": "Witness script omitted",
     "outcome": "refuse", "screen": _PROBLEM_SCREEN, "expected": _MALFORMED,
     "blurb": ("A native segwit multisig input whose witness script is left out. The "
               "scriptPubKey is only a hash of it, so with the script gone there is "
               "nothing to check and nothing to read the wallet policy from. " + _PR1047_MIXED)},
    {"kind": "missing_redeem_p2sh", "label": "Redeem script omitted",
     "outcome": "refuse", "screen": _PROBLEM_SCREEN, "expected": _MALFORMED,
     "blurb": ("A legacy p2sh multisig input with no redeem script. For legacy p2sh the "
               "redeem script is the multisig itself, so this is the whole script the "
               "input spends with. " + _PR1047_MIXED)},
    {"kind": "missing_redeem_nested_singlesig", "label": "Redeem script omitted",
     "outcome": "refuse", "screen": _PROBLEM_SCREEN, "expected": _MALFORMED,
     "blurb": ("A nested single sig input with no redeem script. Note this is the input "
               "side of the same omission PR #1046 handles on an output, where leaving "
               "it out is legal; on an input it is the one thing being checked. " + _PR1047_UNPROVEN)},
    {"kind": "missing_witness_nested_multisig", "label": "Witness script omitted",
     "outcome": "refuse", "screen": _PROBLEM_SCREEN, "expected": _MALFORMED,
     "blurb": ("A nested segwit multisig input missing the second of its two layers. The "
               "redeem script is present and commits to a witness script that is not "
               "there. " + _PR1047_UNPROVEN)},
    {"kind": "missing_redeem_nested_multisig", "label": "Redeem script omitted",
     "outcome": "refuse", "screen": _PROBLEM_SCREEN, "expected": _MALFORMED,
     "blurb": ("A nested segwit multisig input with its redeem script, the outer of its "
               "two layers, left out. This one is inert: the "
               "signature and the wallet policy both read the witness script, which is "
               "still correct, so nothing downstream is affected. It is refused because "
               "a rule about which script matters would move with the policy code. " + _PR1047_SILENT)},

    # --- a supplied script hashes to the wrong value (attack) ----------------
    {"kind": "wrong_witness_p2wsh", "label": "Witness script is a stranger's",
     "outcome": "refuse", "screen": _ATTACK_SCREEN, "expected": _REFUSE,
     "blurb": ("A native segwit multisig input supplying a 2-of-3 that holds none of "
               "your keys. It does not hash to the scriptPubKey, so the input's own "
               "account of what it spends contradicts itself. " + _PR1047_SILENT)},
    {"kind": "wrong_redeem_p2sh", "label": "Redeem script is a stranger's",
     "outcome": "refuse", "screen": _ATTACK_SCREEN, "expected": _REFUSE,
     "blurb": ("A legacy p2sh multisig input supplying a stranger's 2-of-3 as its redeem "
               "script. " + _PR1047_SILENT)},
    {"kind": "wrong_redeem_nested_singlesig", "label": "Redeem script is a stranger's",
     "outcome": "refuse", "screen": _ATTACK_SCREEN, "expected": _REFUSE,
     "blurb": ("A nested single sig input whose redeem script wraps a key you do not "
               "own. " + _PR1047_SILENT)},
    {"kind": "wrong_witness_nested_multisig", "label": "Witness script is a stranger's",
     "outcome": "refuse", "screen": _ATTACK_SCREEN, "expected": _REFUSE,
     "blurb": ("A nested segwit multisig input whose witness script does not hash to the "
               "redeem script that is supplied beside it. The inner of the two layers "
               "fails. " + _PR1047_SILENT)},
    {"kind": "wrong_redeem_nested_multisig", "label": "Redeem script is a stranger's",
     "outcome": "refuse", "screen": _ATTACK_SCREEN, "expected": _REFUSE,
     "blurb": ("A nested segwit multisig input whose redeem script does not hash to the "
               "scriptPubKey, while its witness script is still correct. This one is "
               "inert: the signature and the wallet policy both read the witness script, "
               "so nothing downstream is affected. It is refused anyway, because a rule "
               "about which script matters would move with the policy code. " + _PR1047_SILENT)},

    # --- a script the input commits to nowhere (ungraded) --------------------
    {"kind": "extra_witness_p2sh", "label": "Extra witness script",
     "outcome": "refuse", "screen": _PROBLEM_SCREEN, "expected": _MALFORMED,
     "blurb": ("A legacy p2sh multisig input with a witness script added. Legacy p2sh "
               "commits to no witness script, so there is no hash it could be checked "
               "against. This is the shape that distorts the wallet policy. " + _PR1047_CRASH)},
    {"kind": "extra_redeem_p2wpkh", "label": "Extra redeem script",
     "outcome": "refuse", "screen": _PROBLEM_SCREEN, "expected": _MALFORMED,
     "blurb": ("A native segwit input with a redeem script added. The scriptPubKey names "
               "the key directly and commits to no script at all. " + _PR1047_SILENT)},
    {"kind": "extra_witness_nested_singlesig", "label": "Extra witness script",
     "outcome": "refuse", "screen": _PROBLEM_SCREEN, "expected": _MALFORMED,
     "blurb": ("A nested single sig input with a witness script added. Its redeem script "
               "is a p2wpkh, not a script hash, so nothing commits to a witness "
               "script. " + _PR1047_CRASH)},
    {"kind": "extra_redeem_p2wsh", "label": "Extra redeem script",
     "outcome": "refuse", "screen": _PROBLEM_SCREEN, "expected": _MALFORMED,
     "blurb": ("A native segwit multisig input with a redeem script added. Native segwit "
               "has no p2sh layer to commit to one. Inert, and refused because a script "
               "outside the input's commitments is provably foreign to it. " + _PR1047_SILENT)},

    # --- the rule applies to another party's input too -----------------------
    {"kind": "payjoin_ok", "label": "Collaborative spend, well formed",
     "outcome": "change", "screen": _CHANGE_OK_RESULT, "expected": _CHANGE_OK,
     "blurb": ("Two inputs: yours, and another party's that claims none of your keys, as "
               "a payjoin would. Every script is correct. Nothing should be refused "
               "here; this is the case that shows the new check leaves an honest "
               "collaborative spend alone.")},
    {"kind": "payjoin_missing_redeem", "label": "Their input omits its redeem script",
     "outcome": "refuse", "screen": _PROBLEM_SCREEN, "expected": _MALFORMED,
     "blurb": ("A collaborative spend, as a payjoin would build, with the other party's "
               "redeem script left out. Whose input it is rests on the psbt's own claims, so exempting "
               "another party's input would let a coordinator claim the exemption for "
               "any input by stripping its derivation paths. " + _PR1047_UNPROVEN)},
    {"kind": "payjoin_finalized", "label": "Their input is already finalized",
     "outcome": "refuse", "screen": _PROBLEM_SCREEN,
     "expected": "Device refuses it, which is a known gap rather than the right answer.",
     "blurb": ("A collaborative spend where the other party has already finalized their "
               "input. Nothing is forged and nothing is wrong with the transaction: "
               "finalizing just moves the script into the final scriptSig and witness "
               "and clears the field the check reads, so an honest input looks like one "
               "that omitted its redeem script. The PR records this as a TODO, to "
               "recover the script from the final fields and verify it the same way. "
               "Until then it is refused. A build without the fix refuses it too, but "
               "on the attack screen: with its script cleared the input reads as legacy "
               "p2sh, which must carry a non-witness UTXO, and it has only a witness "
               "UTXO.")},
    {"kind": "payjoin_wrong_redeem", "label": "Their input supplies the wrong script",
     "outcome": "refuse", "screen": _ATTACK_SCREEN, "expected": _REFUSE,
     "blurb": ("A collaborative spend where the other party's redeem script is built "
               "from their next address rather than the one their scriptPubKey commits "
               "to. Their input is checked exactly as yours would be. " + _PR1047_SILENT)},
]


# PR #1041: a negative fee. Not a forgery: every key claim in this psbt is honest
# and the change output is genuinely ours. Only the arithmetic is impossible, the
# outputs move more than the inputs hold. The check is a single comparison on the
# parsed fee, so it is script-type agnostic and one family is enough to exercise it.
_PR1041_DEFS = [
    {"kind": "negative_fee", "script_type": "P2WPKH", "family": "Native SegWit",
     "label": "Outputs exceed inputs", "outcome": "refuse",
     "screen": _PROBLEM_SCREEN, "expected": _MALFORMED,
     "blurb": ("An ordinary change transaction with its change output inflated "
               f"{NEGATIVE_FEE_OVERRUN:,} sats past what the inputs hold, so the fee "
               "comes out negative. Nothing about the keys is false; the transaction is "
               "simply impossible and no network would relay it. Before the fix the "
               "psbt parsed and the device reviewed it as normal, quoting a fee of "
               f"-{NEGATIVE_FEE_OVERRUN:,} sats.")},
]


# PR #1060: each claim of ours on an input is held to the script the input commits to.
# "Before the fix" is measured on dev, #1060's base now that #1047 has merged. A build
# without the fix parses all but the held and wrong-seed cases, then signs. The taproot
# refusals forge every input, so that build adds no signature at all and stops on
# "Signing Failed" after the review; the one-input merkle root case shows what happens
# when it can sign the rest.
_PR1060_HELD = ("Before the fix the milder finding was checked first and the device "
                "stopped on it, as \"Transaction Problem\" rather than an attack warning.")
_PR1060_SIGNING_FAILED = ("Before the fix the transaction was reviewed as normal and then "
                          "stopped on \"Signing Failed\", since embit added no signature.")
_PR1060_FAKE_CHANGE = ("Two problems. The change output claims your key at your change path "
                       "but pays someone else's, so the funds really leave. ")

_PR1060_DEFS = [
    # --- a true key of ours that the input's script does not use (attack) ----
    {"kind": "planted_claim", "script_type": "P2WPKH", "family": "Native SegWit",
     "label": "Your key planted on their input", "outcome": "refuse",
     "screen": _ATTACK_SCREEN, "expected": _REFUSE,
     "blurb": ("A collaborative spend, as a payjoin would build: your three inputs and "
               "another party's. Their input carries a true claim of yours, your "
               "fingerprint on a key your seed really derives, which anyone with your "
               "account xpub can work out. But their input's script pays their own key. "
               "Before the fix the device signed as normal, adding a signature for their "
               "input that can never spend it.")},
    {"kind": "decoy_input_multisig", "script_type": "P2WSH", "family": "Multisig (2-of-3)",
     "label": "Decoy key on your own input", "outcome": "refuse",
     "screen": _ATTACK_SCREEN, "expected": _REFUSE,
     "blurb": ("Your own 2-of-3 input, with its real derivation entries plus a decoy: a "
               "key your seed really derives, at an address index no input uses, so the "
               "input's witness script has no place for it. Before the fix the device "
               "signed as normal, adding a signature with the decoy key that can never "
               "help spend the coin.")},
    {"kind": "taproot_claim_on_p2wpkh", "script_type": "P2WPKH", "family": "Native SegWit",
     "label": "Taproot claim on a native segwit input", "outcome": "refuse",
     "screen": _ATTACK_SCREEN, "expected": _REFUSE,
     "blurb": ("Input 0's only claim of yours sits in the taproot derivation map, on a key "
               "of yours its p2wpkh script does not use. Only a taproot input commits to "
               "a tweaked key, so nothing can explain the mismatch. Before the fix the "
               "psbt parsed and the device signed it.")},
    {"kind": "taproot_root_contradicts", "script_type": "P2TR", "family": "Taproot",
     "label": "Merkle root the address does not commit to", "outcome": "refuse",
     "screen": _ATTACK_SCREEN, "expected": _REFUSE,
     "blurb": ("Every input is your own key path taproot coin with no script tree, but "
               "the psbt supplies a merkle root for each one anyway. Your internal key "
               "tweaked by that root is not the key the input pays, so the psbt "
               "contradicts its own claim. " + _PR1060_SIGNING_FAILED)},

    # --- shapes the device cannot check or sign yet ---------------------------
    {"kind": "taproot_leaf_only", "script_type": "P2TR", "family": "Taproot",
     "label": "Your key only in a script leaf", "outcome": "refuse",
     "screen": _NOT_YET_SCREEN, "expected": _UNSUPPORTED,
     "blurb": ("Every input pays a taproot address spendable only through its script "
               "tree: the internal key is the provably unspendable NUMS point, and your "
               "key is in the tree's one leaf. The device cannot sign a script path "
               "spend yet. " + _PR1060_SIGNING_FAILED)},
    {"kind": "taproot_root_omitted", "script_type": "P2TR", "family": "Taproot",
     "label": "Merkle root left out", "outcome": "refuse",
     "screen": _CANT_SIGN_SCREEN, "expected": _CANT_SIGN,
     "blurb": ("Every input is your own taproot coin, spendable through its key path, at "
               "an address that tweaks your internal key by a script tree. Nothing is "
               "forged, but the psbt leaves out the optional merkle root needed to "
               "rebuild that address, so each claim can be neither confirmed nor "
               "refuted. Each is set aside, which leaves no input this seed can sign. "
               + _PR1060_SIGNING_FAILED)},
    {"kind": "taproot_root_omitted_one_input", "script_type": "P2TR", "family": "Taproot",
     "label": "Merkle root left out on one input", "outcome": "change",
     "screen": _CHANGE_OK_RESULT,
     "expected": ("Device signs the other two inputs and leaves input 0 unsigned, with no "
                  "warning. The PR sets that input aside by design."),
     "blurb": ("Input 0 is your own taproot coin, spendable through its key path, at an "
               "address that tweaks your internal key by a script tree. Nothing is "
               "forged, but the psbt leaves out the optional merkle root needed to "
               "rebuild that address, so the claim on input 0 can be neither confirmed "
               "nor refuted. The other two inputs are ordinary. The fix sets input 0 "
               "aside as not yours and signs the other two, and nothing on screen says "
               "input 0 was skipped. Builds without the fix end the same way, because "
               "embit cannot sign input 0 without the merkle root.")},

    # --- claims at paths no wallet uses ("Transaction Problem") --------------
    {"kind": "master_key_input", "script_type": "P2WPKH", "family": "Native SegWit",
     "label": "Input at the master key", "outcome": "refuse",
     "screen": _PROBLEM_SCREEN, "expected": _MALFORMED,
     "blurb": ("Input 0 really pays your seed's master key and claims it at the empty "
               "path m. No wallet spends from the master key, though embit will sign for "
               "it. Before the fix the device signed as normal, including a valid "
               "signature for that coin.")},
    {"kind": "master_key_change", "script_type": "P2WPKH", "family": "Native SegWit",
     "label": "Change to the master key", "outcome": "refuse",
     "screen": _PROBLEM_SCREEN, "expected": _MALFORMED,
     "blurb": ("The change output really pays your seed's master key and claims it at the "
               "empty path m. No wallet receives at the master key. Before the fix the "
               "device showed it as your change.")},
    {"kind": "one_level_input", "script_type": "P2WPKH", "family": "Native SegWit",
     "label": "Input at a one-level path", "outcome": "refuse",
     "screen": _PROBLEM_SCREEN, "expected": _MALFORMED,
     "blurb": ("Input 0 really pays your seed's key at m/5 and claims it at that path. A "
               "path of one level cannot hold both a branch and an address index, so no "
               "wallet spends from one. Before the fix the device signed as normal, "
               "including a valid signature for that coin.")},
    {"kind": "one_level_change", "script_type": "P2WPKH", "family": "Native SegWit",
     "label": "Change at a one-level path", "outcome": "change",
     "screen": _CHANGE_RESULT,
     "expected": "Device counts it as yours, a known gap that PR #1073 closes.",
     "blurb": ("The change output really pays your seed's key at m/5 and claims it at that "
               "path. The fix refuses that path on an input but not on an output, where "
               "the rules for change paths are left to PR #1073, so the device still "
               "counts it as yours, on a screen titled Self-Transfer. Builds without the "
               "fix do the same.")},

    # --- a milder finding held until the outputs are read (attack) -----------
    {"kind": "held_false_input_claim", "script_type": "P2WPKH", "family": "Native SegWit",
     "label": "Fake change behind a false input claim", "outcome": "refuse",
     "screen": _ATTACK_SCREEN, "expected": _REFUSE,
     "blurb": (_PR1060_FAKE_CHANGE + "Input 0 also claims your fingerprint on a key your "
               "seed does not derive, which could be an honest bug. " + _PR1060_HELD)},
    {"kind": "held_mixed_types_input", "script_type": "P2WPKH", "family": "Native SegWit",
     "label": "Fake change behind mixed path types", "outcome": "refuse",
     "screen": _ATTACK_SCREEN, "expected": _REFUSE,
     "blurb": (_PR1060_FAKE_CHANGE + "Input 0 also lists entries in both the ecdsa and "
               "taproot derivation maps, which no script can use and which could be an "
               "honest bug. " + _PR1060_HELD)},
    {"kind": "held_surplus_output", "script_type": "P2WPKH", "family": "Native SegWit",
     "label": "Fake change behind a surplus path entry", "outcome": "refuse",
     "screen": _ATTACK_SCREEN, "expected": _REFUSE,
     "blurb": (_PR1060_FAKE_CHANGE + "A second output of yours, listed ahead of it, gives "
               "two derivation paths for its one key, which could be an honest bug. "
               + _PR1060_HELD)},

    # --- the wrong-seed check now waits for the input checks ------------------
    {"kind": "wrong_seed_fee_lie", "script_type": "P2PKH", "family": "Legacy",
     "label": "Wrong seed, forged input amount", "outcome": "refuse",
     "screen": _ATTACK_SCREEN, "expected": _REFUSE, "load_seed": TEST_DECOY_SEED,
     "blurb": ("The seed to load is not in this wallet, and input 0 is also forged: its "
               "non-witness UTXO proves it is worth "
               f"{PR995_REAL_INPUT_VALUE:,} sats, but a witness UTXO beside it claims "
               f"only {PR995_CLAIMED_INPUT_VALUE:,}. The fix checks the inputs before "
               "asking whether the seed can sign, so the forgery is reported. Before the "
               "fix the device said only that this seed can't sign it."),
     "summary_note": _PR995_FEE_LIE_NOTE},
]


# PR #1073: change has to come back where the wallet will look for it. #1073 is stacked
# on #1060, so "before the fix" is measured on #1060's head; current dev does the same
# with every psbt here. A build without the fix parses all of them with no warning and
# signs.
_PR1073_LOST = ("Your wallet never scans that path, so the change would vanish from your "
                "balance. ")
_PR1073_BEFORE_CHANGE = "Before the fix the device showed it as your change and signed."
_PR1073_BEFORE_SELF = ("Before the fix the device showed it as a self-transfer back to your "
                       "wallet and signed.")

_PR1073_DEFS = [
    # --- change at a path the wallet does not scan (attack) ------------------
    {"kind": "change_extra_level", "script_type": "P2WPKH", "family": "Native SegWit",
     "label": "Change at an extra path level", "outcome": "refuse",
     "screen": _UNSAFE_PATH_SCREEN, "expected": _REFUSE,
     "blurb": ("The change output really pays your key, at m/84'/0'/0'/7/1/0: a level no "
               "wallet uses sits between the account and the change branch, and anyone "
               "with your account xpub can derive keys there. " + _PR1073_LOST
               + _PR1073_BEFORE_CHANGE)},
    {"kind": "change_extra_level_taproot", "script_type": "P2TR", "family": "Taproot",
     "label": "Change at an extra path level", "outcome": "refuse",
     "screen": _UNSAFE_PATH_SCREEN, "expected": _REFUSE,
     "blurb": ("The taproot change output really pays your key, at m/86'/0'/0'/7/1/0: a "
               "level no wallet uses sits between the account and the change branch, and "
               "anyone with your account xpub can derive keys there. " + _PR1073_LOST
               + _PR1073_BEFORE_CHANGE)},
    {"kind": "change_extra_level_multisig", "script_type": "P2WSH", "family": "Multisig (2-of-3)",
     "label": "Change at an extra path level", "outcome": "refuse",
     "screen": _UNSAFE_PATH_SCREEN, "expected": _REFUSE,
     "blurb": ("The change output really pays your 2-of-3, with every cosigner's key at "
               "m/48'/0'/0'/2'/7/1/0: a level no wallet uses sits between the account and "
               "the change branch. " + _PR1073_LOST + "The psbt carries no global xpubs. "
               "Before the fix the device showed it as your change, and only a loaded "
               "wallet descriptor caught it, as \"Address Verification Failed\".")},
    {"kind": "change_other_branch", "script_type": "P2WPKH", "family": "Native SegWit",
     "label": "Change on branch 2", "outcome": "refuse",
     "screen": _UNSAFE_PATH_SCREEN, "expected": _REFUSE,
     "blurb": ("The change output really pays your key, at m/84'/0'/0'/2/0. Wallets scan "
               "only branch 0 (receive) and branch 1 (change), so the change would vanish "
               "from your balance. " + _PR1073_BEFORE_SELF)},
    {"kind": "change_hardened_index", "script_type": "P2WPKH", "family": "Native SegWit",
     "label": "Change at a hardened address index", "outcome": "refuse",
     "screen": _UNSAFE_PATH_SCREEN, "expected": _REFUSE,
     "blurb": ("The change output really pays your key, at m/84'/0'/0'/1/0', a hardened "
               "address index. Wallets derive their addresses from the account xpub, "
               "which cannot reach a hardened index, so the change would vanish from your "
               "balance. " + _PR1073_BEFORE_CHANGE)},
    {"kind": "one_level_change", "script_type": "P2WPKH", "family": "Native SegWit",
     "label": "Change at a one-level path", "outcome": "refuse",
     "screen": _UNSAFE_PATH_SCREEN, "expected": _REFUSE,
     "blurb": ("The change output really pays your seed's key at m/5 and claims it at that "
               "path. A path of one level cannot hold both a branch and an address index, "
               "so no wallet would find the change. " + _PR1073_BEFORE_SELF)},
    {"kind": "change_other_account", "script_type": "P2WPKH", "family": "Native SegWit",
     "label": "Output to your second account", "outcome": "refuse",
     "screen": _UNSAFE_PATH_SCREEN, "expected": _REFUSE,
     "blurb": ("An output pays the first receive address of your seed's second account, "
               "m/84'/0'/1'/0/0, and says so, while every input spends from the first "
               "account. The fix refuses an output of yours that goes to a wallet the "
               "inputs do not spend from, and that includes an honest transfer between "
               "your own accounts annotated like this one. The PR notes Bitcoin Core "
               "annotates such transfers; left unannotated, the output is shown as a "
               "payment. " + _PR1073_BEFORE_SELF)},

    # --- change far past the inputs' address indexes (warning) ---------------
    {"kind": "distant_change", "script_type": "P2WPKH", "family": "Native SegWit",
     "label": "Change at a distant address index", "outcome": "warn",
     "screen": _DISTANT_SCREEN,
     "expected": "The change screen then marks it \"Distant index #20000\", and signing is allowed.",
     "blurb": ("The change output pays your key at m/84'/0'/0'/1/20000, while the inputs "
               "spend from receive indexes 0 to 2. A wallet looks only a limited distance "
               "past the addresses it has used, so it may never find change this far "
               "along. The device cannot see how far the wallet has handed out addresses, "
               "so change more than 10,000 indexes past the smallest input index gets a "
               "warning and you decide. Before the fix there was no warning.")},
    {"kind": "distant_change_far_input", "script_type": "P2WPKH", "family": "Native SegWit",
     "label": "Distant change behind a far input", "outcome": "warn",
     "screen": _DISTANT_SCREEN,
     "expected": "The change screen then marks it \"Distant index #20000\", and signing is allowed.",
     "blurb": ("The change output pays your key at m/84'/0'/0'/1/20000. Inputs 0 and 1 "
               "spend from receive indexes 0 and 1, and input 2 from receive index 50,000. "
               "A coordinator could add an input like that to make the change look close "
               "to addresses in use, but the device measures from the smallest input "
               "index, so the warning still shows. Before the fix there was no warning.")},

    # --- inputs of yours from two wallets ------------------------------------
    {"kind": "added_input", "script_type": "P2WPKH", "family": "Native SegWit",
     "label": "Change under an added input's path", "outcome": "refuse",
     "screen": _PROBLEM_SCREEN, "expected": _MIXED_WALLETS,
     "blurb": ("A fourth input claims your key at m/84'/0'/0'/7/0/0 and carries only a "
               "witness UTXO, and the change goes to m/84'/0'/0'/7/1/0, under that input's "
               "path. A segwit v0 signature commits only to its own input, so this may be "
               "the coordinator's own coin described as yours, and your signatures on the "
               "other three stay valid either way. The device cannot tell which of the "
               "inputs' wallets is real. " + _PR1073_BEFORE_CHANGE)},
    {"kind": "two_accounts", "script_type": "P2WPKH", "family": "Native SegWit",
     "label": "Honest spend from two accounts", "outcome": "refuse",
     "screen": _PROBLEM_SCREEN,
     "expected": ("A known cost of the fix: this psbt is honest. With each input's previous "
                  "transaction attached, it would pass."),
     "blurb": ("An honest spend from two of your accounts: input 0 from m/84'/0'/1'/0/0, "
               "the other inputs and the change in the first account. Every input carries "
               "only a witness UTXO, so the device cannot tell this from a coordinator "
               "adding a coin it describes as yours, and refuses it. "
               + _PR1073_BEFORE_CHANGE)},
    {"kind": "two_accounts_previous_txs", "script_type": "P2WPKH", "family": "Native SegWit",
     "label": "Two accounts, previous transactions attached", "outcome": "change",
     "screen": _CHANGE_OK_RESULT, "expected": _CHANGE_OK,
     "blurb": ("An honest spend from two of your accounts: input 0 from m/84'/0'/1'/0/0, "
               "the other inputs and the change in the first account. Every input carries "
               "a non-witness UTXO, its previous transaction, which the device checks "
               "against the input's txid. With every input proven, inputs from two "
               "wallets are allowed. Builds without the fix show the change too.")},

    # --- a gap the PR documents ----------------------------------------------
    {"kind": "added_input_taproot", "script_type": "P2TR", "family": "Taproot",
     "label": "Change under a real coin's path", "outcome": "change",
     "screen": _CHANGE_RESULT,
     "expected": ("Device shows it as change, a known gap: a real coin of yours at a path "
                  "the coordinator chose lets change go there. The overview shows 4 inputs."),
     "blurb": ("A fourth input pays your key at m/86'/0'/0'/7/0/0, and the change goes to "
               "m/86'/0'/0'/7/1/0, under that input's path. Every taproot signature commits "
               "to every input's script and amount, so this coin has to be real: a "
               "coordinator would first have to send it to you. The fix then takes the "
               "input's path as a wallet you spend from and accepts the change there. "
               "Builds without the fix do the same.")},
]


# Not tied to a PR. The unsupported-script-type abort sat under #1032 while having
# nothing to do with change ownership, and #995 changes which screen it reaches, so
# it belongs here rather than under either one.
_DEV_DEFS = [
    {"kind": "unsupported_script_type", "script_type": "P2WPKH", "family": "bare p2pk",
     "label": "Unsupported script type", "outcome": "error",
     "screen": _ERROR_SCREEN, "expected": _ERROR,
     "blurb": ("The inputs and change use bare pay-to-pubkey, which the device does not "
               "support. It aborts rather than guess. No dedicated screen for this yet. "
               "PR #995 changes the destination: bare p2pk types as None, which its "
               "input-amount check reads as an amount it cannot prove, so the abort "
               "becomes a refusal on the attack screen instead.")},
]


# PR #949: silent payments. Outcomes are what #949 (head 3ac91816, on embit
# 371b9f2) does, checked by running every psbt through it; where that differs from
# BIP375 the blurb says so. #949 recomputes every share, proof and script itself
# at the sign step, after the review screens, so refusals land there.
_SP_ERROR_SCREEN = "SP Signing Error"
_UNKNOWN_QR_SCREEN = "Error / Unknown QR Type"
_SP_SIGNS = ("Device should show the silent payment address, sign, and hand back the "
             "psbt with its ECDH share, DLEQ proof and output script filled in.")
_SP_AT_SIGN = ("The review screens come first. SP Signing Error shows when you choose to "
               "sign.")
_UNKNOWN_QR = "Device should reject the scan as an unknown QR type."
_OBVIOUS_EXPECTATIONS = _OBVIOUS_EXPECTATIONS | {_UNKNOWN_QR}

_PR949_HONEST_DEFS = [
    {"kind": "sp_pay", "label": "Pay a silent payment address", "outcome": "spend",
     "screen": _SPEND_RESULT, "expected": _SP_SIGNS,
     "blurb": ("Pays bob's silent payment address, with change back to your wallet. The "
               "output carries only bob's scan and spend keys, no script and no ECDH "
               "share: the device has to work out the real taproot output itself.")},
    {"kind": "sp_pay_plus_normal", "label": "Silent payment plus an ordinary payment",
     "outcome": "spend", "screen": _SPEND_RESULT, "expected": _SP_SIGNS,
     "blurb": ("Pays bob's silent payment address and an ordinary bc1q address, with "
               "change. Only the silent payment output needs the device to compute its "
               "script.")},
    {"kind": "sp_same_twice", "label": "Two payments to one silent payment address",
     "outcome": "spend", "screen": _SPEND_RESULT, "expected": _SP_SIGNS,
     "blurb": ("Pays bob's silent payment address twice. The two outputs share one ECDH "
               "secret and differ only by k = 0 and k = 1, so they land at two different "
               "taproot keys. Both should show as bob's sp1q address.")},
    {"kind": "sp_two_recipients", "label": "Two silent payment recipients",
     "outcome": "spend", "screen": _SPEND_RESULT, "expected": _SP_SIGNS,
     "blurb": ("Pays bob's and carol's silent payment addresses. Each scan key gets its "
               "own ECDH share and DLEQ proof when the device signs.")},
    {"kind": "sp_labeled_recipient", "label": "Pay a labeled silent payment address",
     "outcome": "spend", "screen": _SPEND_RESULT, "expected": _SP_SIGNS,
     "blurb": ("Pays bob's label 1 address. To a sender a labeled address is just another "
               "spend key, so the output carries no label field; that field is only for "
               "marking your own change.")},
    {"kind": "sp_change", "label": "Silent payment change", "outcome": "change",
     "screen": _CHANGE_OK_RESULT, "expected": _SP_SIGNS,
     "blurb": ("Pays bob's silent payment address, with the change sent to your own "
               "silent payment address under the change label, m = 0, and marked with "
               "that label. The device rebuilds the labeled spend key from this seed and "
               "shows it as Your Change.")},
    {"kind": "sp_nums_input", "label": "Input that does not count", "outcome": "refuse",
     "screen": _SP_ERROR_SCREEN, "expected": _SP_AT_SIGN, "family": "Taproot",
     "blurb": ("Three taproot inputs. Two are your key path coins. The third is someone "
               "else's script path coin whose internal key is the provably unspendable "
               "point H, which BIP352 leaves out of the shared secret. #949 never gets "
               "to that rule: it signs alone, and refuses any input that is not this "
               "seed's own as a multi-party send.")},
    {"kind": "sp_mixed_types", "label": "Inputs of three script types", "outcome": "error",
     "screen": _ERROR_SCREEN, "family": "Mixed input types",
     "expected": ("Device aborts with \"Mixed inputs in the transaction\" while reading "
                  "the inputs, before any silent payment code runs."),
     "blurb": ("One taproot, one native segwit and one legacy input, all yours and all "
               "valid for a silent payment. SeedSigner allows only one input type per "
               "transaction, so #949 never gets as far as the silent payment.")},
    {"kind": "sp_ready", "label": "Shares, proof and script already filled",
     "outcome": "spend", "screen": _SPEND_RESULT,
     "expected": ("Device should check the share, proof and script against its own, then "
                  "sign."),
     "blurb": ("Pays bob's silent payment address. The ECDH share, its DLEQ proof and the "
               "output script are already in the psbt, all correct, and the transaction "
               "is closed to changes. The device derives them again and they agree.")},
    {"kind": "sp_per_input_shares", "label": "Per-input shares", "outcome": "spend",
     "screen": _SPEND_RESULT, "expected": _SP_SIGNS,
     "blurb": ("Every input carries its own ECDH share and DLEQ proof, the form BIP375 uses "
               "when several signers share a transaction. #949 signs alone: it deletes "
               "the per-input shares without checking them and writes one global share "
               "of its own.")},
    {"kind": "sp_spend", "label": "Spend a received silent payment",
     "outcome": "spend", "screen": _SPEND_RESULT, "num_inputs": 1, "family": "Taproot",
     "expected": "Device should sign the input with your spend key plus the tweak.",
     "blurb": ("Spends a coin someone sent to your silent payment address. The input "
               "carries the tweak and your spend key's path, m/352'/0'/0'/0'/0 (BIP376), "
               "and pays everything out to an ordinary address.")},
    {"kind": "sp_spend_labeled", "label": "Spend a received labeled payment",
     "outcome": "spend", "screen": _SPEND_RESULT, "num_inputs": 1, "family": "Taproot",
     "expected": "Device should sign the input with your spend key plus the tweak.",
     "blurb": ("Spends a coin someone sent to your label 1 address. The tweak includes "
               "the label's own tweak, so it still opens the coin from your one spend "
               "key.")},
]

_PR949_ATTACK_DEFS = [
    {"kind": "sp_script_mismatch", "label": "Output script redirected", "outcome": "refuse",
     "screen": _SP_ERROR_SCREEN, "expected": _SP_AT_SIGN,
     "blurb": ("The share and proof are right, but the output script pays an attacker's "
               "key instead of the one they derive. A device that trusted the script would "
               "send bob's payment elsewhere. #949 derives the script itself and refuses.")},
    {"kind": "sp_bad_dleq", "label": "Invalid DLEQ proof", "outcome": "refuse",
     "screen": _SP_ERROR_SCREEN, "expected": _SP_AT_SIGN,
     "blurb": ("The ECDH share is right but its DLEQ proof has one bit flipped, so it "
               "proves nothing. #949 checks a declared proof against the inputs' keys.")},
    {"kind": "sp_missing_dleq", "label": "Share with no proof", "outcome": "refuse",
     "screen": _SP_ERROR_SCREEN, "expected": _SP_AT_SIGN,
     "blurb": ("A global ECDH share with no DLEQ proof next to it. BIP375 requires the "
               "pair, and #949 refuses either one alone.")},
    {"kind": "sp_share_wrong_value", "label": "Share for different keys",
     "outcome": "refuse", "screen": _SP_ERROR_SCREEN, "expected": _SP_AT_SIGN,
     "blurb": ("The share and its proof agree with each other, but for a key sum these "
               "inputs do not have. #949 compares the share with the one it derives and "
               "refuses.")},
    {"kind": "sp_share_wrong_scan_key", "label": "Share for a scan key nobody is paid",
     "outcome": "spend", "screen": _SPEND_RESULT,
     "expected": "Device signs: #949 drops the extra share without a warning.",
     "blurb": ("Next to the payment to bob sits a valid share and proof for carol's scan "
               "key, which no output pays. It cannot move funds, and #949 silently drops "
               "it when it writes its own shares.")},
    {"kind": "sp_missing_input_share", "label": "One input's share missing",
     "outcome": "spend", "screen": _SPEND_RESULT,
     "expected": ("Device signs: BIP375 calls this psbt invalid, but #949 ignores per-input "
                  "shares and computes its own."),
     "blurb": ("Inputs 0 and 1 carry per-input shares and proofs, input 2 has none, yet "
               "the output script is already set. BIP375 says a script needs every "
               "eligible input's share. The script happens to be correct.")},
    {"kind": "sp_input_left_out", "label": "Input left out of the key sum",
     "outcome": "refuse", "screen": _SP_ERROR_SCREEN, "expected": _SP_AT_SIGN,
     "blurb": ("The output script was derived from inputs 0 and 1 only. Bob would scan "
               "with all three inputs and never find the payment, so the coins are lost "
               "to him. #949 derives the script from every eligible input and refuses.")},
    {"kind": "sp_in_v0", "label": "Silent payment in a version 0 psbt", "outcome": "error",
     "screen": _UNKNOWN_QR_SCREEN, "expected": _UNKNOWN_QR,
     "blurb": ("A version 0 psbt with a silent payment output field. BIP375 fields exist "
               "only in version 2, and #949 refuses to read this psbt at all.")},
    {"kind": "sp_info_wrong_length", "label": "Silent payment keys cut short",
     "outcome": "error", "screen": _UNKNOWN_QR_SCREEN, "expected": _UNKNOWN_QR,
     "blurb": ("The output's scan and spend key field is 65 bytes instead of 66. #949 "
               "rejects the psbt as it reads it.")},
    {"kind": "sp_info_invalid_point", "label": "Scan key not on the curve",
     "outcome": "error", "screen": _UNKNOWN_QR_SCREEN, "expected": _UNKNOWN_QR,
     "blurb": ("The output's scan key is 33 bytes that are not a point on secp256k1. #949 "
               "rejects the psbt as it reads it.")},
    {"kind": "sp_fake_change", "label": "Change label on someone else's key",
     "outcome": "spend", "screen": _SPEND_RESULT, "expected": _SPEND,
     "summary_note": ("The table reads the psbt's own change label. The device checks the "
                      "keys and shows this output as a payment."),
     "blurb": ("The second output carries the change label m = 0 and your real scan key, "
               "but an attacker's spend key. A device that trusted the label would hide a "
               "payment to the attacker as change. #949 rebuilds the labeled spend key "
               "from this seed and shows the output as a payment.")},
    {"kind": "sp_tx_modifiable_open", "label": "Scripts set, transaction left open",
     "outcome": "refuse", "screen": _SP_ERROR_SCREEN, "expected": _SP_AT_SIGN,
     "blurb": ("The share, proof and script are all correct, but the inputs and outputs "
               "are still marked modifiable. Adding an input later would change the "
               "derived output, so BIP375 requires them closed once a script is set.")},
    {"kind": "sp_wrong_tweak", "label": "Wrong spend tweak", "outcome": "refuse",
     "screen": _SP_ERROR_SCREEN, "num_inputs": 1, "family": "Taproot",
     "expected": _SP_AT_SIGN,
     "blurb": ("Spends a silent payment you received, but the tweak is off by one, so "
               "your spend key plus the tweak is not the coin's key. #949 checks that "
               "before signing.")},
]


def _make_pr_test(pr, d):
    info = script_types.get(d["script_type"])
    network = d.get("network", "main")
    base_wallet = WALLET_FOR_SCRIPT_TYPE[d["script_type"]]
    wallet = base_wallet if network == "main" else f"{base_wallet}_testnet"
    suffix = "" if network == "main" else "-testnet"
    slug = d["kind"].replace("_", "-")
    return Scenario(
        id=f"test-{pr}-{slug}{suffix}", wallet=wallet, script_type=d["script_type"],
        num_inputs=d.get("num_inputs", DEFAULT_NUM_INPUTS), output_shape="change",
        network=network,
        title=f"{_ICON[d['outcome']]} {d['label']} ({d['family']})",
        blurb=d["blurb"], is_default=False,
        tags=["test", d["label"], info.label],
        pr=pr, attack=d["kind"], load_seed=d.get("load_seed", TEST_VICTIM_SEED),
        expected=d["expected"], expected_screen=d["screen"], outcome=d["outcome"],
        summary_note=d.get("summary_note"),
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
    # PR #1032: output-ownership contradictions and malformed derivation data.
    out.extend(_make_pr_test("1032", d) for d in _PR1032_DEFS)
    # PR #1044: a decoy claim of ours in every placement on a multisig output.
    out.extend(_make_pr_test("1044", d) for d in _PR1044_DEFS)
    # PR #1040: the two fingerprint records for a key must agree.
    out.extend(_make_pr_test("1040", d) for d in _PR1040_DEFS)
    # PR #1046: nested single sig change that leaves out its redeem script.
    out.extend(_make_pr_test("1046", d) for d in _PR1046_DEFS)
    # PR #1047: an input must supply exactly the scripts it commits to. The script
    # type and the family label come from PR1047_CASES so they cannot drift from the
    # psbt each builder produces.
    for d in _PR1047_DEFS:
        script_type = PR1047_CASES[d["kind"]][0]
        out.append(_make_pr_test("1047", dict(
            d, script_type=script_type,
            family=script_types.get(script_type).label)))
    # PR #995: prove each input's amount before any of them is summed.
    out.extend(_make_pr_test("995", d) for d in _PR995_DEFS)
    # PR #1041: outputs may not exceed inputs. One case; the check does not vary by type.
    out.extend(_make_pr_test("1041", d) for d in _PR1041_DEFS)
    # PR #1060: each claim of ours on an input held to the input's script.
    out.extend(_make_pr_test("1060", d) for d in _PR1060_DEFS)
    # PR #1073: change has to come back to a path the inputs' wallet scans.
    out.extend(_make_pr_test("1073", d) for d in _PR1073_DEFS)
    # PR #949: silent payments. Honest ones on both networks, attacks mainnet only.
    from common.sp_psbt import CASES

    def _949(d, network="main"):
        st = CASES[d["kind"]]
        blurb = d["blurb"] if network == "main" else d["blurb"].replace("m/352'/0'", "m/352'/1'")
        return _make_pr_test("949", dict(d, script_type=st, network=network, blurb=blurb,
                                         family=d.get("family", script_types.get(st).label)))
    for d in _PR949_HONEST_DEFS:
        out.extend([_949(d), _949(d, "test")])
    out.extend(_949(d) for d in _PR949_ATTACK_DEFS)
    # Not a PR: what the current dev build does.
    out.extend(_make_pr_test("dev", d) for d in _DEV_DEFS)
    return out
