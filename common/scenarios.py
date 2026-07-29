"""The demo transaction matrix.

Static hosting means every PSBT has to exist before anyone loads the page, so
"configurable" is a bounded matrix presented as pickers rather than arbitrary
runtime construction. The matrix is deliberately shaped rather than a full cross
product (which would be ~340 cases, most of them redundant):

  * a **full cross** of all seven script types x all four output shapes at the
    default input count — this is the "what does each wallet type look like"
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
    "full_spend": "Sweeps the whole balance to one external recipient — no change "
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


def _make(script_type, shape, num_inputs, network, is_default=False):
    info = script_types.get(script_type)
    base_wallet = WALLET_FOR_SCRIPT_TYPE[script_type]
    wallet = base_wallet if network == "main" else f"{base_wallet}_testnet"
    suffix = "" if network == "main" else "-testnet"
    sid = f"{base_wallet}-{shape}-{num_inputs}in{suffix}"
    inputs_label = f"{num_inputs} input" + ("s" if num_inputs != 1 else "")
    title = f"{info.label} — {OUTPUT_SHAPE_LABELS[shape]}"
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
