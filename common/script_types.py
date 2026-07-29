"""The seven wallet script types SeedSigner can sign for, in one table.

SeedSigner's supported matrix is sig type x script type (see its
`models/settings_definition.py` SINGLE_SIG/MULTISIG and LEGACY_P2PKH /
NATIVE_SEGWIT / NESTED_SEGWIT / TAPROOT). This module is the single source of
truth for everything that varies between them: the account derivation path, the
descriptor expression, and the `crypto-output` script-expression tag stack.

Derivation paths follow the usual standards — BIP44/49/84/86 for single sig,
BIP48 for segwit multisig, and the pre-BIP48 `m/45h` convention for legacy P2SH
multisig (which is what Sparrow emits).
"""
from dataclasses import dataclass

SINGLE_SIG = "single-sig"
MULTISIG = "multisig"

# crypto-output script-expression tags (BCR-2020-010 / urtypes SCRIPT_EXPRESSION_TAG_MAP),
# outermost first. NOTE: 406 is `multi` and 407 is `sortedmulti` — they are NOT
# interchangeable. `multi` preserves the given key order while `sortedmulti`
# sorts lexicographically, so the two derive DIFFERENT addresses from the same
# keys. Sparrow emits sortedmulti; so do we.
TAG_SH = 400
TAG_WSH = 401
TAG_PKH = 403
TAG_WPKH = 404
TAG_SORTEDMULTI = 407
TAG_TR = 409


@dataclass(frozen=True)
class ScriptType:
    name: str            # canonical key, e.g. "P2WPKH"
    label: str           # human label, e.g. "Native SegWit"
    sig_type: str        # SINGLE_SIG | MULTISIG
    derivation: str      # account path template; {coin} -> 0 (main) or 1 (test)
    ur_tags: tuple       # crypto-output script expression tag stack
    segwit: bool         # spends via witness -> witness_utxo, else non_witness_utxo
    nested: bool         # wrapped in P2SH -> needs redeem_script

    @property
    def is_multisig(self) -> bool:
        return self.sig_type == MULTISIG


SCRIPT_TYPES = {s.name: s for s in [
    # --- single sig ---------------------------------------------------------
    ScriptType("P2WPKH", "Native SegWit", SINGLE_SIG,
               "m/84h/{coin}h/0h", (TAG_WPKH,), segwit=True, nested=False),
    ScriptType("P2SH-P2WPKH", "Nested SegWit", SINGLE_SIG,
               "m/49h/{coin}h/0h", (TAG_SH, TAG_WPKH), segwit=True, nested=True),
    ScriptType("P2TR", "Taproot", SINGLE_SIG,
               "m/86h/{coin}h/0h", (TAG_TR,), segwit=True, nested=False),
    ScriptType("P2PKH", "Legacy", SINGLE_SIG,
               "m/44h/{coin}h/0h", (TAG_PKH,), segwit=False, nested=False),
    # --- multisig -----------------------------------------------------------
    ScriptType("P2WSH", "Native SegWit multisig", MULTISIG,
               "m/48h/{coin}h/0h/2h", (TAG_WSH, TAG_SORTEDMULTI), segwit=True, nested=False),
    ScriptType("P2SH-P2WSH", "Nested SegWit multisig", MULTISIG,
               "m/48h/{coin}h/0h/1h", (TAG_SH, TAG_WSH, TAG_SORTEDMULTI), segwit=True, nested=True),
    ScriptType("P2SH", "Legacy multisig", MULTISIG,
               "m/45h", (TAG_SH, TAG_SORTEDMULTI), segwit=False, nested=True),
]}

SINGLE_SIG_TYPES = [s.name for s in SCRIPT_TYPES.values() if s.sig_type == SINGLE_SIG]
MULTISIG_TYPES = [s.name for s in SCRIPT_TYPES.values() if s.sig_type == MULTISIG]

COIN_TYPE = {"main": 0, "test": 1}


def get(script_type: str) -> ScriptType:
    try:
        return SCRIPT_TYPES[script_type]
    except KeyError:
        raise ValueError(f"unsupported script_type: {script_type!r}. "
                         f"expected one of {', '.join(SCRIPT_TYPES)}")


def derivation_for(script_type: str, network: str = "main") -> str:
    """Account derivation path for this script type on this network."""
    return get(script_type).derivation.format(coin=COIN_TYPE[network])
