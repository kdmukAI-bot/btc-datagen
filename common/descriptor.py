"""Descriptor text + UR `crypto-output` construction for all seven script types.

Produces output identical to what Sparrow Wallet emits. See
docs/knowledge/sparrow-qr-formats.md.

A note on the multisig tag, because getting it wrong is silent and expensive:
`crypto-output` tag **406 is `multi`** (keys in the given order) and **407 is
`sortedmulti`** (keys sorted lexicographically). The two derive DIFFERENT
addresses from the same key set, so a descriptor QR tagged `multi` will import a
wallet whose addresses don't match a PSBT built with sorted keys. Sparrow —
and `common/psbt.py`, which sorts — mean `sortedmulti`, i.e. 407.
"""
from urtypes.crypto import Account, Output, MultiKey, SCRIPT_EXPRESSION_TAG_MAP

from common import script_types
from common.ur2.ur import UR
from common.ur2.ur_encoder import UREncoder

# Sparrow PdfUtils uses UREncoder(ur, 2000, 10, 0): single part for any descriptor.
SPARROW_DESCRIPTOR_MAX_FRAGMENT = 2000

# Descriptor expression wrappers, innermost payload substituted for {}.
_DESCRIPTOR_TEMPLATES = {
    "P2WPKH": "wpkh({})",
    "P2SH-P2WPKH": "sh(wpkh({}))",
    "P2TR": "tr({})",
    "P2PKH": "pkh({})",
    "P2WSH": "wsh(sortedmulti({}))",
    "P2SH-P2WSH": "sh(wsh(sortedmulti({})))",
    "P2SH": "sh(sortedmulti({}))",
}

# Each cosigner key expression gets the standard receive/change multipath suffix.
KEY_SUFFIX = "/<0;1>/*"


def output_descriptor(signers: list, script_type: str, threshold: int = None) -> Output:
    """Build the urtypes Output (the `crypto-output` payload) for a wallet."""
    info = script_types.get(script_type)
    expressions = [SCRIPT_EXPRESSION_TAG_MAP[t] for t in info.ur_tags]
    if info.is_multisig:
        if threshold is None:
            raise ValueError(f"{script_type} is multisig; a threshold is required")
        key = MultiKey(threshold, ec_keys=[], hd_keys=[s.hdkey for s in signers])
    else:
        if len(signers) != 1:
            raise ValueError(f"{script_type} is single sig; got {len(signers)} signers")
        key = signers[0].hdkey
    return Output(expressions, key)


def descriptor_text(threshold, signers: list, script_type: str) -> str:
    """Plain-text output descriptor (no checksum), Sparrow style."""
    info = script_types.get(script_type)
    keys = ",".join(s.key_expression + KEY_SUFFIX for s in signers)
    inner = f"{threshold},{keys}" if info.is_multisig else keys
    return _DESCRIPTOR_TEMPLATES[script_type].format(inner)


def crypto_output_ur(threshold, signers: list, script_type: str) -> str:
    """Single-part ur:crypto-output/... string (Sparrow PDF-backup payload)."""
    output = output_descriptor(signers, script_type, threshold)
    ur = UR("crypto-output", output.to_cbor())
    encoder = UREncoder(ur, SPARROW_DESCRIPTOR_MAX_FRAGMENT, 0, 10)
    if not encoder.is_single_part():
        raise ValueError("descriptor did not fit in a single UR part")
    return encoder.next_part()


def crypto_account_ur(threshold, signers: list, script_type: str) -> str:
    """Single-part ur:crypto-account/... carrying the same output descriptor.

    SeedSigner imports a wallet descriptor from EITHER `crypto-output` or
    `crypto-account` — see `get_wallet_descriptor()` in its `models/decode_qr.py`,
    which for the account type takes `output_descriptors[0]`. The two types have
    different intents (`crypto-account` is really a signer exporting its own
    accounts to a coordinator, which is also what SeedSigner's own xpub export
    emits), but since a demo just needs the descriptor to land on the device, we
    publish both and let the site choose.

    The account's master fingerprint is the first signer's, which is the only
    sensible choice for a multisig wallet that has no single master key.
    """
    output = output_descriptor(signers, script_type, threshold)
    account = Account(bytes.fromhex(signers[0].fingerprint), [output])
    ur = UR("crypto-account", account.to_cbor())
    encoder = UREncoder(ur, SPARROW_DESCRIPTOR_MAX_FRAGMENT, 0, 10)
    if not encoder.is_single_part():
        raise ValueError("account descriptor did not fit in a single UR part")
    return encoder.next_part()


def expected_output_tags(script_type: str) -> list:
    return list(script_types.get(script_type).ur_tags)


# Back-compat alias: the original API was multisig-only.
def multisig_output(threshold: int, cosigners: list, script_type: str = "P2WSH") -> Output:
    return output_descriptor(cosigners, script_type, threshold)
