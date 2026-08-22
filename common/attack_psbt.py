"""Adversarial and malformed PSBTs that exercise SeedSigner's ownership scan.

These reproduce the three conditions SeedSigner PR #1013 ("scan seed ownership")
was written to catch. Each one is a structurally valid PSBT — a coordinator or an
attacker really could hand it to a signer — whose *derivation metadata lies*. The
device only finds out by re-deriving keys from the loaded seed and comparing the
actual key material, which is exactly what the PR added.

    fake_change  A change output pays an attacker but carries a derivation entry
                 naming THIS seed's fingerprint on a key the seed cannot derive.
                 A naive signer counts it as "back to your wallet"; the funds
                 leave. -> PSBTOutputOwnershipClaimError -> "Likely an Attack!"

    bad_input    An input does the same false claim. It gains an attacker nothing
                 (embit refuses to sign it either), so it reads as malformed data
                 rather than an attack. -> PSBTInputOwnershipClaimError ->
                 "Transaction Problem".

    wrong_seed   A perfectly valid PSBT that the loaded seed simply has no key in.
                 The PSBT itself is honest — the mismatch is the operator loading
                 the wrong seed. -> PSBTSeedCannotSignError -> "Seed Can't Sign".
                 There is nothing to forge here: the generator ships an ordinary
                 PSBT and the *scenario* pairs it with a decoy seed (see
                 common/scenarios.py). This module only covers the two forgeries.

The forgery is always the same shape: find the derivation entry that claims the
victim seed's fingerprint and swap its key for one the seed does not own, leaving
the fingerprint and the derivation path untouched. That is the entire trick the
ownership scan defeats — the fingerprint is metadata the file's author chose, so
it can say anything, and only re-derivation settles ownership.

Throwaway keys only; none of this is signable into a broadcastable transaction.
"""
import hashlib

from embit import bip32, script
from embit.networks import NETWORKS
from embit.psbt import DerivationPath

from common import script_types
from common.psbt import (build_psbt, _path_ints, CHANGE_BRANCH, RECEIVE_BRANCH)

# A key nobody in the fixtures owns. Deterministic so builds are reproducible;
# domain-separated so it can never collide with a real fixture seed.
_ATTACKER_ENTROPY = hashlib.sha256(b"btc-datagen-attacker-not-your-key").digest()


def _attacker_pubkey(network: str, branch: int, index: int):
    """An embit PublicKey the fixture seeds provably do not derive."""
    root = bip32.HDKey.from_seed(_ATTACKER_ENTROPY, version=NETWORKS[network]["xprv"])
    return root.derive([branch, index]).to_public().key


def _forged_path(victim, branch: int, index: int) -> list:
    """The derivation path the lie claims: the victim's own account path plus
    branch/index, so it looks exactly like a key this wallet would own."""
    return _path_ints(victim.derivation) + [branch, index]


def _forge_scope_claim(scope, forged_fp: bytes, forged_path: list,
                       attacker_key, is_taproot: bool):
    """Replace whatever entry in `scope` claims `forged_fp` with a lie: the same
    fingerprint and path, but the attacker's key. Single-sig scopes carry exactly
    one entry; a multisig scope carries one per cosigner, and only the victim's is
    rewritten so the others still verify."""
    if is_taproot:
        for pk, (_leaves, dp) in list(scope.taproot_bip32_derivations.items()):
            if dp.fingerprint == forged_fp:
                del scope.taproot_bip32_derivations[pk]
        scope.taproot_bip32_derivations[attacker_key] = (
            [], DerivationPath(forged_fp, forged_path))
        scope.taproot_internal_key = attacker_key
    else:
        for pk, dp in list(scope.bip32_derivations.items()):
            if dp.fingerprint == forged_fp:
                del scope.bip32_derivations[pk]
        scope.bip32_derivations[attacker_key] = DerivationPath(forged_fp, forged_path)


def _change_output_index(psbt) -> int:
    for i, out in enumerate(psbt.outputs):
        if out.bip32_derivations:
            _, dp = next(iter(out.bip32_derivations.items()))
            if dp.derivation[-2] == CHANGE_BRANCH:
                return i
        if out.taproot_bip32_derivations:
            _, (_, dp) = next(iter(out.taproot_bip32_derivations.items()))
            if dp.derivation[-2] == CHANGE_BRANCH:
                return i
    raise ValueError("no change output to forge; build with output_shape='change'")


def forge_fake_change(signers: list, script_type: str, network: str = "main",
                      num_inputs: int = 3, threshold: int = None):
    """Fake-change attack: dress an attacker's output as this wallet's change.

    Single-sig: the whole change output is replaced — its scriptPubKey pays the
    attacker and its lone derivation entry carries the victim's fingerprint, so a
    naive signer shows the amount as change while it is really leaving. Multisig:
    the p2wsh change script is left intact (so the summary still reads as a change
    address) and only the victim cosigner's derivation entry is swapped, which is
    all the ownership scan needs to reject it.
    """
    info = script_types.get(script_type)
    psbt = build_psbt(signers, script_type, num_inputs, "change", threshold=threshold)
    victim = signers[0]
    forged_fp = bytes.fromhex(victim.fingerprint)
    forged_path = _forged_path(victim, CHANGE_BRANCH, 0)

    idx = _change_output_index(psbt)
    out = psbt.outputs[idx]
    attacker_key = _attacker_pubkey(network, CHANGE_BRANCH, 0)

    if info.is_multisig:
        # Keep the real p2wsh change scriptPubKey; poison only our entry.
        _forge_scope_claim(out, forged_fp, forged_path, attacker_key, is_taproot=False)
    elif script_type == "P2TR":
        _forge_scope_claim(out, forged_fp, forged_path, attacker_key, is_taproot=True)
        psbt.tx.vout[idx].script_pubkey = script.p2tr(attacker_key)
    else:
        # P2WPKH / P2SH-P2WPKH / P2PKH: attacker gets a plain p2wpkh output.
        _forge_scope_claim(out, forged_fp, forged_path, attacker_key, is_taproot=False)
        psbt.tx.vout[idx].script_pubkey = script.p2wpkh(attacker_key)

    return psbt


def forge_bad_input(signers: list, script_type: str, network: str = "main",
                    num_inputs: int = 3, threshold: int = None):
    """Malformed input ownership: the first input claims the victim's fingerprint
    on a key the seed does not derive. The scriptPubKey (in witness_utxo) is left
    as the wallet's real input so nothing upstream chokes; only the derivation
    lies. Outputs are honest, so the scan clears them and rejects on the input."""
    info = script_types.get(script_type)
    psbt = build_psbt(signers, script_type, num_inputs, "change", threshold=threshold)
    victim = signers[0]
    forged_fp = bytes.fromhex(victim.fingerprint)
    forged_path = _forged_path(victim, RECEIVE_BRANCH, 0)

    inp = psbt.inputs[0]
    attacker_key = _attacker_pubkey(network, RECEIVE_BRANCH, 0)
    _forge_scope_claim(inp, forged_fp, forged_path, attacker_key,
                       is_taproot=(script_type == "P2TR"))
    return psbt


def build_attack_psbt(kind: str, signers: list, script_type: str,
                      network: str = "main", num_inputs: int = 3,
                      threshold: int = None):
    if kind == "fake_change":
        return forge_fake_change(signers, script_type, network, num_inputs, threshold)
    if kind == "bad_input":
        return forge_bad_input(signers, script_type, network, num_inputs, threshold)
    raise ValueError(f"unknown attack kind: {kind!r}")
