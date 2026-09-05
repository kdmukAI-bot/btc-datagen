"""Adversarial and malformed PSBTs that exercise SeedSigner's ownership scan.

These reproduce the three conditions SeedSigner PR #1013 ("scan seed ownership")
was written to catch. Each one is a structurally valid PSBT, a coordinator or an
attacker really could hand it to a signer, whose *derivation metadata lies*. The
device only finds out by re-deriving keys from the loaded seed and comparing the
actual key material, which is exactly what the PR added.

    fake_change  A change output carries a derivation entry naming THIS seed's
                 fingerprint on a key the seed cannot derive. Single-sig and
                 taproot also repoint the scriptPubKey at the attacker, so the
                 funds leave; multisig keeps the wallet's real change script, so
                 the funds return and only the ownership claim is false. Either
                 way -> PSBTOutputOwnershipClaimError -> "Likely an Attack!"

    bad_input    An input does the same false claim. It gains an attacker nothing
                 (embit refuses to sign it either), so it reads as malformed data
                 rather than an attack. -> PSBTInputOwnershipClaimError ->
                 "Transaction Problem".

    wrong_seed   A perfectly valid PSBT that the loaded seed simply has no key in.
                 The PSBT itself is honest, the mismatch is the operator loading
                 the wrong seed. -> PSBTSeedCannotSignError -> "Seed Can't Sign".
                 There is nothing to forge here: the generator ships an ordinary
                 PSBT and the *scenario* pairs it with a decoy seed (see
                 common/scenarios.py). This module only covers the two forgeries.

The forgery is always the same shape: find the derivation entry that claims the
victim seed's fingerprint and swap its key for one the seed does not own, leaving
the fingerprint and the derivation path untouched. That is the entire trick the
ownership scan defeats, the fingerprint is metadata the file's author chose, so
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

    Single-sig: the whole change output is replaced, its scriptPubKey pays the
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

    # The committed scriptPubKey lives on the output scope; embit's psbt.tx is a
    # property that reassembles the tx from the scopes, so a psbt.tx.vout edit is
    # discarded. The ownership scan keys on the derivation entry either way, but
    # repointing the real scriptPubKey is what makes the funds actually leave.
    if info.is_multisig:
        # Deliberately NOT symmetric with the single-key branches below: keep the
        # wallet's real p2wsh change script and poison only our derivation entry.
        # The funds still come home to the real 2-of-3; what is false is the claim
        # about which key in that script is ours. Isolating the false claim from
        # any fund movement is the whole point of this vector, and it is the case
        # 0.8.7 misses entirely (its descriptor.owns() check tests the script, not
        # the claimed derivation path). Do not "fix" this to repoint the script.
        _forge_scope_claim(out, forged_fp, forged_path, attacker_key, is_taproot=False)
    elif script_type == "P2TR":
        _forge_scope_claim(out, forged_fp, forged_path, attacker_key, is_taproot=True)
        out.script_pubkey = script.p2tr(attacker_key)
    else:
        # P2WPKH / P2SH-P2WPKH / P2PKH: attacker gets a plain p2wpkh output.
        _forge_scope_claim(out, forged_fp, forged_path, attacker_key, is_taproot=False)
        out.script_pubkey = script.p2wpkh(attacker_key)

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


# --- D5 / PR #1032: "verify that change outputs actually pay this seed" -------
#
# Stage C (#1013, above) re-derives every derivation entry that claims our
# fingerprint and rejects a key that does not derive from the seed. It does not
# check that the output's committed scriptPubKey actually pays that key, nor that
# the derivation-path bookkeeping is well formed. D5 closes both gaps: an output
# counts as change only when the script rebuilt from the seed matches the
# scriptPubKey the output commits to, and a psbt whose claims contradict that (or
# whose derivation entries are malformed) is refused. The three refusals map to
# three device screens:
#
#   PSBTOutputOwnershipContradictionError -> PSBTOutputOwnershipContradictionView
#       The psbt's account of who an output pays contradicts the key(s) the output
#       actually commits to. Either it claims our seed on an output that pays
#       someone else, or it pays our seed while claiming someone else (or nobody).
#
#   PSBTSurplusDerivationPathsError -> PSBTSurplusDerivationPathsView
#       An output lists more derivation entries than its script can use: two paths
#       on a single-key output, two internal-key claims on a taproot output, or
#       more paths than a multisig script has keys.
#
#   PSBTMixedDerivationPathTypesError -> PSBTMixedDerivationPathTypesView
#       One scope declares entries in both the ecdsa and the taproot derivation
#       maps; no script type can use both.
#
# These build on a genuine change output from common.psbt and then edit only the
# change output, so the inputs stay honestly this seed's (the signability gate
# passes) and the refusal comes from the output alone. Throwaway keys only.


def _victim_key(victim, branch: int, index: int):
    """The victim seed's own public key at branch/index (a key it really owns)."""
    return victim.account.derive([branch, index]).key


def _attacker_root(network: str):
    return bip32.HDKey.from_seed(_ATTACKER_ENTROPY, version=NETWORKS[network]["xprv"])


def _attacker_fingerprint(network: str) -> bytes:
    """A master fingerprint that is real (a genuine key's) but not any fixture's."""
    return _attacker_root(network).my_fingerprint


def _attacker_multisig_script(network: str, m: int, n: int):
    """An m-of-n sortedmulti script whose keys the fixture seeds do not own."""
    keys = [_attacker_pubkey(network, CHANGE_BRANCH, 100 + i) for i in range(n)]
    keys.sort(key=lambda k: k.sec())
    return script.multisig(m, keys)


def _d5_contradiction_singlesig(signers, network, num_inputs):
    """Claims this seed truthfully, then pays someone else (single-sig).

    The change output keeps its honest derivation entry (our key, our fingerprint,
    our change path), so C's ownership scan is satisfied. Only the scriptPubKey is
    repointed at an attacker key, so the script rebuilt from the seed no longer
    matches what the output commits to -> contradiction.
    """
    psbt = build_psbt(signers, "P2WPKH", num_inputs, "change")
    idx = _change_output_index(psbt)
    attacker_key = _attacker_pubkey(network, CHANGE_BRANCH, 0)
    # The committed scriptPubKey lives on the output scope; embit's psbt.tx is a
    # property that reassembles the tx from these, so a psbt.tx.vout edit is lost.
    psbt.outputs[idx].script_pubkey = script.p2wpkh(attacker_key)
    return psbt


def _d5_contradiction_multisig(signers, network, num_inputs, threshold):
    """Claims this seed, but the committed multisig holds no key of ours.

    The output commits to an attacker's m-of-n (hashed correctly, same shape as
    the wallet), while a single derivation entry annotates it with our fingerprint
    at a path we really own. C passes (the claimed key derives from us); D5 finds
    our key is not in the committed script -> contradiction. This is the headline
    multisig fake-change the PR closes.
    """
    m, n = threshold, len(signers)
    psbt = build_psbt(signers, "P2WSH", num_inputs, "change", threshold=threshold)
    victim = signers[0]
    idx = _change_output_index(psbt)
    out = psbt.outputs[idx]

    attacker_script = _attacker_multisig_script(network, m, n)
    # scriptPubKey lives on the output scope (embit's psbt.tx is a rebuilt copy).
    out.script_pubkey = script.p2wsh(attacker_script)
    out.witness_script = attacker_script
    out.redeem_script = None
    out.bip32_derivations.clear()
    out.bip32_derivations[_victim_key(victim, CHANGE_BRANCH, 0)] = DerivationPath(
        bytes.fromhex(victim.fingerprint), _forged_path(victim, CHANGE_BRANCH, 0))
    return psbt


def _d5_contradiction_multisig_unclaimed(signers, network, num_inputs, threshold):
    """Pays a multisig this seed is in, but hides it behind foreign fingerprints.

    The committed script is the wallet's real change script (our key is in it), but
    every derivation entry is relabelled with a foreign fingerprint, so nothing
    claims our seed. Before D5 that one-field edit dropped the output out of every
    check; D5 derives at each supplied path, finds our key in the committed script,
    and refuses the concealment -> contradiction.
    """
    psbt = build_psbt(signers, "P2WSH", num_inputs, "change", threshold=threshold)
    idx = _change_output_index(psbt)
    out = psbt.outputs[idx]
    forged_fp = _attacker_fingerprint(network)
    for pk in list(out.bip32_derivations):
        dp = out.bip32_derivations[pk]
        out.bip32_derivations[pk] = DerivationPath(forged_fp, dp.derivation)
    return psbt


def _d5_surplus_singlesig(signers, network, num_inputs):
    """A single-key output that lists two derivation paths.

    Both entries are honest keys of ours (so C passes), which is enough to trip the
    single-key surplus check: one script, one key, cannot own two paths.
    """
    psbt = build_psbt(signers, "P2WPKH", num_inputs, "change")
    victim = signers[0]
    idx = _change_output_index(psbt)
    out = psbt.outputs[idx]
    out.bip32_derivations[_victim_key(victim, RECEIVE_BRANCH, 0)] = DerivationPath(
        bytes.fromhex(victim.fingerprint), _forged_path(victim, RECEIVE_BRANCH, 0))
    return psbt


def _d5_surplus_multisig(signers, network, num_inputs, threshold):
    """A multisig change output that lists more paths than its script has keys.

    The real change output is confirmed ours, then one extra derivation entry (a
    foreign fingerprint, so C skips it and the real entry stays the verified one)
    pushes the entry count past n -> surplus.
    """
    psbt = build_psbt(signers, "P2WSH", num_inputs, "change", threshold=threshold)
    victim = signers[0]
    idx = _change_output_index(psbt)
    out = psbt.outputs[idx]
    out.bip32_derivations[_attacker_pubkey(network, RECEIVE_BRANCH, 7)] = DerivationPath(
        _attacker_fingerprint(network), _forged_path(victim, RECEIVE_BRANCH, 7))
    return psbt


def _d5_surplus_taproot(signers, network, num_inputs):
    """A taproot output claiming two internal keys.

    A taproot output has exactly one internal key. A second internal-key entry
    (empty leaf hashes), again an honest key of ours so C passes, trips the taproot
    surplus check.
    """
    psbt = build_psbt(signers, "P2TR", num_inputs, "change")
    victim = signers[0]
    idx = _change_output_index(psbt)
    out = psbt.outputs[idx]
    out.taproot_bip32_derivations[_victim_key(victim, RECEIVE_BRANCH, 0)] = (
        [], DerivationPath(bytes.fromhex(victim.fingerprint),
                           _forged_path(victim, RECEIVE_BRANCH, 0)))
    return psbt


def _d5_mixed_types(signers, network, num_inputs):
    """One output scope declaring both an ecdsa and a taproot derivation entry.

    The p2wpkh change keeps its ecdsa entry; a taproot entry (foreign fingerprint,
    so the scan skips ownership and reaches the structural refusal) is added
    alongside it. No script type can use both maps -> mixed-types refusal.
    """
    psbt = build_psbt(signers, "P2WPKH", num_inputs, "change")
    idx = _change_output_index(psbt)
    out = psbt.outputs[idx]
    out.taproot_bip32_derivations[_attacker_pubkey(network, RECEIVE_BRANCH, 3)] = (
        [], DerivationPath(_attacker_fingerprint(network),
                           _forged_path(signers[0], RECEIVE_BRANCH, 3)))
    return psbt


_D5_BUILDERS = {
    "contradiction_singlesig": _d5_contradiction_singlesig,
    "contradiction_multisig": _d5_contradiction_multisig,
    "contradiction_multisig_unclaimed": _d5_contradiction_multisig_unclaimed,
    "surplus_singlesig": _d5_surplus_singlesig,
    "surplus_multisig": _d5_surplus_multisig,
    "surplus_taproot": _d5_surplus_taproot,
    "mixed_types": _d5_mixed_types,
}

# Kinds that need the wallet threshold passed through (multisig builders).
_D5_MULTISIG_KINDS = {"contradiction_multisig", "contradiction_multisig_unclaimed",
                      "surplus_multisig"}


def build_d5_psbt(kind: str, signers: list, script_type: str,
                  network: str = "main", num_inputs: int = 3, threshold: int = None):
    builder = _D5_BUILDERS.get(kind)
    if builder is None:
        raise ValueError(f"unknown D5 kind: {kind!r}")
    if kind in _D5_MULTISIG_KINDS:
        return builder(signers, network, num_inputs, threshold)
    return builder(signers, network, num_inputs)
