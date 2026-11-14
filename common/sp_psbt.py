"""Silent payment psbts (BIP375 sends, BIP376 spends) for the PR #949 test group.

embit 0.8.0 knows PSBTv2 but none of the SP fields, so every SP field travels as
a raw key in a scope's `unknown` dict. They round-trip byte-identical. embit
0.8.0 shares ONE default `unknown={}` dict between scopes built without one, so
set_field() always replaces the dict instead of writing into it.

`audit()` rederives everything a verifier can from the psbt's own fields plus
the sender's seed, and names each place the psbt disagrees. Builders and
tools/verify.py both hold a scenario to EXPECTED_FINDINGS through it.
"""
import hashlib

from embit import bip32, bip39
from embit.networks import NETWORKS
from embit.psbt import OutputScope
from embit.script import Script

from common import silent_payments as sp
from common.fixtures import load_seeds, load_sp_wallets
from common.psbt import CHANGE_BRANCH, FEE, _external_spk, _ScriptContext, build_psbt

SENDER = "alice"
EXT = ("external",)
CHG = ("change",)


# --- raw fields ------------------------------------------------------------------

def set_field(scope, key: bytes, value: bytes):
    scope.unknown = dict(scope.unknown)
    scope.unknown[key] = value


def del_field(scope, key: bytes):
    scope.unknown = {k: v for k, v in scope.unknown.items() if k != key}


def get_field(scope, t: int):
    return scope.unknown.get(bytes([t]))


def fields(scope, t: int) -> dict:
    return {k[1:]: v for k, v in scope.unknown.items() if len(k) > 1 and k[0] == t}


def to_v2(psbt):
    psbt.version, psbt.tx_version, psbt.locktime = 2, 2, 0
    return psbt


# --- keys ------------------------------------------------------------------------

def sender_root(network: str):
    mnemonic = load_seeds()[SENDER]["mnemonic"]
    return bip32.HDKey.from_seed(bip39.mnemonic_to_seed(mnemonic),
                                 version=NETWORKS[network]["xprv"])


def recipient(who: str, network: str, m=None, label=False):
    """An output spec paying `who`'s sp address, or its label m. `label=True`
    also writes PSBT_OUT_SP_V0_LABEL, which BIP375 only uses for your own change."""
    w = load_sp_wallets()[who if network == "main" else f"{who}_testnet"]
    B_m = w["spend_pub"] if m is None else next(l["spend_pub"] for l in w["labels"] if l["m"] == m)
    return ("sp", bytes.fromhex(w["scan_pub"]), bytes.fromhex(B_m), m if label else None)


# --- outputs ---------------------------------------------------------------------

def set_sp_info(out, B_scan: bytes, B_m: bytes, label=None):
    out.script_pubkey = None                 # BIP375: computed later from the shares
    set_field(out, bytes([sp.PSBT_OUT_SP_V0_INFO]), B_scan + B_m)
    if label is not None:
        set_field(out, bytes([sp.PSBT_OUT_SP_V0_LABEL]), label.to_bytes(4, "little"))


def set_outputs(psbt, signers, script_type, network, specs):
    """Replace a v2 psbt's outputs. Change takes a third of what is spendable and
    the payees split the rest, the first one taking the remainder, the same split
    common.psbt.build_psbt uses."""
    spendable = sum(inp.utxo.value for inp in psbt.inputs) - FEE
    has_change = CHG in specs
    change_value = spendable // 3 if has_change else 0
    payees = len(specs) - (1 if has_change else 0)
    per = (spendable - change_value) // payees
    rem = spendable - change_value - per * payees
    outs, ext = [], 0
    for spec in specs:
        out = OutputScope()
        out.unknown = {}
        if spec == CHG:
            ctx = _ScriptContext(signers, None, script_type, CHANGE_BRANCH, 0)
            out.value, out.script_pubkey = change_value, ctx.script_pubkey
            ctx.apply_to_output(out)
        else:
            out.value = per + (rem if not outs else 0)
            if spec == EXT:
                out.script_pubkey = _external_spk(signers, ext)
                ext += 1
            else:
                _, B_scan, B_m, label = spec
                set_sp_info(out, B_scan, B_m, label)
        outs.append(out)
    psbt.outputs = outs


def pay(signers, network, n, specs=None, script_type="P2WPKH"):
    """n inputs of the sender's wallet paying bob's sp address plus change,
    unless `specs` says otherwise."""
    psbt = to_v2(build_psbt(signers, script_type, n, "full_spend"))
    set_outputs(psbt, signers, script_type, network,
                specs or [recipient("bob", network), CHG])
    return psbt


def sp_outputs(psbt) -> list:
    """[(output index, B_scan, B_m, label or None)] for well-formed SP outputs."""
    res = []
    for i, out in enumerate(psbt.outputs):
        info = get_field(out, sp.PSBT_OUT_SP_V0_INFO)
        if info is None or len(info) != 66 or not (sp.is_point(info[:33]) and sp.is_point(info[33:])):
            continue
        lab = get_field(out, sp.PSBT_OUT_SP_V0_LABEL)
        res.append((i, info[:33], info[33:], None if lab is None else int.from_bytes(lab, "little")))
    return res


def output_kind(out) -> str:
    """What the psbt claims about an SP output: a PSBT_OUT_SP_V0_LABEL marks it as
    ours (0 is the change label), no label means a payment out."""
    lab = get_field(out, sp.PSBT_OUT_SP_V0_LABEL)
    if lab is None:
        return "external"
    return "change" if int.from_bytes(lab, "little") == 0 else "self_transfer"


def output_address(out, network: str) -> str:
    info = get_field(out, sp.PSBT_OUT_SP_V0_INFO)
    try:
        return sp.encode_address(info[:33], info[33:], network) if len(info) == 66 else info.hex()
    except Exception:
        return info.hex()


# --- the sender's side (what a single signer computes) ------------------------

def outpoints(psbt) -> list:
    return [sp.outpoint_bytes(inp.txid, inp.vout) for inp in psbt.inputs]


def A_sum(psbt):
    return sp.point_add(*[p for p in map(sp.psbt_input_pubkey, psbt.inputs) if p])


def input_privkeys(psbt, root) -> list:
    """(private key, is_taproot) of every eligible input, from its own derivation."""
    keys = []
    for inp in psbt.inputs:
        if sp.psbt_input_pubkey(inp) is None:
            continue
        if inp.taproot_bip32_derivations:
            (_leaves, der), = inp.taproot_bip32_derivations.values()
            key = root.derive(der.derivation).key.taproot_tweak(b"")
            keys.append((int.from_bytes(key.secret, "big"), True))
        else:
            der, = inp.bip32_derivations.values()
            keys.append((int.from_bytes(root.derive(der.derivation).key.secret, "big"), False))
    return keys


def derive_scripts(psbt, shares: dict, A=None) -> dict:
    """BIP375 "Computing the Output Scripts": per scan key, ecdh = input_hash*share,
    with codes sharing a scan key sorted by spend key, then output index, for k."""
    ih = sp.input_hash(outpoints(psbt), A or A_sum(psbt))
    groups = {}
    for idx, B_scan, B_m, _ in sp_outputs(psbt):
        groups.setdefault(B_scan, []).append((B_m, idx))
    scripts = {}
    for B_scan, members in groups.items():
        members.sort()
        keys = sp.output_keys(sp.point_mul(shares[B_scan], ih), [m for m, _ in members])
        for (_, idx), x in zip(members, keys):
            scripts[idx] = b"\x51\x20" + x
    return scripts


def set_scripts(psbt, shares: dict, A=None):
    for idx, s in derive_scripts(psbt, shares, A).items():
        psbt.outputs[idx].script_pubkey = Script(s)
    # BIP375 Signer: setting PSBT_OUT_SCRIPT clears Inputs and Outputs Modifiable.
    set_field(psbt, bytes([sp.PSBT_GLOBAL_TX_MODIFIABLE]), b"\x00")


def fill_global(psbt, root, aux: bytes) -> int:
    """What #949 writes for a single signer: a global ECDH share and DLEQ proof
    per scan key (BIP375 "Computing the ECDH Shares and DLEQ Proofs"), plus the
    output scripts. Returns a_sum."""
    a = sp.a_sum(input_privkeys(psbt, root))
    shares = {B: sp.point_mul(B, a) for _, B, _, _ in sp_outputs(psbt)}
    for B, C in shares.items():
        set_field(psbt, bytes([sp.PSBT_GLOBAL_SP_ECDH_SHARE]) + B, C)
        set_field(psbt, bytes([sp.PSBT_GLOBAL_SP_DLEQ]) + B, sp.dleq_prove(a, B, aux))
    set_scripts(psbt, shares)
    return a


def fill_per_input(psbt, root, aux: bytes, skip=()):
    """Per-input ECDH shares and proofs, as a multi-party signer would write them."""
    scans = {B for _, B, _, _ in sp_outputs(psbt)}
    privs = iter(input_privkeys(psbt, root))
    for i, inp in enumerate(psbt.inputs):
        if sp.psbt_input_pubkey(inp) is None:
            continue
        a_i = sp.a_sum([next(privs)])
        if i in skip:
            continue
        for B in scans:
            set_field(inp, bytes([sp.PSBT_IN_SP_ECDH_SHARE]) + B, sp.point_mul(B, a_i))
            set_field(inp, bytes([sp.PSBT_IN_SP_DLEQ]) + B, sp.dleq_prove(a_i, B, aux))


def aux_for(kind: str) -> bytes:
    """Deterministic BIP374 aux randomness, one per scenario kind."""
    return hashlib.sha256(b"btc-datagen/sp-aux/" + kind.encode()).digest()


# --- audit -----------------------------------------------------------------------

def _audit_spends(psbt, keys) -> list:
    """BIP376: the spend key must be ours and B_spend + tweak*G the output key."""
    found = []
    for i, inp in enumerate(psbt.inputs):
        tweak = get_field(inp, sp.PSBT_IN_SP_TWEAK)
        if tweak is None:
            continue
        for B_spend in fields(inp, sp.PSBT_IN_SP_SPEND_BIP32_DERIVATION):
            if B_spend != keys["B_spend"]:
                found.append(f"spend-key-not-ours:{i}")
            P = sp.point_add(B_spend, sp.base_mul(int.from_bytes(tweak, "big")))
            if P is None or P[1:] != inp.utxo.script_pubkey.data[2:]:
                found.append(f"tweak-mismatch:{i}")
    return found


def audit(psbt, root, network: str) -> list:
    """Every way this psbt disagrees with what the sender's seed derives. [] for
    an honest psbt. Codes: v0-with-sp, info-length, info-point, a-sum-mismatch,
    share-extra, share-wrong, dleq-missing, dleq-invalid, in-share-missing,
    in-share-wrong, in-dleq-invalid, script-wrong, tx-modifiable-open,
    label-not-ours, spend-key-not-ours, tweak-mismatch (":i" = input/output index)."""
    keys = sp.wallet_keys(root, network)
    found = _audit_spends(psbt, keys)
    for i, out in enumerate(psbt.outputs):
        info = get_field(out, sp.PSBT_OUT_SP_V0_INFO)
        if info is None:
            continue
        if psbt.version != 2:
            found.append(f"v0-with-sp:{i}")
        elif len(info) != 66:
            found.append(f"info-length:{i}")
        elif not (sp.is_point(info[:33]) and sp.is_point(info[33:])):
            found.append(f"info-point:{i}")
    outs = sp_outputs(psbt)
    if psbt.version != 2 or not outs:
        return sorted(found)

    privs = input_privkeys(psbt, root)
    a, A = sp.a_sum(privs), A_sum(psbt)
    if sp.base_mul(a) != A:
        found.append("a-sum-mismatch")
    shares = {B: sp.point_mul(B, a) for _, B, _, _ in outs}

    proofs = fields(psbt, sp.PSBT_GLOBAL_SP_DLEQ)
    for B, C in fields(psbt, sp.PSBT_GLOBAL_SP_ECDH_SHARE).items():
        if B not in shares:
            found.append("share-extra")
            continue
        if C != shares[B]:
            found.append("share-wrong")
        if B not in proofs:
            found.append("dleq-missing")
        elif not sp.dleq_verify(A, B, C, proofs[B]):
            found.append("dleq-invalid")

    eligible = [i for i, inp in enumerate(psbt.inputs) if sp.psbt_input_pubkey(inp)]
    if any(fields(psbt.inputs[i], sp.PSBT_IN_SP_ECDH_SHARE) for i in eligible):
        for i, priv in zip(eligible, privs):
            a_i = sp.a_sum([priv])
            in_shares = fields(psbt.inputs[i], sp.PSBT_IN_SP_ECDH_SHARE)
            in_proofs = fields(psbt.inputs[i], sp.PSBT_IN_SP_DLEQ)
            for B in shares:
                C_i = in_shares.get(B)
                if C_i is None:
                    found.append(f"in-share-missing:{i}")
                    continue
                if C_i != sp.point_mul(B, a_i):
                    found.append(f"in-share-wrong:{i}")
                if B not in in_proofs or not sp.dleq_verify(sp.base_mul(a_i), B, C_i, in_proofs[B]):
                    found.append(f"in-dleq-invalid:{i}")

    derived, declared = derive_scripts(psbt, shares), False
    for i, _, _, _ in outs:
        spk = psbt.outputs[i].script_pubkey
        if spk is not None:
            declared = True
            if spk.data != derived[i]:
                found.append(f"script-wrong:{i}")
    flags = psbt.unknown.get(bytes([sp.PSBT_GLOBAL_TX_MODIFIABLE]))
    if declared and flags is not None and flags[0] & 0x03:
        found.append("tx-modifiable-open")

    for i, B_scan, B_m, m in outs:
        if m is not None and (B_scan != keys["B_scan"] or
                              B_m != sp.labeled_spend_key(keys["B_spend"], keys["b_scan"], m)):
            found.append(f"label-not-ours:{i}")
    return sorted(found)
