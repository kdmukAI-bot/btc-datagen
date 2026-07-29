"""Build valid, signable PSBTs for every script type SeedSigner supports.

Synthetic UTXOs only. Each input is funded by a **real, fully-formed fake
funding transaction** that we build first and then reference by its actual txid,
because legacy (non-segwit) inputs carry `non_witness_utxo` — the whole previous
transaction — and both embit and SeedSigner check that it hashes to the input's
prevout txid. Segwit inputs only need `witness_utxo`, which keeps large PSBTs
manageable (a 100-input legacy PSBT would be enormous, which is realistic but
not useful).

Nothing here is ever broadcast and none of these UTXOs exist on any chain; the
goal is only to be structurally realistic enough that a signer treats it like
the real thing. Throwaway keys only.

Two constraints worth knowing:
  * Inputs are homogeneous. SeedSigner raises "Mixed inputs in the transaction"
    if input policies differ within one PSBT.
  * Multisig uses sortedmulti (keys sorted lexicographically per input), which
    must match the descriptor's `sortedmulti` — see common/descriptor.py.
"""
import hashlib

from embit import script
from embit.psbt import PSBT, DerivationPath
from embit.transaction import Transaction, TransactionInput, TransactionOutput

from common import script_types

IN_VALUE = 100_000          # sats per synthetic input
FEE = 10_000                # flat network fee for every scenario

RECEIVE_BRANCH = 0
CHANGE_BRANCH = 1

# Output shapes. Each entry lists what the transaction pays to, in order.
#   external      -> a third-party recipient (no derivation info in the PSBT)
#   change        -> back to this wallet on the change branch
#   self_transfer -> back to this wallet on the RECEIVE branch (not change!)
OUTPUT_SHAPES = {
    "change": ["external", "change"],
    "full_spend": ["external"],
    "self_transfer": ["self_transfer", "change"],
    "multi_recipient": ["external", "external", "external", "change"],
}


def _path_ints(path: str) -> list:
    out = []
    for element in path.split("/"):
        if element in ("m", ""):
            continue
        hardened = element[-1] in ("h", "'")
        index = int(element[:-1]) if hardened else int(element)
        out.append(index | 0x80000000 if hardened else index)
    return out


def _derivations(signers: list, branch: int, index: int) -> dict:
    """{pubkey: DerivationPath} for every signer at branch/index."""
    out = {}
    for s in signers:
        pk = s.account.derive([branch, index]).key
        out[pk] = DerivationPath(bytes.fromhex(s.fingerprint),
                                 _path_ints(s.derivation) + [branch, index])
    return out


class _ScriptContext:
    """Everything needed to spend from (or pay to) one address of a wallet.

    Attributes: script_pubkey, witness_script, redeem_script, derivations,
    and for taproot the internal key.
    """

    def __init__(self, signers, threshold, script_type, branch, index):
        info = script_types.get(script_type)
        self.info = info
        self.derivations = _derivations(signers, branch, index)
        self.witness_script = None
        self.redeem_script = None
        self.internal_key = None

        pubkeys = list(self.derivations)
        if info.is_multisig:
            pubkeys.sort(key=lambda p: p.serialize())      # sortedmulti
            self.witness_script = script.multisig(threshold, pubkeys)
            self._build_multisig_spk(script_type)
        else:
            self._build_singlesig_spk(script_type, pubkeys[0])

    def _build_multisig_spk(self, script_type):
        if script_type == "P2WSH":
            self.script_pubkey = script.p2wsh(self.witness_script)
        elif script_type == "P2SH-P2WSH":
            self.redeem_script = script.p2wsh(self.witness_script)
            self.script_pubkey = script.p2sh(self.redeem_script)
        elif script_type == "P2SH":
            # Legacy P2SH multisig: the multisig script IS the redeem script.
            self.redeem_script = self.witness_script
            self.witness_script = None
            self.script_pubkey = script.p2sh(self.redeem_script)
        else:
            raise ValueError(f"not a multisig script type: {script_type}")

    def _build_singlesig_spk(self, script_type, pubkey):
        if script_type == "P2WPKH":
            self.script_pubkey = script.p2wpkh(pubkey)
        elif script_type == "P2SH-P2WPKH":
            self.redeem_script = script.p2wpkh(pubkey)
            self.script_pubkey = script.p2sh(self.redeem_script)
        elif script_type == "P2PKH":
            self.script_pubkey = script.p2pkh(pubkey)
        elif script_type == "P2TR":
            # embit's p2tr() applies the BIP86 key tweak; the PSBT carries the
            # UNtweaked internal key plus taproot derivations.
            self.internal_key = pubkey
            self.script_pubkey = script.p2tr(pubkey)
        else:
            raise ValueError(f"not a single-sig script type: {script_type}")

    def apply_to_input(self, inp, value: int, funding_tx: Transaction):
        if self.info.segwit:
            inp.witness_utxo = TransactionOutput(value, self.script_pubkey)
        else:
            inp.non_witness_utxo = funding_tx
        if self.witness_script is not None:
            inp.witness_script = self.witness_script
        if self.redeem_script is not None:
            inp.redeem_script = self.redeem_script
        self._apply_derivations(inp)

    def apply_to_output(self, out):
        if self.witness_script is not None:
            out.witness_script = self.witness_script
        if self.redeem_script is not None:
            out.redeem_script = self.redeem_script
        self._apply_derivations(out)

    def _apply_derivations(self, scope):
        if self.internal_key is not None:
            scope.taproot_internal_key = self.internal_key
            for pk, dp in self.derivations.items():
                # (leaf_hashes, derivation) — empty leaf hashes for key-path spends
                scope.taproot_bip32_derivations[pk] = ([], dp)
        else:
            for pk, dp in self.derivations.items():
                scope.bip32_derivations[pk] = dp


def _funding_tx(ctx: _ScriptContext, value: int, nonce: int) -> Transaction:
    """A plausible previous transaction paying `value` to ctx at vout 0.

    Deterministic and self-consistent: its txid is computed from its own bytes,
    so `non_witness_utxo` validates. Its own input is an arbitrary fake outpoint
    — nothing walks further back than one level.
    """
    prev_txid = hashlib.sha256(b"btc-datagen-funding" + nonce.to_bytes(4, "big")).digest()
    return Transaction(
        vin=[TransactionInput(prev_txid, 0)],
        vout=[
            TransactionOutput(value, ctx.script_pubkey),
            # A second output makes the funding tx look like an ordinary payment
            # rather than an exact-value gift.
            TransactionOutput(value * 3, script.p2wpkh(list(ctx.derivations)[0])),
        ],
    )


def _external_spk(signers: list, seq: int):
    """A third-party recipient script with no derivation info in the PSBT.

    Derived from a signer's key at an absurd index purely so it's deterministic;
    the PSBT carries no derivation for it, so a signer sees it as external.
    """
    return script.p2wpkh(signers[0].account.derive([RECEIVE_BRANCH, 900_000 + seq]).key)


def build_psbt(signers: list, script_type: str, num_inputs: int = 3,
               output_shape: str = "change", threshold: int = None) -> PSBT:
    """Build one signable PSBT.

    signers      -- Signer/Cosigner list (exactly one for single sig)
    script_type  -- any key of common.script_types.SCRIPT_TYPES
    num_inputs   -- how many synthetic UTXOs to spend
    output_shape -- key of OUTPUT_SHAPES
    threshold    -- required for multisig
    """
    info = script_types.get(script_type)
    if output_shape not in OUTPUT_SHAPES:
        raise ValueError(f"unknown output_shape: {output_shape!r}. "
                         f"expected one of {', '.join(OUTPUT_SHAPES)}")
    if info.is_multisig and threshold is None:
        raise ValueError(f"{script_type} is multisig; a threshold is required")

    # --- inputs -------------------------------------------------------------
    vin, input_ctx, funding = [], [], []
    for i in range(num_inputs):
        ctx = _ScriptContext(signers, threshold, script_type, RECEIVE_BRANCH, i)
        tx = _funding_tx(ctx, IN_VALUE, i)
        vin.append(TransactionInput(bytes.fromhex(tx.txid().hex()), 0))
        input_ctx.append(ctx)
        funding.append(tx)

    total_in = num_inputs * IN_VALUE
    spendable = total_in - FEE

    # --- outputs ------------------------------------------------------------
    shape = OUTPUT_SHAPES[output_shape]
    has_change = "change" in shape
    # Change takes a third of the spendable amount; the rest is split evenly
    # across the non-change outputs. With no change, everything is spent.
    change_value = spendable // 3 if has_change else 0
    payees = [kind for kind in shape if kind != "change"]
    per_payee = (spendable - change_value) // len(payees)
    remainder = (spendable - change_value) - per_payee * len(payees)

    vout, output_ctx, external_seq = [], [], 0
    for kind in shape:
        if kind == "change":
            ctx = _ScriptContext(signers, threshold, script_type, CHANGE_BRANCH, 0)
            vout.append(TransactionOutput(change_value, ctx.script_pubkey))
            output_ctx.append(ctx)
        elif kind == "self_transfer":
            # Own wallet, receive branch — a self-send, distinct from change.
            ctx = _ScriptContext(signers, threshold, script_type, RECEIVE_BRANCH, 500)
            value = per_payee + (remainder if len(vout) == 0 else 0)
            vout.append(TransactionOutput(value, ctx.script_pubkey))
            output_ctx.append(ctx)
        else:
            value = per_payee + (remainder if len(vout) == 0 else 0)
            vout.append(TransactionOutput(value, _external_spk(signers, external_seq)))
            output_ctx.append(None)
            external_seq += 1

    psbt = PSBT(Transaction(vin=vin, vout=vout))

    for k, (ctx, tx) in enumerate(zip(input_ctx, funding)):
        ctx.apply_to_input(psbt.inputs[k], IN_VALUE, tx)
    for k, ctx in enumerate(output_ctx):
        if ctx is not None:
            ctx.apply_to_output(psbt.outputs[k])

    return psbt


def build_multisig_psbt(cosigners: list, threshold: int, script_type: str,
                        num_inputs: int) -> PSBT:
    """Back-compat wrapper for the original multisig-only entry point."""
    return build_psbt(cosigners, script_type, num_inputs,
                      output_shape="change", threshold=threshold)


def _output_kind(out) -> str:
    """external | change | self_transfer, decided the way SeedSigner decides it.

    An output is ours if it carries our BIP32 derivations; the second-to-last
    path element then says which branch it's on (1 = change, 0 = receive, i.e.
    a self-transfer). Note SeedSigner's PSBTParser lumps both of ours into
    `change_data`, so a self-transfer shows on-device as two change outputs.
    """
    if out.bip32_derivations:
        _, der = next(iter(out.bip32_derivations.items()))
        return "change" if der.derivation[-2] == CHANGE_BRANCH else "self_transfer"
    if out.taproot_bip32_derivations:
        _, (_, der) = next(iter(out.taproot_bip32_derivations.items()))
        return "change" if der.derivation[-2] == CHANGE_BRANCH else "self_transfer"
    return "external"


def summarize(psbt: PSBT, network: str = "main") -> dict:
    """Plain-language description of a PSBT, for display alongside its QR."""
    from embit.networks import NETWORKS
    net = NETWORKS[network]

    input_amount = 0
    for inp in psbt.inputs:
        input_amount += inp.witness_utxo.value if inp.witness_utxo else inp.utxo.value

    outputs, output_total = [], 0
    for i, out in enumerate(psbt.outputs):
        value = psbt.tx.vout[i].value
        output_total += value
        outputs.append({
            "address": psbt.tx.vout[i].script_pubkey.address(net),
            "value": value,
            "kind": _output_kind(out),
        })

    return {
        "num_inputs": len(psbt.inputs),
        "input_amount": input_amount,
        "outputs": outputs,
        "fee": input_amount - output_total,
    }


def address_at(signers: list, script_type: str, branch: int, index: int,
               network: str = "main", threshold: int = None) -> str:
    """The wallet's address at branch/index — what SeedSigner's Verify Address
    flow should confirm belongs to this wallet."""
    from embit.networks import NETWORKS
    ctx = _ScriptContext(signers, threshold, script_type, branch, index)
    return ctx.script_pubkey.address(NETWORKS[network])
