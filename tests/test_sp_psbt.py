"""sp_psbt builders: round-trip through embit 0.8.0, audit agrees with the
scenario's named defect, and the scripts a signer writes are the ones the
BIP352 sender math (already gated by the vectors) gives."""
from embit.psbt import PSBT

from common import silent_payments as sp
from common import sp_psbt
from common.fixtures import load_wallets, wallet_cosigners

ROOT = sp_psbt.sender_root("main")


def _signers(script_type="P2WPKH", network="main"):
    name = {"P2WPKH": "ss_native_segwit", "P2TR": "ss_taproot"}[script_type]
    return wallet_cosigners(load_wallets()[name if network == "main" else f"{name}_testnet"])


def test_pay_has_scriptless_sp_output_and_roundtrips():
    psbt = sp_psbt.pay(_signers(), "main", 3)
    raw = psbt.serialize()
    again = PSBT.parse(raw)
    assert again.serialize() == raw and again.version == 2
    assert again.outputs[0].script_pubkey is None
    info = sp_psbt.get_field(again.outputs[0], sp.PSBT_OUT_SP_V0_INFO)
    assert len(info) == 66
    assert sp_psbt.audit(again, ROOT, "main") == []


def test_fill_global_matches_bip352_sender():
    psbt = sp_psbt.pay(_signers(), "main", 3)
    sp_psbt.fill_global(psbt, ROOT, b"\x00" * 32)
    privs = sp_psbt.input_privkeys(psbt, ROOT)
    (_, B_scan, B_m, _), = sp_psbt.sp_outputs(psbt)
    want = sp.create_outputs(privs, sp_psbt.outpoints(psbt), [(B_scan, B_m)])
    assert psbt.outputs[0].script_pubkey.data == b"\x51\x20" + want[0]
    assert sp_psbt.audit(PSBT.parse(psbt.serialize()), ROOT, "main") == []


import pytest


@pytest.mark.parametrize("kind", sorted(sp_psbt.BUILDERS))
@pytest.mark.parametrize("network", ["main", "test"])
def test_builder_roundtrips_and_audits(kind, network):
    signers = _signers(sp_psbt.CASES[kind], network)
    psbt = sp_psbt.BUILDERS[kind](signers, network, 3)
    raw = psbt.serialize()
    again = PSBT.parse(raw)
    assert again.serialize() == raw
    assert sp_psbt.BUILDERS[kind](signers, network, 3).serialize() == raw   # deterministic
    want = sorted(sp_psbt.EXPECTED_FINDINGS.get(kind, []))
    assert sp_psbt.audit(again, sp_psbt.sender_root(network), network) == want


def test_same_twice_gets_two_different_outputs_once_filled():
    psbt = sp_psbt.BUILDERS["sp_same_twice"](_signers(), "main", 3)
    sp_psbt.fill_global(psbt, ROOT, b"\x00" * 32)
    assert psbt.outputs[0].script_pubkey != psbt.outputs[1].script_pubkey


def test_nums_input_is_skipped():
    psbt = sp_psbt.BUILDERS["sp_nums_input"](_signers("P2TR"), "main", 3)
    assert [sp.psbt_input_pubkey(i) is None for i in psbt.inputs] == [False, False, True]


from common.psbt import summarize


def test_summarize_shows_sp_address_and_change_claim():
    psbt = sp_psbt.BUILDERS["sp_change"](_signers(), "test", 3)
    rows = summarize(psbt, "test")["outputs"]
    assert rows[0]["address"].startswith("tsp1q") and rows[0]["kind"] == "external"
    assert rows[1]["kind"] == "change"
    assert summarize(psbt, "test")["fee"] == 10_000
