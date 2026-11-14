"""The gate for common/silent_payments.py: the official BIP352 send/receive
vectors and the BIP374 DLEQ vectors, vendored verbatim from the bips repo at
4f979da into fixtures/vectors/. Nothing that builds psbts lands until these pass.
"""
import csv
import hashlib
import json
import os
from io import BytesIO

import pytest
from embit import compact
from embit.util import secp256k1 as secp

from common import silent_payments as sp

VEC = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                   "fixtures", "vectors")

with open(os.path.join(VEC, "bip352_send_and_receive_test_vectors.json")) as f:
    BIP352 = json.load(f)

# reference.py signs every found output with these to prove the tweak spends it.
MSG = hashlib.sha256(b"message").digest()
AUX = hashlib.sha256(b"random auxiliary data").digest()


def _witness(hexstr: str) -> list:
    raw = bytes.fromhex(hexstr)
    if not raw:
        return []
    s = BytesIO(raw)
    return [s.read(compact.read_from(s)) for _ in range(compact.read_from(s))]


def _pubkeys(vins):
    """(index, pubkey) of every input that counts, per BIP352."""
    out = []
    for i, vin in enumerate(vins):
        spk = bytes.fromhex(vin["prevout"]["scriptPubKey"]["hex"])
        pub = sp.input_pubkey(spk, bytes.fromhex(vin["scriptSig"]), _witness(vin["txinwitness"]))
        if pub is not None:
            out.append((i, pub))
    return out


def _outpoints(vins):
    return [sp.outpoint_bytes(bytes.fromhex(v["txid"]), v["vout"]) for v in vins]


@pytest.mark.parametrize("case", BIP352, ids=[c["comment"][:70] for c in BIP352])
def test_bip352_sending(case):
    for t in case["sending"]:
        given, exp = t["given"], t["expected"]
        found = _pubkeys(given["vin"])
        assert [p.hex() for _, p in found] == exp["input_pub_keys"]
        if not found:
            assert exp["outputs"] == [[]]
            continue
        privs = []
        for i, _ in found:
            vin = given["vin"][i]
            spk = bytes.fromhex(vin["prevout"]["scriptPubKey"]["hex"])
            privs.append((int(vin["private_key"], 16), spk[:2] == b"\x51\x20"))
        if "input_private_key_sum" in exp:
            assert sp.a_sum(privs) == int(exp["input_private_key_sum"], 16)
        recipients = []
        for r in given["recipients"]:
            _, B_scan, B_m = sp.decode_address(r["address"])
            assert (B_scan.hex(), B_m.hex()) == (r["scan_pub_key"], r["spend_pub_key"])
            recipients += [(B_scan, B_m)] * r.get("count", 1)
        got = {x.hex() for x in sp.create_outputs(privs, _outpoints(given["vin"]), recipients)}
        assert any(got == set(o) for o in exp["outputs"])


@pytest.mark.parametrize("case", BIP352, ids=[c["comment"][:70] for c in BIP352])
def test_bip352_receiving(case):
    for t in case["receiving"]:
        given, exp = t["given"], t["expected"]
        b_scan = int(given["key_material"]["scan_priv_key"], 16)
        b_spend = int(given["key_material"]["spend_priv_key"], 16)
        B_scan, B_spend = sp.base_mul(b_scan), sp.base_mul(b_spend)
        addresses = [sp.encode_address(B_scan, B_spend, "main")] + [
            sp.encode_address(B_scan, sp.labeled_spend_key(B_spend, b_scan, m), "main")
            for m in given["labels"]]
        assert addresses == exp["addresses"]

        found = []
        pubs = [p for _, p in _pubkeys(given["vin"])]
        if pubs:
            A = sp.point_add(*pubs)
            if A is None:
                assert exp.get("outputs") == []
                continue
            assert A.hex() == exp["input_pub_key_sum"]
            ih = sp.input_hash(_outpoints(given["vin"]), A)
            assert sp.point_mul(A, ih).hex() == exp["tweak"]
            labels = {}
            for m in given["labels"]:
                tw = sp.label_tweak(b_scan, m)
                labels[sp.base_mul(tw)] = tw
            found = sp.scan(b_scan, B_spend, A, ih,
                            [bytes.fromhex(o) for o in given["outputs"]], labels)

        if "outputs" in exp:
            with_sig = any("signature" in o for o in exp["outputs"])
            got = set()
            for x, tweak in found:
                sig = None
                if with_sig:
                    d = (b_spend + tweak) % sp.N
                    sig = secp.schnorrsig_sign(MSG, d.to_bytes(32, "big"), None, AUX).hex()
                got.add((x.hex(), tweak.to_bytes(32, "big").hex(), sig))
            want = {(o["pub_key"], o["priv_key_tweak"], o.get("signature")) for o in exp["outputs"]}
            assert got == want
        else:
            assert len(found) == exp["n_outputs"]


def _rows(name):
    with open(os.path.join(VEC, name)) as f:
        return list(csv.DictReader(f))


def _pt(h):
    return None if h == "INFINITY" else bytes.fromhex(h)


def _msg(h):
    return bytes.fromhex(h) if h else None


@pytest.mark.parametrize("row", _rows("bip374_test_vectors_generate_proof.csv"),
                         ids=lambda r: r["comment"])
def test_bip374_generate(row):
    proof = sp.dleq_prove(int(row["scalar_a"], 16), _pt(row["point_B"]),
                          bytes.fromhex(row["auxrand_r"]), _pt(row["point_G"]),
                          _msg(row["message"]))
    assert (proof.hex() if proof else "INVALID") == row["result_proof"]


@pytest.mark.parametrize("row", _rows("bip374_test_vectors_verify_proof.csv"),
                         ids=lambda r: r["comment"])
def test_bip374_verify(row):
    ok = sp.dleq_verify(_pt(row["point_A"]), _pt(row["point_B"]), _pt(row["point_C"]),
                        bytes.fromhex(row["proof"]), _pt(row["point_G"]), _msg(row["message"]))
    assert ok == (row["result_success"] == "TRUE")


def test_sp_fixture_matches_the_seeds():
    from embit import bip32, bip39
    from embit.networks import NETWORKS
    from common.fixtures import load_seeds, load_sp_wallets
    seeds, wallets = load_seeds(), load_sp_wallets()
    assert len(wallets) == 2 * len(seeds)
    for w in wallets.values():
        root = bip32.HDKey.from_seed(bip39.mnemonic_to_seed(seeds[w["seed"]]["mnemonic"]),
                                     version=NETWORKS[w["network"]]["xprv"])
        keys = sp.wallet_keys(root, w["network"])
        assert w["scan_pub"] == keys["B_scan"].hex() and w["spend_pub"] == keys["B_spend"].hex()
        assert sp.decode_address(w["address"]) == (w["network"], keys["B_scan"], keys["B_spend"])
        assert [l["m"] for l in w["labels"]] == [0, 1, 2, 3]
        for l in w["labels"]:
            B_m = sp.labeled_spend_key(keys["B_spend"], keys["b_scan"], l["m"])
            assert sp.decode_address(l["address"]) == (w["network"], keys["B_scan"], B_m)
