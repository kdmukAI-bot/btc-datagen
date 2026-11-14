"""(Re)generate the reusable plaintext test fixtures: seeds + wallets.

Deterministic throwaway keys. INSECURE BY DESIGN — never use for real funds.

Every wallet is built for both mainnet and testnet, because the two genuinely
differ: the account path's coin type (0h vs 1h), the xpub/tpub version bytes in
the descriptor and its `crypto-output` UR, and the resulting addresses. A
testnet wallet is named with a `_testnet` suffix.

Run:  python -m tools.build_fixtures
"""
import hashlib
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from embit import bip39, bip32
from embit.networks import NETWORKS

from common import script_types
from common.keys import make_signer, mnemonic_from_entropy
from common.descriptor import descriptor_text, crypto_output_ur, crypto_account_ur
from common import silent_payments as sp
from common.fixtures import FIXTURES_DIR, SEEDS_PATH, WALLETS_PATH, SP_WALLETS_PATH
from common.psbt import address_at, RECEIVE_BRANCH, CHANGE_BRANCH

WARNING = ("INSECURE TEST KEYS — deterministic, public, and stored in plain text. "
           "NEVER use for real funds.")

# --- Canonical seed set ------------------------------------------------------
# (name, word_count). Entropy is DETERMINISTIC but high-quality: SHA256 of a
# domain-separated name. Reproducible across rebuilds, yet the mnemonics look
# like real random seeds (no repeating-word artifacts) for realistic testing.
# Mix of 12- and 24-word seeds so both BIP39 lengths get exercised on SeedSigner.
ENTROPY_DOMAIN = "btc-datagen/test-seed/v1"
SEED_DEFS = [
    ("alice", 24), ("bob", 24), ("carol", 24),
    ("dave", 12), ("erin", 12), ("frank", 24), ("grace", 12),
]

NETWORKS_BUILT = ["main", "test"]

# How many addresses to precompute per wallet, per branch, for the
# verify-address demo step.
ADDRESSES_PER_BRANCH = 3


def _entropy_for(name: str, words: int) -> bytes:
    nbytes = 32 if words == 24 else 16
    return hashlib.sha256(f"{ENTROPY_DOMAIN}:{name}".encode()).digest()[:nbytes]


# --- Canonical wallet set ----------------------------------------------------
# `threshold` is None for single sig. Derivation paths come from script_types.
WALLET_DEFS = [
    # single sig — one wallet per script type, all on the same seed so a demo
    # only ever needs `alice` loaded to try any of them
    {"name": "ss_native_segwit", "script_type": "P2WPKH", "signers": ["alice"]},
    {"name": "ss_nested_segwit", "script_type": "P2SH-P2WPKH", "signers": ["alice"]},
    {"name": "ss_taproot", "script_type": "P2TR", "signers": ["alice"]},
    {"name": "ss_legacy", "script_type": "P2PKH", "signers": ["alice"]},
    # multisig
    {"name": "2of3_p2wsh", "script_type": "P2WSH", "threshold": 2,
     "signers": ["alice", "bob", "carol"]},
    {"name": "3of5_p2wsh", "script_type": "P2WSH", "threshold": 3,
     "signers": ["alice", "bob", "carol", "dave", "erin"]},
    {"name": "2of3_p2sh_p2wsh", "script_type": "P2SH-P2WSH", "threshold": 2,
     "signers": ["alice", "bob", "carol"]},
    {"name": "2of3_p2sh", "script_type": "P2SH", "threshold": 2,
     "signers": ["alice", "bob", "carol"]},
]


# BIP352 labels written for every seed. m=0 is the change label ("Overview"):
# the wallet must never hand it out, so the site shows only m=1..3.
SP_LABELS = [0, 1, 2, 3]


def build_sp_wallet(seed: dict, network: str) -> dict:
    root = bip32.HDKey.from_seed(bip39.mnemonic_to_seed(seed["mnemonic"]),
                                 version=NETWORKS[network]["xprv"])
    keys = sp.wallet_keys(root, network)
    coin = script_types.COIN_TYPE[network]
    return {
        "name": seed["name"] if network == "main" else f"{seed['name']}_testnet",
        "seed": seed["name"],
        "network": network,
        "master_fingerprint": seed["master_fingerprint"],
        "derivation": f"m/352h/{coin}h/0h",
        "scan_path": sp.scan_path(coin),
        "spend_path": sp.spend_path(coin),
        "scan_priv": keys["b_scan"].to_bytes(32, "big").hex(),
        "scan_pub": keys["B_scan"].hex(),
        "spend_pub": keys["B_spend"].hex(),
        "address": sp.encode_address(keys["B_scan"], keys["B_spend"], network),
        # What SeedSigner #949 exports under "Export SP descriptor": the key
        # expression with its origin, without the sp(...) wrapper (BIP392).
        "spscan": (f"[{seed['master_fingerprint']}/352h/{coin}h/0h]"
                   + sp.encode_spscan(keys["b_scan"], keys["B_spend"], network)),
        "labels": [
            {"m": m, "use": "change" if m == 0 else "receive",
             "spend_pub": (B_m := sp.labeled_spend_key(keys["B_spend"], keys["b_scan"], m)).hex(),
             "address": sp.encode_address(keys["B_scan"], B_m, network)}
            for m in SP_LABELS
        ],
    }


def build_seeds() -> list:
    seeds = []
    for name, words in SEED_DEFS:
        entropy = _entropy_for(name, words)
        mnemonic = mnemonic_from_entropy(entropy)
        root = bip32.HDKey.from_seed(bip39.mnemonic_to_seed(mnemonic),
                                     version=NETWORKS["main"]["xprv"])
        seeds.append({
            "name": name,
            "words": len(mnemonic.split()),
            "entropy_hex": entropy.hex(),
            "mnemonic": mnemonic,
            "master_fingerprint": root.my_fingerprint.hex(),
        })
    return seeds


def build_wallet(wd: dict, network: str, seeds_by_name: dict) -> dict:
    info = script_types.get(wd["script_type"])
    derivation = script_types.derivation_for(wd["script_type"], network)
    threshold = wd.get("threshold")
    signers = [make_signer(n, seeds_by_name[n]["mnemonic"], derivation, network)
               for n in wd["signers"]]

    name = wd["name"] if network == "main" else f"{wd['name']}_testnet"
    policy = (f"{threshold}-of-{len(signers)}" if info.is_multisig else "single sig")

    addresses = {}
    for label, branch in (("receive", RECEIVE_BRANCH), ("change", CHANGE_BRANCH)):
        addresses[label] = [
            {"index": i, "path": f"{branch}/{i}",
             "address": address_at(signers, wd["script_type"], branch, i, network, threshold)}
            for i in range(ADDRESSES_PER_BRANCH)
        ]

    return {
        "name": name,
        "sig_type": info.sig_type,
        "policy": policy,
        "threshold": threshold,
        "total": len(signers),
        "script_type": wd["script_type"],
        "script_label": info.label,
        "network": network,
        "derivation": derivation,
        # Key kept as "cosigners" for both sig types so loaders stay uniform.
        "cosigners": wd["signers"],
        "descriptor": descriptor_text(threshold, signers, wd["script_type"]),
        "ur_crypto_output": crypto_output_ur(threshold, signers, wd["script_type"]),
        "ur_crypto_account": crypto_account_ur(threshold, signers, wd["script_type"]),
        "cosigner_keys": [{"name": s.name, "master_fingerprint": s.fingerprint,
                           "derivation": s.derivation, "xpub": s.xpub} for s in signers],
        "addresses": addresses,
    }


def build_wallets(seeds_by_name: dict) -> list:
    return [build_wallet(wd, network, seeds_by_name)
            for wd in WALLET_DEFS for network in NETWORKS_BUILT]


def main():
    os.makedirs(FIXTURES_DIR, exist_ok=True)
    seeds = build_seeds()
    seeds_by_name = {s["name"]: s for s in seeds}
    wallets = build_wallets(seeds_by_name)

    with open(SEEDS_PATH, "w") as f:
        json.dump({"_warning": WARNING, "seeds": seeds}, f, indent=2)
        f.write("\n")
    with open(WALLETS_PATH, "w") as f:
        json.dump({"_warning": WARNING, "wallets": wallets}, f, indent=2)
        f.write("\n")

    sp_wallets = [build_sp_wallet(s, n) for s in seeds for n in NETWORKS_BUILT]
    with open(SP_WALLETS_PATH, "w") as f:
        json.dump({"_warning": WARNING, "wallets": sp_wallets}, f, indent=2)
        f.write("\n")
    print(f"Wrote {len(sp_wallets)} silent payment wallets -> {SP_WALLETS_PATH}")

    print(f"Wrote {len(seeds)} seeds -> {SEEDS_PATH}")
    print(f"Wrote {len(wallets)} wallets -> {WALLETS_PATH}")
    for w in wallets:
        print(f"  {w['name']:26s} {w['policy']:11s} {w['script_type']:12s} "
              f"{w['network']:5s} {w['addresses']['receive'][0]['address']}")


if __name__ == "__main__":
    main()
