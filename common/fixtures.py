"""Loaders for the reusable plaintext test fixtures (seeds + multisig wallets).

The fixtures are deterministic throwaway keys stored as plain text so they can be
reused across generators and re-entered into / scanned by SeedSigner by hand.
Regenerate them with `python -m tools.build_fixtures`.
"""
import json
import os

from common.keys import make_cosigner

FIXTURES_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "fixtures")
SEEDS_PATH = os.path.join(FIXTURES_DIR, "test_seeds.json")
WALLETS_PATH = os.path.join(FIXTURES_DIR, "test_wallets.json")


def load_seeds() -> dict:
    with open(SEEDS_PATH) as f:
        return {s["name"]: s for s in json.load(f)["seeds"]}


def load_wallets() -> dict:
    with open(WALLETS_PATH) as f:
        return {w["name"]: w for w in json.load(f)["wallets"]}


def wallet_cosigners(wallet: dict, seeds: dict = None) -> list:
    """Rebuild embit-backed Cosigner objects for a wallet fixture."""
    seeds = seeds or load_seeds()
    return [
        make_cosigner(name, seeds[name]["mnemonic"], wallet["derivation"], wallet["network"])
        for name in wallet["cosigners"]
    ]
