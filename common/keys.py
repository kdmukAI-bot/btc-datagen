"""Deterministic throwaway key material for Bitcoin test-data generation.

Seeds are plain BIP39 mnemonics built from deterministic but high-quality
entropy (SHA256 of a domain-separated name; see tools/build_fixtures.py), so they
are fully reproducible AND look like real random seeds — yet can still be typed
into / scanned by SeedSigner by hand. NEVER put real bitcoin on anything here.
"""
from dataclasses import dataclass

from embit import bip39, bip32
from embit.networks import NETWORKS
from urtypes.crypto import HDKey, Keypath, PathComponent, CoinInfo

# Derivation paths per script type live in common/script_types.py (the single
# source of truth for everything that varies between the seven wallet types).


def mnemonic_from_entropy(entropy: bytes) -> str:
    return bip39.mnemonic_from_bytes(entropy)


def _path_components(path: str) -> list:
    components = []
    for element in path.split("/"):
        if element in ("m", ""):
            continue
        hardened = element[-1] in ("h", "'")
        index = int(element[:-1]) if hardened else int(element)
        components.append(PathComponent(index, hardened))
    return components


@dataclass
class Cosigner:
    name: str
    mnemonic: str
    network: str              # "main" | "test"
    derivation: str           # account path, e.g. "m/48h/0h/0h/2h"
    fingerprint: str          # master (root) fingerprint, hex
    xpub: str                 # account xpub (base58, network-correct)
    account: object           # embit public HDKey at `derivation` (for child derivation)
    hdkey: HDKey              # urtypes HDKey (for crypto-output CBOR)
    key_expression: str       # descriptor key expr WITHOUT the /<0;1>/* suffix


def make_cosigner(name: str, mnemonic: str,
                  derivation: str = "m/48h/0h/0h/2h",
                  network: str = "main") -> Cosigner:
    """Build a Cosigner from a (throwaway) BIP39 mnemonic."""
    net = NETWORKS[network]
    root = bip32.HDKey.from_seed(bip39.mnemonic_to_seed(mnemonic), version=net["xprv"])
    root_fp = root.my_fingerprint
    account = root.derive(derivation).to_public()

    components = _path_components(derivation)
    origin = Keypath(components, root_fp, len(components))
    use_info = None if network == "main" else CoinInfo(type=None, network=1)
    hdkey = HDKey({
        "key": account.key.serialize(),
        "chain_code": account.chain_code,
        "origin": origin,
        "parent_fingerprint": account.fingerprint,
        "use_info": use_info,
    })

    xpub_b58 = account.to_base58(version=net["xpub"])
    dpath = derivation.replace("m/", "").replace("'", "h")
    key_expression = f"[{root_fp.hex()}/{dpath}]{xpub_b58}"

    return Cosigner(
        name=name, mnemonic=mnemonic, network=network, derivation=derivation,
        fingerprint=root_fp.hex(), xpub=xpub_b58, account=account,
        hdkey=hdkey, key_expression=key_expression,
    )


# The same structure serves single-sig wallets (where there is exactly one of
# them), so expose neutral names alongside the original multisig-flavoured ones.
Signer = Cosigner
make_signer = make_cosigner
