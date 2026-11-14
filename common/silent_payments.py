"""BIP352 silent payments, and the BIP374 DLEQ proofs BIP375 carries.

Built on embit 0.8.0's own secp256k1 bindings so there is no second crypto
dependency. Points travel as 33-byte compressed SEC bytes and scalars as ints.
Every constant names the BIP section it comes from (bips repo at 4f979da).

Throwaway test data only. Nothing here is constant-time.
"""
from embit import bech32
from embit.hashes import hash160, tagged_hash
from embit.util import secp256k1 as secp

# secp256k1 group order and generator.
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = bytes.fromhex("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")

# BIP352 "Inputs For Shared Secret Derivation": a taproot input whose internal key
# is this NUMS point H is skipped.
NUMS_H = bytes.fromhex("50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0")

# BIP352 "Creating outputs" (K_max in reference.py): per scan key group limit.
K_MAX = 2323

# BIP352 "Address encoding": bech32m, version 0, HRP sp / tsp, 1023-char limit.
HRP = {"main": "sp", "test": "tsp"}
ADDRESS_MAX_LEN = 1023
# BIP392 "Key Expressions" > spscan: bech32m of ser256(b_scan) || serP(B_spend).
SPSCAN_HRP = {"main": "spscan", "test": "tspscan"}

# BIP370 global field type.
PSBT_GLOBAL_TX_MODIFIABLE = 0x06
# BIP375 "Specification" field types.
PSBT_GLOBAL_SP_ECDH_SHARE = 0x07   # key: 33-byte B_scan, value: 33-byte share
PSBT_GLOBAL_SP_DLEQ = 0x08         # key: 33-byte B_scan, value: 64-byte proof
PSBT_IN_SP_ECDH_SHARE = 0x1D       # key: 33-byte B_scan, value: 33-byte share
PSBT_IN_SP_DLEQ = 0x1E             # key: 33-byte B_scan, value: 64-byte proof
PSBT_OUT_SP_V0_INFO = 0x09         # no keydata, value: B_scan(33) || B_spend(33)
PSBT_OUT_SP_V0_LABEL = 0x0A        # no keydata, value: 4-byte little-endian label
# BIP376 "Fields".
PSBT_IN_SP_SPEND_BIP32_DERIVATION = 0x1F  # key: 33-byte B_spend, value: fp || path
PSBT_IN_SP_TWEAK = 0x20                   # no keydata, value: 32-byte tweak


# --- points and scalars --------------------------------------------------------

def _parse(sec: bytes):
    return secp.ec_pubkey_parse(sec)        # a fresh 64-byte buffer every call


def is_point(sec: bytes) -> bool:
    if len(sec) != 33:
        return False
    try:
        _parse(sec)
        return True
    except ValueError:
        return False


def base_mul(k: int) -> bytes:
    return secp.ec_pubkey_serialize(secp.ec_pubkey_create((k % N).to_bytes(32, "big")))


def point_mul(sec: bytes, k: int):
    """k*P, or None for the point at infinity (k = 0 mod N)."""
    if k % N == 0:
        return None
    pub = _parse(sec)
    out = secp.ec_pubkey_tweak_mul(pub, (k % N).to_bytes(32, "big"))
    # The ctypes binding writes into `pub` and returns None; the pure-python
    # fallback returns the result. Accept either.
    return secp.ec_pubkey_serialize(out if out is not None else pub)


def point_add(*secs):
    """Sum of points, or None for the point at infinity."""
    try:
        return secp.ec_pubkey_serialize(secp.ec_pubkey_combine(*[_parse(s) for s in secs]))
    except ValueError:
        return None


def point_neg(sec: bytes) -> bytes:
    return secp.ec_pubkey_serialize(secp.ec_pubkey_negate(_parse(sec)))


def _sub(p, q):
    """p - q with None standing for infinity."""
    if q is None:
        return p
    if p is None:
        return point_neg(q)
    return point_add(p, point_neg(q))


def _ser32(i: int) -> bytes:
    return i.to_bytes(4, "big")             # BIP352 ser32: most significant byte first


def _scalar(h: bytes) -> int:
    k = int.from_bytes(h, "big")
    if not 0 < k < N:
        raise ValueError("hash outside the group order")
    return k


# --- keys (BIP352 "Key Derivation") -------------------------------------------

def scan_path(coin: int) -> str:
    return f"m/352h/{coin}h/0h/1h/0"


def spend_path(coin: int) -> str:
    return f"m/352h/{coin}h/0h/0h/0"


def wallet_keys(root, network: str) -> dict:
    """b_scan, B_scan, b_spend, B_spend for account 0 of a BIP32 root."""
    coin = 0 if network == "main" else 1
    b_scan = int.from_bytes(root.derive(scan_path(coin)).key.secret, "big")
    b_spend = int.from_bytes(root.derive(spend_path(coin)).key.secret, "big")
    return {"b_scan": b_scan, "B_scan": base_mul(b_scan),
            "b_spend": b_spend, "B_spend": base_mul(b_spend)}


# --- inputs (BIP352 "Inputs For Shared Secret Derivation") ---------------------

def _is_p2pkh(s): return len(s) == 25 and s[:3] == b"\x76\xa9\x14" and s[-2:] == b"\x88\xac"
def _is_p2sh(s): return len(s) == 23 and s[:2] == b"\xa9\x14" and s[-1:] == b"\x87"
def _is_p2wpkh(s): return len(s) == 22 and s[:2] == b"\x00\x14"
def _is_p2tr(s): return len(s) == 34 and s[:2] == b"\x51\x20"


def _compressed(item: bytes):
    return item if is_point(item) else None


def input_pubkey(spk: bytes, script_sig: bytes = b"", witness=()):
    """The key a signed input contributes, or None if it does not count.
    Port of get_pubkey_from_input in the BIP352 reference."""
    witness = list(witness)
    if _is_p2pkh(spk):
        for i in range(len(script_sig), 32, -1):
            cand = script_sig[i - 33:i]
            if hash160(cand) == spk[3:23] and is_point(cand):
                return cand
        return None
    if _is_p2sh(spk):
        if _is_p2wpkh(script_sig[1:]) and witness:
            return _compressed(witness[-1])
        return None
    if _is_p2wpkh(spk):
        return _compressed(witness[-1]) if witness else None
    if _is_p2tr(spk):
        if not witness:
            return None
        if len(witness) > 1 and witness[-1][:1] == b"\x50":
            witness.pop()                   # annex
        if len(witness) > 1 and witness[-1][1:33] == NUMS_H:
            return None                     # script path with the NUMS internal key
        return _compressed(b"\x02" + spk[2:])
    return None


def psbt_input_pubkey(inp):
    """The same rule for an unsigned psbt input (embit InputScope): the key comes
    from the input's own derivation entries, checked against its script, and a
    taproot input counts unless its internal key is H."""
    spk = inp.utxo.script_pubkey.data
    if _is_p2tr(spk):
        if inp.taproot_internal_key is not None and inp.taproot_internal_key.xonly() == NUMS_H:
            return None
        return _compressed(b"\x02" + spk[2:])
    for pub in inp.bip32_derivations:
        sec = pub.sec()
        wpkh = b"\x00\x14" + hash160(sec)
        if spk in (wpkh, b"\x76\xa9\x14" + hash160(sec) + b"\x88\xac",
                   b"\xa9\x14" + hash160(wpkh) + b"\x87"):
            return sec
    return None


# --- shared secret and outputs (BIP352 "Creating outputs") ----------------------

def outpoint_bytes(txid: bytes, vout: int) -> bytes:
    """Serialized outpoint. `txid` is in display order, the way embit and the
    vectors hold it; the wire form is reversed."""
    return txid[::-1] + vout.to_bytes(4, "little")


def a_sum(keys) -> int:
    """keys: [(private key, is_taproot)]. A taproot key with odd y is negated."""
    total = 0
    for k, xonly in keys:
        if xonly and base_mul(k)[0] == 3:
            k = N - k
        total = (total + k) % N
    return total


def input_hash(outpoints, A_sum: bytes) -> int:
    return _scalar(tagged_hash("BIP0352/Inputs", min(outpoints) + A_sum))


def t_k(ecdh: bytes, k: int) -> int:
    return _scalar(tagged_hash("BIP0352/SharedSecret", ecdh + _ser32(k)))


def output_keys(ecdh: bytes, spend_keys) -> list:
    """x-only output keys for one scan key's B_m list, k = 0, 1, ..."""
    return [point_add(B_m, base_mul(t_k(ecdh, k)))[1:] for k, B_m in enumerate(spend_keys)]


def create_outputs(privs, outpoints, recipients) -> list:
    """BIP352 sender. recipients: [(B_scan, B_m)] in order. [] where sending fails."""
    a = a_sum(privs)
    if a == 0:
        return []
    ih = input_hash(outpoints, base_mul(a))
    groups = {}
    for B_scan, B_m in recipients:
        groups.setdefault(B_scan, []).append(B_m)
    if any(len(g) > K_MAX for g in groups.values()):
        return []
    out = []
    for B_scan, spends in groups.items():
        out += output_keys(point_mul(B_scan, ih * a % N), spends)
    return out


# --- receiving (BIP352 "Scanning") ----------------------------------------------

def scan(b_scan: int, B_spend: bytes, A_sum: bytes, ih: int, outputs, labels=None) -> list:
    """[(x-only output, spend tweak)] found for this wallet. `labels` maps a label
    point m*G to its tweak."""
    labels = labels or {}
    ecdh = point_mul(A_sum, ih * b_scan % N)
    remaining, found = list(outputs), []
    for k in range(K_MAX):
        t = t_k(ecdh, k)
        P_k = point_add(B_spend, base_mul(t))
        hit = None
        for out in remaining:
            if P_k[1:] == out:
                hit = (out, t)
                break
            if labels:
                lifted = b"\x02" + out
                for cand in (lifted, point_neg(lifted)):
                    diff = _sub(cand, P_k)
                    if diff in labels:
                        hit = (out, (t + labels[diff]) % N)
                        break
                if hit:
                    break
        if hit is None:
            break
        remaining.remove(hit[0])
        found.append(hit)
    return found


# --- labels and addresses (BIP352 "Overview" labels, "Address encoding") -------

def label_tweak(b_scan: int, m: int) -> int:
    return _scalar(tagged_hash("BIP0352/Label", b_scan.to_bytes(32, "big") + _ser32(m)))


def labeled_spend_key(B_spend: bytes, b_scan: int, m: int) -> bytes:
    return point_add(B_spend, base_mul(label_tweak(b_scan, m)))


def _bech32m(hrp: str, payload: bytes) -> str:
    return bech32.bech32_encode(bech32.Encoding.BECH32M, hrp,
                                [0] + bech32.convertbits(payload, 8, 5))


def encode_address(B_scan: bytes, B_m: bytes, network: str) -> str:
    return _bech32m(HRP[network], B_scan + B_m)


def encode_spscan(b_scan: int, B_spend: bytes, network: str) -> str:
    return _bech32m(SPSCAN_HRP[network], b_scan.to_bytes(32, "big") + B_spend)


def decode_address(addr: str):
    """(network, B_scan, B_m). embit's bech32_decode caps strings at 90 chars,
    so this decodes against BIP352's 1023 limit itself."""
    if (addr.lower() != addr and addr.upper() != addr) or len(addr) > ADDRESS_MAX_LEN:
        raise ValueError("bad silent payment address")
    addr = addr.lower()
    pos = addr.rfind("1")
    if pos < 1 or pos + 7 > len(addr) or any(c not in bech32.CHARSET for c in addr[pos + 1:]):
        raise ValueError("bad silent payment address")
    hrp, data = addr[:pos], [bech32.CHARSET.find(c) for c in addr[pos + 1:]]
    if bech32.bech32_verify_checksum(hrp, data) != bech32.Encoding.BECH32M:
        raise ValueError("bad bech32m checksum")
    network = {v: k for k, v in HRP.items()}.get(hrp)
    data = data[:-6]
    if network is None or not data or data[0] != 0:
        raise ValueError("not a version 0 silent payment address")
    payload = bytes(bech32.convertbits(data[1:], 5, 8, False))
    if len(payload) != 66:
        raise ValueError("version 0 payload must be 66 bytes")
    return network, payload[:33], payload[33:]


# --- BIP374 DLEQ proofs ---------------------------------------------------------

def _challenge(A, B, C, R1, R2, m, G_) -> int:
    data = A + B + C + G_ + R1 + R2 + (m or b"")
    return int.from_bytes(tagged_hash("BIP0374/challenge", data), "big") % N


def dleq_prove(a: int, B, r: bytes, G_=G, m=None):
    """BIP374 GenerateProof: proof that log_G(A) == log_B(C) for A=aG, C=aB."""
    if not 0 < a < N or B is None:
        return None
    A, C = point_mul(G_, a), point_mul(B, a)
    t = bytes(x ^ y for x, y in zip(a.to_bytes(32, "big"), tagged_hash("BIP0374/aux", r)))
    k = int.from_bytes(tagged_hash("BIP0374/nonce", t + A + C + (m or b"")), "big") % N
    if k == 0:
        return None
    e = _challenge(A, B, C, point_mul(G_, k), point_mul(B, k), m, G_)
    proof = e.to_bytes(32, "big") + ((k + e * a) % N).to_bytes(32, "big")
    return proof if dleq_verify(A, B, C, proof, G_, m) else None


def dleq_verify(A, B, C, proof: bytes, G_=G, m=None) -> bool:
    """BIP374 VerifyProof."""
    if None in (A, B, C, G_) or len(proof) != 64:
        return False
    e, s = int.from_bytes(proof[:32], "big"), int.from_bytes(proof[32:], "big")
    if e >= N or s >= N:
        return False
    R1 = _sub(point_mul(G_, s), point_mul(A, e))
    R2 = _sub(point_mul(B, s), point_mul(C, e))
    if R1 is None or R2 is None:
        return False
    return e == _challenge(A, B, C, R1, R2, m, G_)
