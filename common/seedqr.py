"""SeedQR + CompactSeedQR payload encoding — byte-identical to SeedSigner's.

Mirrors SeedSigner's `models/encode_qr.py`:

  * Standard SeedQR : each BIP39 word's 4-digit wordlist index, concatenated,
                      encoded in QR NUMERIC mode (12w -> 48 digits, 24w -> 96).
  * CompactSeedQR   : the 11-bit indices concatenated, checksum bits dropped,
                      packed into raw bytes, encoded in QR BYTE mode
                      (= the BIP39 entropy; 16 bytes for 12w, 32 for 24w).
"""
import math

from embit import bip39

WORDLIST = bip39.WORDLIST


def standard_seedqr_digits(mnemonic_words: list) -> str:
    return "".join("%04d" % WORDLIST.index(w) for w in mnemonic_words)


def compact_seedqr_bytes(mnemonic_words: list) -> bytes:
    bits = "".join(bin(WORDLIST.index(w))[2:].zfill(11) for w in mnemonic_words)
    checksum_bits = 8 if len(mnemonic_words) == 24 else 4   # ENT/32
    bits = bits[:-checksum_bits]
    return bytes(int(bits[i * 8:(i + 1) * 8], 2) for i in range(math.ceil(len(bits) / 8)))
