#
# crc32.py
#
# Copyright © 2020 Foundation Devices, Inc.
# Licensed under the "BSD-2-Clause Plus Patent License"
#

from .constants import MAX_UINT32

def bit_length(n):
    return len(bin(abs(n))) - 2

TABLE = None

def crc32(buf):
    # Lazily instantiate CRC table
    global TABLE
    if TABLE == None:
        TABLE = [None] * (256 * 4)

        for i in range(256):
            c = i
            for j in range(8):
                c = (c >> 1) if (c % 2 == 0) else (0xEDB88320 ^ (c >> 1))

            TABLE[i] = c

    crc = MAX_UINT32 & ~0
    for byte in buf:
        crc = (crc >> 8) ^ TABLE[(crc ^ byte) & 0xFF]

    return MAX_UINT32 & ~crc

def crc32n(buf):
    # FIXED WIDTH, always four bytes. The original used a minimal-width
    # encoding — `n.to_bytes((bit_length(n) + 7) // 8, 'big')` — which silently
    # drops leading zero bytes, so roughly one part in 256 (any checksum below
    # 2**24) came out three bytes long. BCR-2020-005 specifies the bytewords
    # checksum as a 4-byte big-endian CRC32, and a decoder that takes the last
    # four bytes as the checksum then hands a body one byte short to the CBOR
    # parser, which rejects the frame.
    #
    # It shipped for a long time because the fountain hides it: a UR animation
    # whose parts are individually corrupt at a ~0.4% rate still reassembles,
    # just with a couple of extra frames of latency, so no round trip ever
    # failed. It only surfaced when the same PSBT was encoded by cUR and the two
    # part strings differed by exactly one `ae` (0x00) byteword.
    #
    # Note for anyone porting this file back: SeedSigner's own vendored copy at
    # src/seedsigner/helpers/ur2/crc32.py has the same bug, and the same effect
    # on the frames a Pi Zero puts on screen when signing.
    return crc32(buf).to_bytes(4, 'big')
