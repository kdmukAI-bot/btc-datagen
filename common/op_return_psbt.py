"""OP_RETURN transactions that exercise SeedSigner's data-carrier handling.

Unlike common/attack_psbt.py, nothing here is a forgery. Every psbt is honest and
ordinary; what varies is how the OP_RETURN output is encoded, how much data it
carries, and whether it destroys value. Each case's user-facing description lives
with its scenario in common/scenarios.py.

    direct_push    40 bytes pushed with the minimal (direct) opcode
    binary         75 bytes that are not valid UTF-8, so the screen shows hex
    pushdata1      80 bytes, the pre-v30 relay ceiling, pushed with OP_PUSHDATA1
    pushdata2      300 bytes, so the push carries a two byte length
    multi_push     two pushes in one script rather than one
    empty          a bare OP_RETURN, pushing nothing

    nonzero_value  10,000 sats on the output, which the transaction destroys
    two_outputs    two OP_RETURN outputs
    many_outputs   five, with the burn on one the overview elides
    max_pages      800 bytes, exactly what the paged screen will show
    large          4 KB, more than paging can show in full
    large_burn     4 KB and 10,000 sats destroyed, on the same output
    kitchen_sink   all of the above in one transaction

Bitcoin Core v30 raised the default -datacarriersize to 100,000 bytes, and consensus
never limited OP_RETURN data at all, so the larger payloads here are sizes a signer
can now be handed rather than exotic ones.

Throwaway keys only; none of this is signable into a broadcastable transaction.
"""
from embit.psbt import PSBT, OutputScope
from embit.script import Script

from common.psbt import build_psbt

OP_RETURN = 0x6a
OP_PUSHDATA_MAX_DIRECT = 0x4b   # opcodes 0x01-0x4b are themselves the byte count
OP_PUSHDATA1 = 0x4c
OP_PUSHDATA2 = 0x4d
OP_PUSHDATA4 = 0x4e

# The payload from the issue report, chosen because the damage is legible: the
# leading "C" is what a device running 0.8.7 drops.
CHANCELLOR = b"Chancellor on the brink of third bailout"

# Sats burned by the nonzero_value case. Deliberately large enough to be obvious
# against the 100,000 sat inputs rather than lost in rounding.
BURNED_SATS = 10_000

# A payload that is deliberately not valid UTF-8, so the screen takes its hex path.
# Ascending from 0x80 means the first bytes are self-describing: the payload starts
# 80 81 82, so a tester reading the first hex pair can see at a glance whether the
# leading byte survived.
BINARY_PAYLOAD = bytes(range(0x80, 0x80 + OP_PUSHDATA_MAX_DIRECT))


def _push(payload: bytes, opcode: int = None) -> bytes:
    """The push prefix for `payload`, minimal unless `opcode` forces one."""
    if opcode is None:
        if len(payload) <= OP_PUSHDATA_MAX_DIRECT:
            return bytes([len(payload)])
        if len(payload) <= 0xff:
            opcode = OP_PUSHDATA1
        elif len(payload) <= 0xffff:
            opcode = OP_PUSHDATA2
        else:
            opcode = OP_PUSHDATA4
    length_size = {OP_PUSHDATA1: 1, OP_PUSHDATA2: 2, OP_PUSHDATA4: 4}[opcode]
    return bytes([opcode]) + len(payload).to_bytes(length_size, "little")


def op_return_script(*payloads: bytes, opcode: int = None) -> Script:
    """An OP_RETURN scriptPubKey carrying one push per payload."""
    data = bytes([OP_RETURN])
    for payload in payloads:
        data += _push(payload, opcode) + payload
    return Script(data)


def _filler(length: int, seed: bytes = b"btc-datagen-op-return") -> bytes:
    """`length` bytes of readable, deterministic filler.

    Readable rather than random so a tester can tell at a glance whether the
    device is showing the start of the payload, the middle, or nothing at all.
    """
    return (b"".join(b"%04d " % i for i in range(length // 5 + 1)))[:length]


# kind -> [(scriptPubKey, value_in_sats), ...]
_CASES = {
    "direct_push":   lambda: [(op_return_script(CHANCELLOR), 0)],
    "binary":        lambda: [(op_return_script(BINARY_PAYLOAD), 0)],
    "pushdata1":     lambda: [(op_return_script(_filler(80), opcode=OP_PUSHDATA1), 0)],
    "pushdata2":     lambda: [(op_return_script(_filler(300)), 0)],
    "max_pages":     lambda: [(op_return_script(_filler(800)), 0)],
    "large":         lambda: [(op_return_script(_filler(4096)), 0)],
    "large_burn":    lambda: [(op_return_script(_filler(4096)), BURNED_SATS)],
    "nonzero_value": lambda: [(op_return_script(CHANCELLOR), BURNED_SATS)],
    "two_outputs":   lambda: [(op_return_script(b"first OP_RETURN payload"), 0),
                              (op_return_script(b"second OP_RETURN payload"), 0)],
    "many_outputs":  lambda: [(op_return_script(b"OP_RETURN payload %d" % i),
                               BURNED_SATS if i == 3 else 0)
                              for i in range(1, 6)],
    "empty":         lambda: [(Script(bytes([OP_RETURN])), 0)],
    "multi_push":    lambda: [(op_return_script(b"first push, ", b"second push"), 0)],

    # In output order, which is the order the outputs are reviewed in.
    "kitchen_sink":  lambda: [
        (op_return_script(CHANCELLOR), 0),                          # readable, one page
        (op_return_script(BINARY_PAYLOAD), 0),                      # not text, so hex
        (op_return_script(_filler(300)), 0),                        # pages, not truncated
        (op_return_script(_filler(4096)), 0),                       # too large to page
        (op_return_script(b"first push, ", b"second push"), 0),     # two pushes
        (Script(bytes([OP_RETURN])), BURNED_SATS),                  # bare, and destroys sats
    ],
}


def build_op_return_psbt(kind: str, signers: list, script_type: str,
                         num_inputs: int, threshold: int = None) -> PSBT:
    """An ordinary send-with-change psbt plus the OP_RETURN output(s) for `kind`.

    Any sats the OP_RETURN outputs carry come out of change, so the fee stays what
    build_psbt set it to and the transaction still balances. That matters here:
    the whole point of the nonzero_value case is that the device's own arithmetic
    stops balancing, and it would prove nothing if the psbt were unbalanced to
    begin with.

    Note the values are set on the OutputScope, never through psbt.tx.vout[i].
    PSBT.tx rebuilds the transaction from the scopes on every access, so writes
    through it are silently discarded.
    """
    if kind not in _CASES:
        raise ValueError(f"unknown OP_RETURN case: {kind!r}. "
                         f"expected one of {', '.join(_CASES)}")

    psbt = build_psbt(signers, script_type, num_inputs,
                      output_shape="change", threshold=threshold)

    # build_psbt's "change" shape is [external, change], so the change output is last.
    change_output = psbt.outputs[-1]

    for script_pubkey, value in _CASES[kind]():
        output = OutputScope()
        output.script_pubkey = script_pubkey
        output.value = value
        psbt.outputs.append(output)
        change_output.value -= value

    if change_output.value <= 0:
        raise ValueError(f"OP_RETURN case {kind!r} burns more than the change output holds")

    return psbt
