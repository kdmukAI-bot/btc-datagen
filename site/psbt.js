/* Read the PSBT a SeedSigner hands back, and check that its signatures are real.
 *
 * Scope on purpose: this parses only enough PSBT to answer one question — "did
 * this device produce valid signatures over the transaction this page sent?" It
 * is not a general PSBT library and should not grow into one.
 *
 * What "valid" means here, precisely, because the distinction matters and the
 * UI says it out loud:
 *
 *   1. the returned PSBT's global unsigned transaction is BYTE-IDENTICAL to the
 *      one we sent (so the device did not sign some other transaction), and
 *   2. each signature verifies, on the secp256k1 curve, against the sighash
 *      digest for that input — a digest computed at build time by embit and
 *      shipped alongside the scenario (see verification_data in
 *      tools/build_site.py).
 *
 * The digest is precomputed rather than derived in the browser because deriving
 * it means implementing BIP143, BIP341 and the legacy algorithm in JavaScript:
 * three chances to be subtly wrong in the one place where being subtly wrong
 * shows a confident green tick. Check (1) is what keeps (2) honest — a
 * signature over our digest is only interesting because the transaction the
 * digest describes is provably the one that came back.
 */
import * as secp from './vendor/noble-secp256k1.js';

const PSBT_MAGIC = [0x70, 0x73, 0x62, 0x74, 0xff];   // "psbt\xff"

/* The handful of PSBT key types this needs. */
const GLOBAL_UNSIGNED_TX = 0x00;
const IN_PARTIAL_SIG = 0x02;
const IN_FINAL_SCRIPTWITNESS = 0x08;
const IN_TAP_KEY_SIG = 0x13;

const hex = (bytes) => Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');

export function bytesFromHex(s) {
  const out = new Uint8Array(s.length >> 1);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(s.substr(i * 2, 2), 16);
  return out;
}

function bytesEqual(a, b) {
  if (!a || !b || a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

/* ---------- byte reader --------------------------------------------------- */

class Reader {
  constructor(bytes) { this.b = bytes; this.pos = 0; }
  get done() { return this.pos >= this.b.length; }

  u8() {
    if (this.pos >= this.b.length) throw new Error('truncated PSBT');
    return this.b[this.pos++];
  }

  /** Bitcoin compact size. */
  varint() {
    const first = this.u8();
    if (first < 0xfd) return first;
    let n = first === 0xfd ? 2 : first === 0xfe ? 4 : 8;
    let value = 0;
    for (let i = 0; i < n; i++) value += this.u8() * 2 ** (8 * i);
    return value;
  }

  take(n) {
    if (this.pos + n > this.b.length) throw new Error('truncated PSBT');
    const out = this.b.subarray(this.pos, this.pos + n);
    this.pos += n;
    return out;
  }
}

/* ---------- PSBT ---------------------------------------------------------- */

/* One key-value map, up to its 0x00 terminator. Returns [{type, keyData, value}]. */
function readMap(r) {
  const records = [];
  for (;;) {
    const keyLen = r.varint();
    if (keyLen === 0) return records;            // separator ends the map
    const key = r.take(keyLen);
    const value = r.take(r.varint());
    records.push({ type: key[0], keyData: key.subarray(1), value });
  }
}

/* How many inputs the unsigned transaction has.
 *
 * A PSBT's global transaction is serialized WITHOUT witnesses, so there is no
 * segwit marker/flag to skip: 4-byte version, then the input count. That is all
 * this needs — the input maps that follow are counted, not the transaction. */
function inputCount(txBytes) {
  const r = new Reader(txBytes);
  r.take(4);
  return r.varint();
}

export function parsePsbt(bytes) {
  const r = new Reader(bytes);
  for (const b of PSBT_MAGIC) {
    if (r.u8() !== b) throw new Error('not a PSBT (bad magic bytes)');
  }

  const global = readMap(r);
  const txRecord = global.find((rec) => rec.type === GLOBAL_UNSIGNED_TX);
  if (!txRecord) throw new Error('PSBT has no unsigned transaction');
  const unsignedTx = txRecord.value;

  const inputs = [];
  for (let i = 0, n = inputCount(unsignedTx); i < n; i++) {
    const records = readMap(r);
    const partialSigs = new Map();
    let tapKeySig = null;

    for (const rec of records) {
      if (rec.type === IN_PARTIAL_SIG) {
        partialSigs.set(hex(rec.keyData), rec.value);
      } else if (rec.type === IN_TAP_KEY_SIG) {
        tapKeySig = rec.value;
      } else if (rec.type === IN_FINAL_SCRIPTWITNESS && !tapKeySig) {
        // embit finalizes a taproot key-path spend straight into the witness
        // rather than leaving a TAP_KEY_SIG field, and a device may do either.
        // A key-path witness is exactly one 64- or 65-byte element.
        const w = new Reader(rec.value);
        if (w.varint() === 1) {
          const item = w.take(w.varint());
          if (item.length === 64 || item.length === 65) tapKeySig = item;
        }
      }
    }
    inputs.push({ partialSigs, tapKeySig });
  }

  return { unsignedTx, inputs };
}

/** Transaction id: double-SHA256 of the unsigned transaction, byte-reversed. */
export async function txidOf(unsignedTx) {
  const once = await crypto.subtle.digest('SHA-256', unsignedTx);
  const twice = new Uint8Array(await crypto.subtle.digest('SHA-256', once));
  return hex(twice.reverse());
}

/* ---------- signatures ---------------------------------------------------- */

/* DER -> the 64-byte compact form noble wants.
 *
 * @noble/secp256k1 v3 dropped DER support (it lives in noble-curves now), and
 * pulling in a second library to reshape 70 bytes would be silly. Bitcoin
 * signatures are strict DER: 0x30 <len> 0x02 <rlen> r 0x02 <slen> s, with r and
 * s big-endian, minimally encoded, and carrying a leading 0x00 when the high
 * bit would otherwise make them look negative. */
function derToCompact(der) {
  if (der[0] !== 0x30) throw new Error('signature is not DER');
  let i = 2;
  const readInt = () => {
    if (der[i++] !== 0x02) throw new Error('malformed DER integer');
    const len = der[i++];
    const value = der.subarray(i, i + len);
    i += len;
    return value;
  };
  const r = readInt();
  const s = readInt();
  const out = new Uint8Array(64);
  const place = (v, offset) => {
    const trimmed = v[0] === 0 ? v.subarray(1) : v;
    if (trimmed.length > 32) throw new Error('DER integer too long');
    out.set(trimmed, offset + 32 - trimmed.length);
  };
  place(r, 0);
  place(s, 32);
  return out;
}

/* SIGHASH_ALL. Anything else and our precomputed digest describes a different
 * commitment, so the check would fail for a reason worth naming. */
const SIGHASH_ALL = 0x01;

async function checkInput(inp, expected, taproot) {
  const results = [];

  if (taproot) {
    if (!inp.tapKeySig) return results;
    const key = expected.keys[0];
    // A 65-byte Schnorr signature carries an explicit sighash flag; 64 means
    // SIGHASH_DEFAULT, which is what our digest was computed for.
    const sig = inp.tapKeySig.subarray(0, 64);
    const flagged = inp.tapKeySig.length === 65 ? inp.tapKeySig[64] : 0x00;
    let valid = false;
    let note = null;
    if (flagged !== 0x00) {
      note = `sighash flag 0x${flagged.toString(16)}, expected DEFAULT`;
    } else {
      valid = await secp.schnorr.verifyAsync(sig, bytesFromHex(expected.sighash),
                                             bytesFromHex(key.pubkey));
    }
    results.push({ ...key, valid, note, scheme: 'schnorr' });
    return results;
  }

  for (const [pubkeyHex, sigBytes] of inp.partialSigs) {
    const key = expected.keys.find((k) => k.pubkey === pubkeyHex)
      || { pubkey: pubkeyHex, fingerprint: null, seed: null, unexpected: true };
    const flag = sigBytes[sigBytes.length - 1];
    let valid = false;
    let note = null;
    if (flag !== SIGHASH_ALL) {
      note = `sighash type 0x${flag.toString(16)}, expected SIGHASH_ALL`;
    } else if (key.unexpected) {
      note = 'signed by a key this wallet does not contain';
    } else {
      try {
        valid = secp.verify(derToCompact(sigBytes.subarray(0, sigBytes.length - 1)),
                            bytesFromHex(expected.sighash),
                            bytesFromHex(key.pubkey),
                            { prehash: false });
      } catch (e) {
        note = e.message;
      }
    }
    results.push({ ...key, valid, note, scheme: 'ecdsa' });
  }
  return results;
}

/* Verify a scanned PSBT against a scenario's shipped `verify` block.
 *
 * Never throws for a *failed* check — a wrong or unsigned PSBT is a result, not
 * an exception. It does throw if the bytes are not a PSBT at all. */
export async function verifySignedPsbt(psbtBytes, expected) {
  const parsed = parsePsbt(psbtBytes);
  const txMatches = bytesEqual(parsed.unsignedTx, bytesFromHex(expected.unsigned_tx));
  const txid = await txidOf(parsed.unsignedTx);

  const inputs = [];
  for (let i = 0; i < expected.inputs.length; i++) {
    const parsedInput = parsed.inputs[i];
    const sigs = parsedInput
      ? await checkInput(parsedInput, expected.inputs[i], expected.taproot)
      : [];
    inputs.push({
      index: i,
      needed: expected.threshold,
      sigs,
      valid: sigs.filter((s) => s.valid).length,
    });
  }

  const signers = new Map();
  for (const inp of inputs) {
    for (const s of inp.sigs) {
      if (s.valid && s.seed) signers.set(s.seed, s.fingerprint);
    }
  }

  const everyInputSatisfied = inputs.length > 0
    && inputs.every((inp) => inp.valid >= inp.needed);
  const anyInvalid = inputs.some((inp) => inp.sigs.some((s) => !s.valid));

  return {
    txid,
    txMatches,
    inputs,
    signers: [...signers].map(([seed, fingerprint]) => ({ seed, fingerprint })),
    // Complete means: our transaction, every input at threshold, nothing
    // rejected. A 2-of-3 signed by one cosigner is a correct partial result and
    // reports as such rather than as a failure.
    complete: txMatches && everyInputSatisfied && !anyInvalid,
    partial: txMatches && !everyInputSatisfied
      && inputs.some((inp) => inp.valid > 0) && !anyInvalid,
    anyInvalid,
  };
}
