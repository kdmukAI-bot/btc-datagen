/* Typed wrapper over the WASM module built by tools/wasm/build.sh.
 *
 * Everything that crosses the JS/C boundary is copied out of the heap before it
 * is handed back, and every handle owns an explicit free(). WASM memory can be
 * *reallocated* under you when the heap grows (ALLOW_MEMORY_GROWTH detaches the
 * old ArrayBuffer), so a Uint8Array view into `HEAPU8` that outlives a single
 * call is a use-after-free waiting for a big enough allocation. The one place
 * that deliberately holds a live view is the camera path, and it re-derives it
 * on every frame.
 *
 * An ES module rather than a global, so the parity test in node and the site in
 * the browser load exactly the same file — the site reaches it from the classic
 * app.js with a dynamic import().
 */
import createSSQR from './vendor/ssqr.js';

let modulePromise = null;
let mod = null;

/** Load (once) and return the raw emscripten module. */
export function ready() {
  if (!modulePromise) modulePromise = createSSQR().then((m) => { mod = m; return m; });
  return modulePromise;
}

/** True once ready() has resolved — lets callers branch without awaiting. */
export function isReady() { return mod !== null; }

/* ---------- UR decoder states (mirrors ur_decoder.h) ----------------------- */

/* UR_DECODER_OK is 0. A `if (state)` test therefore reads "not finished" as
 * success and vice versa — compare against these names, never truthiness. */
export const UR_OK = 0;
export const UR_PROCESSING = 1;
export const UR_NO_RESULT = 2;
export const UR_ERROR_BASE = 16;

export function urStateIsError(state) { return state >= UR_ERROR_BASE; }
export function urStateIsTerminal(state) {
  return state === UR_OK || state === UR_NO_RESULT
    || state === UR_ERROR_BASE + 6;   // INVALID_CHECKSUM
}

/* ---------- helpers ------------------------------------------------------- */

function withCString(str, fn) {
  const ptr = mod.stringToNewUTF8(str);
  try { return fn(ptr); } finally { mod._free(ptr); }
}

function withBytes(bytes, fn) {
  const ptr = mod._malloc(bytes.length);
  try {
    mod.HEAPU8.set(bytes, ptr);
    return fn(ptr, bytes.length);
  } finally { mod._free(ptr); }
}

/* ---------- UR encoding --------------------------------------------------- */

/* A live ur:crypto-psbt fountain over one PSBT.
 *
 * This is the whole point of the WASM build: the encoder keeps producing
 * distinct parts forever, so the animation never loops the way a pre-generated
 * frame list has to. Parts 1..seqLen are the pure message fragments; everything
 * after is a fresh XOR of a pseudorandom subset, with a sequence number that
 * keeps climbing — exactly what Sparrow puts on screen. */
export class UrPsbtEncoder {
  constructor(psbtBytes, maxFragmentLen, firstSeqNum = 0) {
    this.ptr = withBytes(psbtBytes, (ptr, len) =>
      mod._ssqr_enc_new(ptr, len, maxFragmentLen, firstSeqNum));
    if (!this.ptr) throw new Error('UR encoder could not be created');
    this.seqLen = mod._ssqr_enc_seq_len(this.ptr);
    this.isSinglePart = mod._ssqr_enc_is_single_part(this.ptr) === 1;
    this.seqNum = firstSeqNum;
  }

  /* The next UR part, UPPERCASE.
   *
   * cUR upper-cases inside encode_uri() rather than leaving it to the caller —
   * the same transform Sparrow and SeedSigner apply just before QR encoding, to
   * reach the QR alphanumeric mode. Python's common/ur2 defers it to
   * common/qr.py instead, which is why the parity test compares
   * case-insensitively: same bytewords, different point in the pipeline. UR is
   * case-insensitive on the wire, so nothing downstream cares. */
  next() {
    const ptr = mod._ssqr_enc_next_part(this.ptr);
    if (!ptr) throw new Error('UR encoder returned no part');
    try {
      this.seqNum++;
      return mod.UTF8ToString(ptr);
    } finally { mod._ssqr_free(ptr); }
  }

  free() {
    if (this.ptr) { mod._ssqr_enc_free(this.ptr); this.ptr = 0; }
  }
}

/* ---------- UR decoding --------------------------------------------------- */

export class UrPsbtDecoder {
  constructor() {
    this.ptr = mod._ssqr_dec_new();
    if (!this.ptr) throw new Error('UR decoder could not be created');
  }

  /** Feed one scanned part; returns the decoder state (see UR_* above). */
  receive(part) {
    return withCString(part, (ptr) => mod._ssqr_dec_receive(this.ptr, ptr));
  }

  get state() { return mod._ssqr_dec_state(this.ptr); }
  /** Total pure fragments this message was split into (0 until the first part). */
  get expected() { return mod._ssqr_dec_expected(this.ptr); }
  /** Unique fragments recovered — including ones solved out of mixed frames. */
  get received() { return mod._ssqr_dec_received(this.ptr); }
  /** Every part accepted, mixed ones included. */
  get processed() { return mod._ssqr_dec_processed(this.ptr); }
  /** 0..1, weighted so mixed frames still move the bar. */
  get percent() { return mod._ssqr_dec_percent(this.ptr); }

  /** The reassembled raw PSBT, or null if not finished. */
  psbt() {
    const len = mod._ssqr_dec_psbt(this.ptr);
    if (len < 0) return null;
    const ptr = mod._ssqr_dec_psbt_ptr();
    return mod.HEAPU8.slice(ptr, ptr + len);
  }

  free() {
    if (this.ptr) { mod._ssqr_dec_free(this.ptr); this.ptr = 0; }
  }
}

/* ---------- QR encoding --------------------------------------------------- */

/* Rasterize to a bare module matrix: {m, v, bits}, the same shape the Python
 * build ships for the static QRs (packed row-major, 1 = dark, no quiet zone).
 *
 * The caller upper-cases UR/BBQR payloads first, mirroring common/qr.py.
 * Upper-casing here would be wrong for anything case-sensitive. */
export function qrEncode(text) {
  const m = withCString(text, (ptr) => mod._ssqr_qr_encode(ptr));
  if (!m) throw new Error(`QR encode failed for a ${text.length}-character payload`);
  const bitsPtr = mod._ssqr_qr_bits();
  const bytes = (m * m + 7) >> 3;
  return { m, v: mod._ssqr_qr_version(), bits: mod.HEAPU8.slice(bitsPtr, bitsPtr + bytes) };
}

/* ---------- QR decoding (k_quirc) ----------------------------------------- */

/* Decode QR codes out of a grayscale frame.
 *
 * `gray` must be w*h bytes of luminance. The buffer is copied into k_quirc's
 * own image plane, which it then binarizes in place — so it cannot be a view
 * the caller still needs.
 *
 * Returns the payloads it managed to decode. A frame yielding nothing is the
 * normal case while the camera is still settling, not an error. */
export function qrDecodeGray(gray, w, h, findInverted = false) {
  const bufPtr = mod._ssqr_qrd_begin(w, h);
  if (!bufPtr) return [];
  mod.HEAPU8.set(gray, bufPtr);

  const count = mod._ssqr_qrd_end(findInverted ? 1 : 0);
  const out = [];
  for (let i = 0; i < count; i++) {
    const len = mod._ssqr_qrd_decode(i);
    if (len <= 0) continue;                 // located but unreadable — half a frame
    const ptr = mod._ssqr_qrd_payload();
    out.push(mod.UTF8ToString(ptr, len));
  }
  return out;
}
