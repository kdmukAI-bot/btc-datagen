/* Prove the browser's runtime QR pipeline produces what the Python build says
 * it should — and that what it produces is readable.
 *
 * The site used to ship pre-rendered QR matrices, so there was no second
 * encoder to keep honest. Now the browser generates every animated transaction
 * frame at runtime, and this is the gate that replaces that structural
 * guarantee. For a sample of real transactions it runs the whole loop:
 *
 *     PSBT -> UR fountain -> QR matrix -> image -> QR decode -> UR decode -> PSBT
 *
 * and asserts, at each hop:
 *
 *   parts     identical to the Python reference encoder (case-insensitively —
 *             see below), including deep into the fountain tail. The pure
 *             fragments would match under almost any implementation; the mixed
 *             parts only match if the Xoshiro256 sampler is seeded and stepped
 *             identically, so the tail is where a subtly wrong port shows up.
 *   symbol    same QR version and module count as Python's rasterization, so
 *             mode selection and version fitting cannot drift.
 *   readable  every frame decodes back to its own part, at EC level L and in
 *             alphanumeric mode. That is the real check on `boostEcl=false`
 *             in ssqr.c, and it exercises k_quirc — the same decoder the camera
 *             step uses — on known-good input.
 *   payload   the decoded parts reassemble to the exact PSBT they came from.
 *
 * What it deliberately does NOT assert is byte equality of the module matrices.
 * qrcodegen and python-qrcode pick different masks for roughly 40% of frames
 * (python-qrcode scores candidates with format/version modules blanked to
 * light, and reads penalty rule 3 as a fixed 11-module window). Both are valid;
 * the mask is invisible to a decoder. Asserting version + EC level + mode +
 * payload pins everything that is actually observable.
 *
 * Run:  python -m tools.wasm.reference && node tools/wasm/roundtrip_test.mjs
 */
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, '..', '..');
const FIXTURE = process.argv[2] || join(HERE, 'reference.json');

const ssqr = await import(join(ROOT, 'site', 'ssqr.js'));
const { ready, UrPsbtEncoder, UrPsbtDecoder, qrEncode, qrDecodeGray, UR_OK } = ssqr;
const { verifySignedPsbt } = await import(join(ROOT, 'site', 'psbt.js'));

/* k_quirc constants (k_quirc.h). */
const ECC_LEVEL_L = 1;
const DATA_TYPE_ALPHA = 2;

/* Render scale and quiet zone for the synthetic decode.
 *
 * This is a pristine bitmap, which per docs/knowledge/qr-scannability-and-
 * verification.md is a STRICTER test than a real camera, not a laxer one — no
 * defocus to average anything away. That is the right trade here: this checks
 * that the encoder emits a correct symbol, not that a phone can read a screen.
 * Scannability is a hardware question and this test does not pretend to answer
 * it. */
const SCALE = 5;
const QUIET = 4;

function b64ToBytes(b64) { return new Uint8Array(Buffer.from(b64, 'base64')); }

function bytesEqual(a, b) {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

/** Blit a bare module matrix into a white-bordered grayscale image. */
function renderGray(frame) {
  const grid = frame.m + QUIET * 2;
  const w = grid * SCALE;
  const img = new Uint8Array(w * w).fill(255);
  for (let r = 0; r < frame.m; r++) {
    for (let c = 0; c < frame.m; c++) {
      const i = r * frame.m + c;
      if (!((frame.bits[i >> 3] >> (7 - (i & 7))) & 1)) continue;
      const y0 = (r + QUIET) * SCALE;
      const x0 = (c + QUIET) * SCALE;
      for (let y = y0; y < y0 + SCALE; y++) img.fill(0, y * w + x0, y * w + x0 + SCALE);
    }
  }
  return { img, w };
}

async function main() {
  const mod = await ready();

  let fixture;
  try {
    fixture = JSON.parse(readFileSync(FIXTURE, 'utf8'));
  } catch (e) {
    console.error(`Could not read ${FIXTURE}: ${e.message}`);
    console.error('Generate it first:  python -m tools.wasm.reference');
    process.exit(2);
  }

  const problems = [];
  let framesChecked = 0;

  for (const c of fixture.cases) {
    const label = `${c.id} ${c.density}`;
    const psbt = b64ToBytes(c.psbt_base64);
    const enc = new UrPsbtEncoder(psbt, c.max_fragment);
    const dec = new UrPsbtDecoder();
    const before = problems.length;

    try {
      if (enc.seqLen !== c.seq_len) {
        problems.push(`${label}: seq_len ${enc.seqLen}, expected ${c.seq_len}`);
      }
      if (enc.isSinglePart !== c.single_part) {
        problems.push(`${label}: single_part ${enc.isSinglePart}, expected ${c.single_part}`);
      }

      for (let i = 0; i < c.parts.length; i++) {
        // Case-insensitive on purpose: cUR upper-cases inside the encoder (the
        // alphanumeric-mode trick), while common/ur2 leaves it to
        // common/qr.py. Same transform, applied one step apart, and UR is
        // case-insensitive on the wire.
        const part = enc.next();
        if (part.toUpperCase() !== c.parts[i].toUpperCase()) {
          problems.push(`${label}: part ${i + 1} differs\n`
            + `        got  ${part.slice(0, 72)}...\n`
            + `        want ${c.parts[i].slice(0, 72)}...`);
          break;                   // the fountain has desynced; the rest is noise
        }

        const frame = qrEncode(part.toUpperCase());
        const want = c.frames[i];
        if (frame.m !== want.m || frame.v !== want.v) {
          problems.push(`${label} frame ${i + 1}: v${frame.v}/${frame.m} modules, `
            + `Python said v${want.v}/${want.m}`);
          continue;
        }

        const { img, w } = renderGray(frame);
        const decoded = qrDecodeGray(img, w, w);
        if (decoded.length !== 1) {
          problems.push(`${label} frame ${i + 1}: decoded ${decoded.length} codes, expected 1`);
          continue;
        }
        if (decoded[0] !== part.toUpperCase()) {
          problems.push(`${label} frame ${i + 1}: decoded payload does not match the part`);
          continue;
        }
        const ecc = mod._ssqr_qrd_ecc_level();
        const mode = mod._ssqr_qrd_data_type();
        if (ecc !== ECC_LEVEL_L) {
          problems.push(`${label} frame ${i + 1}: EC level ${ecc}, expected L (${ECC_LEVEL_L}) `
            + `— boostEcl leaked back on?`);
        }
        if (mode !== DATA_TYPE_ALPHA) {
          problems.push(`${label} frame ${i + 1}: QR mode ${mode}, expected alphanumeric `
            + `(${DATA_TYPE_ALPHA}) — was the payload upper-cased?`);
        }

        dec.receive(decoded[0]);
        framesChecked++;
      }

      // The decoder should be done well before the pure set runs out, since the
      // fixture feeds every frame in order.
      if (dec.state !== UR_OK) {
        problems.push(`${label}: UR decoder ended in state ${dec.state}, expected OK `
          + `(${dec.received}/${dec.expected} fragments)`);
      } else if (!bytesEqual(dec.psbt(), psbt)) {
        problems.push(`${label}: reassembled PSBT differs from the source`);
      }
    } finally {
      enc.free();
      dec.free();
    }

    // Far-downstream spot checks: each starts its own encoder at a high sequence
    // number, which also asserts the fountain is a pure function of the sequence
    // number rather than of how many parts have already been pulled.
    for (const far of c.far) {
      const farEnc = new UrPsbtEncoder(psbt, c.max_fragment, far.seq);
      try {
        const part = farEnc.next();
        if (part.toUpperCase() !== far.part.toUpperCase()) {
          problems.push(`${label}: part at seq ${far.seq} differs\n`
            + `        got  ${part.slice(0, 72)}...\n`
            + `        want ${far.part.slice(0, 72)}...`);
          continue;
        }
        const frame = qrEncode(part.toUpperCase());
        if (frame.m !== far.frame.m || frame.v !== far.frame.v) {
          problems.push(`${label} frame at seq ${far.seq}: v${frame.v}/${frame.m} modules, `
            + `Python said v${far.frame.v}/${far.frame.m}`);
          continue;
        }
        const { img, w } = renderGray(frame);
        const decoded = qrDecodeGray(img, w, w);
        if (decoded.length !== 1 || decoded[0] !== part.toUpperCase()) {
          problems.push(`${label} frame at seq ${far.seq}: did not decode back to its part`);
          continue;
        }
        framesChecked++;
      } finally {
        farEnc.free();
      }
    }

    const status = problems.length === before ? 'OK' : 'FAIL';
    console.log(`  ${label.padEnd(52)} ${String(c.parts.length + c.far.length).padStart(4)} frames  ${status}`);
  }

  /* --- signature verification (site/psbt.js) ------------------------------
   *
   * The positive cases show the verifier accepts a real signature. The negative
   * ones are the point: a checker that cannot say NO is decoration. Each
   * fixture states what it expects and any deviation is a failure, so
   * "tampered" passing as valid fails just as loudly as "signed" failing.
   */
  console.log();
  let signingChecked = 0;
  for (const c of fixture.signing || []) {
    const before = problems.length;
    let report;
    try {
      report = await verifySignedPsbt(b64ToBytes(c.psbt_base64), c.verify);
    } catch (e) {
      problems.push(`${c.label}: verifier threw — ${e.message}`);
      console.log(`  ${c.label.padEnd(52)} FAIL`);
      continue;
    }

    for (const [field, want] of Object.entries(c.expect)) {
      if (report[field] !== want) {
        problems.push(`${c.label}: ${field} is ${report[field]}, expected ${want}`);
      }
    }
    if (report.txMatches && report.txid !== c.verify.txid) {
      problems.push(`${c.label}: txid ${report.txid}, expected ${c.verify.txid}`);
    }
    for (const seed of c.expect_signers || []) {
      if (!report.signers.some((s) => s.seed === seed)) {
        problems.push(`${c.label}: expected a valid signature from "${seed}", `
          + `got [${report.signers.map((s) => s.seed).join(', ')}]`);
      }
    }
    signingChecked++;
    console.log(`  ${c.label.padEnd(52)} ${problems.length === before ? 'OK' : 'FAIL'}`);
  }

  console.log();
  if (problems.length) {
    for (const p of problems) console.error(`  - ${p}`);
    console.error(`\nFAILED — ${problems.length} problem(s) across ${framesChecked} frames `
      + `and ${signingChecked} signing cases`);
    process.exit(1);
  }
  console.log(`PASS — ${framesChecked} frames encoded, rasterized, decoded and reassembled; `
    + `${signingChecked} signing cases verified`);
}

await main();
