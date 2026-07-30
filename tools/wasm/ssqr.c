/* ssqr.c — the whole C surface the demo site talks to, in one WASM module.
 *
 * Four jobs, three upstream libraries:
 *
 *   UR encode   (cUR)       generate ur:crypto-psbt frames forever, the way a
 *                           real fountain encoder does, instead of replaying a
 *                           finite tail baked at build time.
 *   UR decode   (cUR)       reassemble the SIGNED PSBT the SeedSigner shows on
 *                           its screen, with live progress while it arrives.
 *   QR encode   (qrcodegen) rasterize each generated frame at Sparrow's exact
 *                           zxing settings.
 *   QR decode   (k_quirc)   read the device's screen through the phone camera.
 *
 * Why these libraries and not JS equivalents: cUR is the codec the ESP32
 * firmware runs and k_quirc is the decoder it scans with, so the browser is
 * exercising the same code the hardware does rather than something merely
 * compatible. qrcodegen is here because it exposes the knobs Sparrow's zxing
 * call actually uses (fixed EC level with NO automatic boost, smallest fitting
 * version, automatic mask) — which is what makes byte-equality with the Python
 * `qrcode` output an assertable property rather than a hope. tools/verify.py
 * asserts exactly that.
 *
 * Calling convention notes for the JS side (site/ssqr.js):
 *   - Anything that returns a buffer writes it to a module-level slot and
 *     returns its length; a companion _ptr() accessor gives the address. Out
 *     parameters through double pointers are miserable from ccall, and the
 *     alternative — malloc per call — leaks the moment an exception unwinds.
 *   - Strings coming back from cUR ARE malloc'd by cUR and must be released
 *     with ssqr_free().
 */

#include <emscripten.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "k_quirc.h"
#include "qrcodegen.h"
#include "types/psbt.h"
#include "ur_decoder.h"
#include "ur_encoder.h"

/* Sparrow's MIN_FRAGMENT_LENGTH. Mirrors MIN_FRAGMENT_BYTES in
 * tools/build_site.py — the two must agree or the browser and the build-time
 * verifier partition the message differently. */
#define SSQR_MIN_FRAGMENT_LEN 10

EMSCRIPTEN_KEEPALIVE
void ssqr_free(void *p) { free(p); }

/* ---------- UR encoder ---------------------------------------------------- */

/* Build an encoder over a raw (binary) PSBT, wrapped as crypto-psbt CBOR.
 *
 * `first_seq_num` is 0 in normal use. It exists so the parity test can start a
 * second encoder mid-stream and confirm the fountain is a pure function of the
 * sequence number rather than of encoder history. */
EMSCRIPTEN_KEEPALIVE
ur_encoder_t *ssqr_enc_new(const uint8_t *psbt_bytes, int psbt_len,
                           int max_fragment_len, int first_seq_num) {
  if (!psbt_bytes || psbt_len <= 0 || max_fragment_len <= 0)
    return NULL;

  psbt_data_t *psbt = psbt_new(psbt_bytes, (size_t)psbt_len);
  if (!psbt)
    return NULL;

  size_t cbor_len = 0;
  uint8_t *cbor = psbt_to_cbor(psbt, &cbor_len);
  psbt_free(psbt);
  if (!cbor)
    return NULL;

  /* ur_encoder_new partitions the payload into its own fragment storage, so the
   * CBOR buffer is ours to release immediately. */
  ur_encoder_t *enc =
      ur_encoder_new("crypto-psbt", cbor, cbor_len, (size_t)max_fragment_len,
                     (uint32_t)first_seq_num, SSQR_MIN_FRAGMENT_LEN);
  free(cbor);
  return enc;
}

EMSCRIPTEN_KEEPALIVE
int ssqr_enc_seq_len(ur_encoder_t *enc) {
  return enc ? (int)ur_encoder_seq_len(enc) : 0;
}

EMSCRIPTEN_KEEPALIVE
int ssqr_enc_is_single_part(ur_encoder_t *enc) {
  return (enc && ur_encoder_is_single_part(enc)) ? 1 : 0;
}

/* Returns a malloc'd NUL-terminated UR part string; release with ssqr_free. */
EMSCRIPTEN_KEEPALIVE
char *ssqr_enc_next_part(ur_encoder_t *enc) {
  char *part = NULL;
  if (!enc || !ur_encoder_next_part(enc, &part))
    return NULL;
  return part;
}

EMSCRIPTEN_KEEPALIVE
void ssqr_enc_free(ur_encoder_t *enc) { ur_encoder_free(enc); }

/* ---------- UR decoder ---------------------------------------------------- */

EMSCRIPTEN_KEEPALIVE
ur_decoder_t *ssqr_dec_new(void) { return ur_decoder_new(); }

/* Returns ur_decoder_state_t. NOTE for the JS side: UR_DECODER_OK == 0, so this
 * must never be read as a boolean — 0 means finished, not failed. */
EMSCRIPTEN_KEEPALIVE
int ssqr_dec_receive(ur_decoder_t *dec, const char *part) {
  return (int)ur_decoder_receive_part(dec, part);
}

EMSCRIPTEN_KEEPALIVE
int ssqr_dec_state(ur_decoder_t *dec) {
  return (int)ur_decoder_get_state(dec);
}

EMSCRIPTEN_KEEPALIVE
int ssqr_dec_expected(ur_decoder_t *dec) {
  return dec ? (int)ur_decoder_expected_part_count(dec) : 0;
}

/* Unique pure fragments recovered — including ones solved out of mixed frames,
 * which is why this can exceed the number of pure frames actually seen. */
EMSCRIPTEN_KEEPALIVE
int ssqr_dec_received(ur_decoder_t *dec) {
  return dec ? (int)ur_decoder_received_parts_count(dec) : 0;
}

EMSCRIPTEN_KEEPALIVE
int ssqr_dec_processed(ur_decoder_t *dec) {
  return dec ? (int)ur_decoder_processed_parts_count(dec) : 0;
}

/* Weighted estimate (0..1): gives partial credit for fragments that are so far
 * only present inside mixed frames, so the progress bar keeps moving during the
 * fountain tail instead of sitting still. */
EMSCRIPTEN_KEEPALIVE
double ssqr_dec_percent(ur_decoder_t *dec) {
  return dec ? (double)ur_decoder_estimated_percent_complete_weighted(dec) : 0.0;
}

EMSCRIPTEN_KEEPALIVE
const char *ssqr_dec_type(ur_decoder_t *dec) {
  ur_result_t *result = dec ? ur_decoder_get_result(dec) : NULL;
  return result ? result->type : NULL;
}

static uint8_t *g_psbt = NULL;
static int g_psbt_len = 0;

/* Unwrap the decoded crypto-psbt CBOR into a raw PSBT. Returns its length (or
 * -1), with the bytes at ssqr_dec_psbt_ptr(). Valid until the next call. */
EMSCRIPTEN_KEEPALIVE
int ssqr_dec_psbt(ur_decoder_t *dec) {
  free(g_psbt);
  g_psbt = NULL;
  g_psbt_len = 0;

  ur_result_t *result = dec ? ur_decoder_get_result(dec) : NULL;
  if (!result)
    return -1;

  psbt_data_t *psbt = psbt_from_cbor(result->cbor_data, result->cbor_len);
  if (!psbt)
    return -1;

  size_t len = 0;
  const uint8_t *data = psbt_get_data(psbt, &len);
  if (data && len) {
    g_psbt = malloc(len);
    if (g_psbt) {
      memcpy(g_psbt, data, len);
      g_psbt_len = (int)len;
    }
  }
  psbt_free(psbt);
  return g_psbt ? g_psbt_len : -1;
}

EMSCRIPTEN_KEEPALIVE
const uint8_t *ssqr_dec_psbt_ptr(void) { return g_psbt; }

EMSCRIPTEN_KEEPALIVE
void ssqr_dec_free(ur_decoder_t *dec) { ur_decoder_free(dec); }

/* ---------- QR encode ----------------------------------------------------- */

/* Version 40 is 177x177. The site never gets near it (UR frames land around
 * version 10-20), but sizing to the format maximum means a density slider can
 * never walk off the end of the buffer. */
#define SSQR_MAX_MODULES 177
#define SSQR_BITS_BYTES ((SSQR_MAX_MODULES * SSQR_MAX_MODULES + 7) / 8)

static uint8_t g_qr[qrcodegen_BUFFER_LEN_MAX];
static uint8_t g_qr_scratch[qrcodegen_BUFFER_LEN_MAX];
static uint8_t g_qr_bits[SSQR_BITS_BYTES];
static int g_qr_version = 0;

/* Rasterize `text` to a bare module matrix at Sparrow's zxing settings.
 * Returns the module count per side, or 0 if the text does not fit.
 *
 * boostEcl is FALSE deliberately. zxing encodes at the level it was asked for;
 * qrcodegen will silently promote L to M/Q/H when the chosen version has room
 * to spare, which produces a perfectly valid QR carrying a different number of
 * data codewords than Sparrow would show. tools/wasm/roundtrip_test.mjs pins
 * this by decoding the result and asserting the EC level comes back L.
 *
 * On the MASK: this does NOT reproduce python-qrcode's choice, and cannot
 * cheaply. python-qrcode scores candidate masks on a matrix with the format and
 * version information blanked to light (`makeImpl(test=True, ...)`), and its
 * rule-3 penalty scans a fixed 11-module window; qrcodegen scores with the real
 * format bits drawn and uses the run-based finder-pattern rule. Both are
 * legitimate readings of the penalty rules and they disagree on roughly 40% of
 * frames. The mask is invisible to a decoder — same data, same version, same EC
 * level, and every mask decodes identically — so the round-trip test verifies
 * what actually matters (payload, version, EC level, mode) instead of byte
 * equality with a second encoder's arbitrary-but-valid pick.
 *
 * The caller upper-cases UR/BBQR payloads before getting here, mirroring
 * common/qr.py — it must NOT happen in here, because the same rasterizer also
 * has to handle case-sensitive payloads. */
EMSCRIPTEN_KEEPALIVE
int ssqr_qr_encode(const char *text) {
  g_qr_version = 0;
  if (!text)
    return 0;
  if (!qrcodegen_encodeText(text, g_qr_scratch, g_qr, qrcodegen_Ecc_LOW,
                            qrcodegen_VERSION_MIN, qrcodegen_VERSION_MAX,
                            qrcodegen_Mask_AUTO, /*boostEcl=*/false))
    return 0;

  const int size = qrcodegen_getSize(g_qr);
  memset(g_qr_bits, 0, (size_t)(size * size + 7) / 8);
  int i = 0;
  for (int y = 0; y < size; y++) {
    for (int x = 0; x < size; x++, i++) {
      if (qrcodegen_getModule(g_qr, x, y))
        g_qr_bits[i >> 3] |= (uint8_t)(1 << (7 - (i & 7)));
    }
  }
  g_qr_version = (size - 17) / 4;
  return size;
}

/* Packed row-major bits, 1 = dark, no quiet zone — the same layout
 * common/qr.py `_pack` produces, so both ends of the verifier speak one format.
 */
EMSCRIPTEN_KEEPALIVE
const uint8_t *ssqr_qr_bits(void) { return g_qr_bits; }

EMSCRIPTEN_KEEPALIVE
int ssqr_qr_version(void) { return g_qr_version; }

/* ---------- QR decode ----------------------------------------------------- */

static k_quirc_t *g_quirc = NULL;
static int g_quirc_w = 0, g_quirc_h = 0;
static k_quirc_result_t g_quirc_result;

/* Hand back the decoder's own grayscale buffer for the caller to fill; returns
 * NULL if the context could not be sized. Resizing reallocates, so it is only
 * done when the dimensions actually change — a camera frame size is stable for
 * the life of a stream, and reallocating per frame would churn the heap at
 * 30 fps. */
EMSCRIPTEN_KEEPALIVE
uint8_t *ssqr_qrd_begin(int w, int h) {
  if (w <= 0 || h <= 0)
    return NULL;
  if (!g_quirc) {
    g_quirc = k_quirc_new();
    if (!g_quirc)
      return NULL;
  }
  if (w != g_quirc_w || h != g_quirc_h) {
    if (k_quirc_resize(g_quirc, w, h) < 0) {
      g_quirc_w = g_quirc_h = 0;
      return NULL;
    }
    g_quirc_w = w;
    g_quirc_h = h;
  }
  return k_quirc_begin(g_quirc, NULL, NULL);
}

/* Process the filled buffer; returns how many codes were located.
 *
 * find_inverted is off for this site's purposes: a SeedSigner shows dark-on-
 * light, and the inverted pass roughly doubles identification cost for frames
 * that will never match. */
EMSCRIPTEN_KEEPALIVE
int ssqr_qrd_end(int find_inverted) {
  if (!g_quirc)
    return 0;
  k_quirc_end(g_quirc, find_inverted != 0);
  return k_quirc_count(g_quirc);
}

/* Decode located code `index`. Returns its payload length, or the negated
 * k_quirc_error_t on failure (so -3 is K_QUIRC_ERROR_FORMAT_ECC). A located
 * code that fails to decode is completely normal — it is what a half-captured
 * frame looks like. */
EMSCRIPTEN_KEEPALIVE
int ssqr_qrd_decode(int index) {
  if (!g_quirc)
    return -1;
  k_quirc_error_t err = k_quirc_decode(g_quirc, index, &g_quirc_result);
  if (err != K_QUIRC_SUCCESS)
    return -(int)err;
  return g_quirc_result.data.payload_len;
}

EMSCRIPTEN_KEEPALIVE
const uint8_t *ssqr_qrd_payload(void) { return g_quirc_result.data.payload; }

/* QR data mode of the last decode (K_QUIRC_DATA_TYPE_ALPHA for Sparrow-style
 * upper-cased UR frames, _BYTE for a CompactSeedQR). */
EMSCRIPTEN_KEEPALIVE
int ssqr_qrd_data_type(void) { return g_quirc_result.data.data_type; }

/* Error-correction level of the last decode (K_QUIRC_ECC_LEVEL_L == 1).
 *
 * Exposed for the round-trip test rather than for the site. It is the direct
 * check on `boostEcl=false` in ssqr_qr_encode: if that ever flips, the symbol
 * stays perfectly valid and perfectly scannable, and the only visible evidence
 * is the EC level reported here coming back as something other than L. */
EMSCRIPTEN_KEEPALIVE
int ssqr_qrd_ecc_level(void) { return g_quirc_result.data.ecc_level; }

EMSCRIPTEN_KEEPALIVE
int ssqr_qrd_qr_version(void) { return g_quirc_result.data.version; }
