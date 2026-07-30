/* Read the signed transaction back off the SeedSigner's screen.
 *
 * The device finishes signing and shows the signed PSBT as its own animated
 * ur:crypto-psbt. This points the phone camera at that, decodes the frames with
 * k_quirc — SeedSigner's own QR decoder, compiled to WASM — and reassembles the
 * PSBT with cUR's fountain decoder, which is the same codec the ESP32 firmware
 * runs. So the browser is not merely compatible with the device; it is running
 * the device's code in the opposite direction.
 *
 * Everything is on the main thread. A worker would keep the UI perfectly smooth,
 * but it would also need its own copy of the WASM module and a copy of every
 * frame across the postMessage boundary, and the measured cost here is a ~10ms
 * block a dozen times a second. Video decode happens off-thread regardless, so
 * the preview stays fluid.
 */
import { ready, UrPsbtDecoder, qrDecodeGray, UR_OK, urStateIsError, urStateIsTerminal }
  from './ssqr.js';

/* Longest edge of the frame actually handed to the decoder.
 *
 * Not the camera's resolution — the camera is asked for 1280x720 and downscaled
 * to this. The decoder needs roughly 3 device pixels per QR module to binarize
 * reliably; a version-16 symbol is 85 modules, so if it fills half the frame
 * width that wants ~510px of frame for the symbol alone. 800 leaves margin for
 * a device held at arm's length without paying for a full 720p pass through
 * quirc's identification stage on every frame. */
const PROCESS_LONG_EDGE = 800;

/* Decode attempts per second. The camera delivers 30fps and there is nothing to
   gain from decoding every frame: the animation on the device runs at 5fps by
   default, so 15 passes a second already sees each displayed frame ~3 times. */
const DECODE_HZ = 15;

const UR_PSBT_PREFIX = 'ur:crypto-psbt/';
/* Enough of a BBQR header to recognise one: 'B$' then two type letters. Worth
   detecting only so the UI can say "switch the device to UR" rather than
   sitting at 0% while the user assumes the camera is broken. */
const BBQR_RE = /^B\$[0-9A-Z]{2}/;

/* `ur:crypto-psbt/12-15/...` — sequence number and count. Absent on a
   single-part UR, which carries no fountain header at all. */
const UR_SEQ_RE = /^ur:crypto-psbt\/(\d+)-(\d+)\//i;

export class SignedPsbtScanner {
  /**
   * @param video       a <video> element to show the preview in
   * @param onProgress  called with a progress snapshot after every decode pass
   *                    that changed something
   * @param onComplete  called with the reassembled PSBT bytes (Uint8Array)
   * @param onError     called with a human-readable string; scanning has stopped
   */
  constructor({ video, onProgress, onComplete, onError }) {
    this.video = video;
    this.onProgress = onProgress || (() => {});
    this.onComplete = onComplete || (() => {});
    this.onError = onError || (() => {});

    this.stream = null;
    this.decoder = null;
    this.running = false;
    this.lastPass = 0;
    this.frames = 0;          // camera frames seen
    this.passes = 0;          // decode attempts
    this.reads = 0;           // frames a QR was actually read from

    /* Which PURE fragments were read directly off the screen, as opposed to
     * solved out of XOR'd mixed frames.
     *
     * Not used to place anything on screen — the decoder reports how many
     * fragments it holds but not which, and against real hardware the directly
     * read set is usually EMPTY anyway: a device shows its pure fragments once
     * and then runs the fountain indefinitely, so a camera that takes a second
     * to focus never sees one. This exists only so the UI can say how much of
     * the transaction was reconstructed rather than read, which is the more
     * interesting number at a demo table and is otherwise invisible. */
    this.direct = new Set();
    this.note = null;
  }

  async start() {
    if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
      // Almost always the secure-context rule rather than a missing feature:
      // getUserMedia is unavailable over plain http:// except on localhost, and
      // testing on a phone means hitting the dev server by LAN IP.
      this.onError('This browser will not open a camera on an insecure page. '
        + 'The live site is https; for local testing use '
        + '`python -m tools.serve --tls` and accept the certificate warning.');
      return false;
    }

    await ready();

    try {
      this.stream = await navigator.mediaDevices.getUserMedia({
        video: {
          facingMode: { ideal: 'environment' },
          width: { ideal: 1280 },
          height: { ideal: 720 },
        },
        audio: false,
      });
    } catch (e) {
      this.onError(e.name === 'NotAllowedError'
        ? 'Camera permission was declined.'
        : `Could not open the camera: ${e.message}`);
      return false;
    }

    this.video.srcObject = this.stream;
    this.video.setAttribute('playsinline', '');   // iOS: do not go fullscreen
    this.video.muted = true;
    try {
      await this.video.play();
    } catch (e) {
      this.onError(`Could not start the camera preview: ${e.message}`);
      this.stop();
      return false;
    }

    this.decoder = new UrPsbtDecoder();
    this.running = true;
    this._schedule();
    return true;
  }

  stop() {
    this.running = false;
    if (this.stream) {
      this.stream.getTracks().forEach((t) => t.stop());
      this.stream = null;
    }
    if (this.video) this.video.srcObject = null;
    if (this.decoder) { this.decoder.free(); this.decoder = null; }
  }

  /* Progress snapshot for the UI. Deliberately reports "read" and
     "reconstructed" separately — see the note on `this.direct`. */
  snapshot() {
    const expected = this.decoder ? this.decoder.expected : 0;
    const received = this.decoder ? this.decoder.received : 0;
    return {
      expected,
      received,
      direct: this.direct,
      // Fragments the decoder solved out of mixed frames rather than reading.
      reconstructed: Math.max(0, received - this.direct.size),
      percent: this.decoder ? this.decoder.percent : 0,
      processed: this.decoder ? this.decoder.processed : 0,
      frames: this.frames,
      reads: this.reads,
      note: this.note,
    };
  }

  _schedule() {
    if (!this.running) return;
    // requestVideoFrameCallback fires once per decoded video frame, so passes
    // line up with actual new pixels instead of with the compositor.
    if (this.video.requestVideoFrameCallback) {
      this.video.requestVideoFrameCallback(() => this._onFrame());
    } else {
      requestAnimationFrame(() => this._onFrame());
    }
  }

  _onFrame() {
    if (!this.running) return;
    this.frames++;
    const now = performance.now();
    if (now - this.lastPass >= 1000 / DECODE_HZ) {
      this.lastPass = now;
      try {
        this._decodePass();
      } catch (e) {
        this.onError(`Scanning failed: ${e.message}`);
        this.stop();
        return;
      }
    }
    this._schedule();
  }

  /* Downscale the current video frame into a grayscale buffer sized for the
     decoder. The canvas is created once and reused; allocating a 480,000-byte
     buffer fifteen times a second would keep the collector permanently busy. */
  _grayFrame() {
    const vw = this.video.videoWidth;
    const vh = this.video.videoHeight;
    if (!vw || !vh) return null;

    const scale = Math.min(1, PROCESS_LONG_EDGE / Math.max(vw, vh));
    const w = Math.max(1, Math.round(vw * scale));
    const h = Math.max(1, Math.round(vh * scale));

    if (!this.canvas || this.canvas.width !== w || this.canvas.height !== h) {
      this.canvas = document.createElement('canvas');
      this.canvas.width = w;
      this.canvas.height = h;
      // willReadFrequently keeps the canvas on the CPU side; without it every
      // getImageData is a GPU readback stall.
      this.ctx = this.canvas.getContext('2d', { willReadFrequently: true });
      this.gray = new Uint8Array(w * h);
    }

    this.ctx.drawImage(this.video, 0, 0, w, h);
    const { data } = this.ctx.getImageData(0, 0, w, h);
    const gray = this.gray;
    // Integer Rec.601 luma. Matching a specific colour standard matters less
    // than being cheap and monotonic — the decoder only needs to tell ink from
    // paper.
    for (let i = 0, p = 0; i < gray.length; i++, p += 4) {
      gray[i] = (data[p] * 77 + data[p + 1] * 150 + data[p + 2] * 29) >> 8;
    }
    return { gray, w, h };
  }

  _decodePass() {
    const frame = this._grayFrame();
    if (!frame) return;
    this.passes++;

    const payloads = qrDecodeGray(frame.gray, frame.w, frame.h);
    if (!payloads.length) return;
    this.reads++;

    let changed = false;
    for (const payload of payloads) {
      const lower = payload.toLowerCase();

      if (!lower.startsWith(UR_PSBT_PREFIX)) {
        this.note = BBQR_RE.test(payload)
          ? 'That is a BBQR code. Set the device to output UR and try again.'
          : 'That QR is not a signed transaction.';
        changed = true;
        continue;
      }

      const before = this.decoder.received;
      const state = this.decoder.receive(payload);

      if (state === UR_OK) {
        const psbt = this.decoder.psbt();
        this.stop();
        if (psbt) this.onComplete(psbt);
        else this.onError('The transaction came through but was not a PSBT.');
        return;
      }

      if (urStateIsError(state)) {
        // Most decoder errors are transient — a half-captured frame — and the
        // right response is to keep scanning. A TERMINAL error means this
        // decoder can never finish, so it is replaced rather than left to spin.
        if (urStateIsTerminal(state)) {
          this.decoder.free();
          this.decoder = new UrPsbtDecoder();
          this.direct.clear();
          this.note = 'Those frames did not agree with each other — starting over.';
          changed = true;
        }
        continue;
      }

      this.note = null;
      const match = UR_SEQ_RE.exec(lower);
      if (match) {
        const seq = Number(match[1]);
        const seqLen = Number(match[2]);
        // Parts 1..seqLen are the plain fragments; past that they are mixed.
        if (seq <= seqLen) this.direct.add(seq - 1);
      } else {
        this.direct.add(0);            // single-part UR: one fragment, read whole
      }
      if (this.decoder.received !== before || match) changed = true;
    }

    if (changed) this.onProgress(this.snapshot());
  }
}
