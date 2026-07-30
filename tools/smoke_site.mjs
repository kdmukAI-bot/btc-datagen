/* Headless-browser smoke test for the demo site.
 *
 * tools/verify.py proves the DATA is correct. This proves the PAGE actually
 * renders it — which is a genuinely different failure mode. Both bugs it caught
 * on first run were invisible to code review and to any data-level check:
 *
 *   1. `.fs`/`.sheet`/`.chooser` declare `display: flex`, and an author-origin
 *      `display` beats the UA stylesheet's `[hidden] { display: none }`
 *      regardless of specificity. The fullscreen overlay (fixed, inset 0,
 *      white, z-index 80) therefore rendered permanently over the page: a blank
 *      white screen after dismissing the disclaimer.
 *   2. `#step-seed` was marked `hidden` in the markup and nothing ever unhid
 *      it, so step 2 of a three-step guided flow silently never appeared.
 *
 * Checks: no console/page errors; the landing warning is intact; overlays are
 * actually hidden; each canvas gets a sane size at whole-pixel scale; the
 * canvas contains a plausible black/white module mix rather than blank白;
 * the animation advances; fullscreen and the picker open and close; and the
 * descriptor step appears for a multisig scenario.
 *
 * Setup (one-off):
 *   npm install playwright && npx playwright install chromium
 *
 * Run (with `python -m tools.serve 8777` already running):
 *   node tools/smoke_site.mjs http://localhost:8777/
 */
import { readFileSync } from 'node:fs';
import { chromium } from 'playwright';

const BASE = process.argv[2] || 'http://localhost:8777/';
const SHOT_DIR = process.env.SMOKE_SHOT_DIR || null;

// A QR is roughly 40% dark. Well outside this band means blank, inverted, or junk.
const DARK_MIN = 0.15;
const DARK_MAX = 0.75;

const VIEWPORTS = [
  ['desktop', { width: 1280, height: 900 }, 1],
  ['phone', { width: 390, height: 844 }, 3],
];

const problems = [];
const fail = (where, msg) => problems.push(`[${where}] ${msg}`);

async function canvasStats(page, id) {
  return page.evaluate((canvasId) => {
    const c = document.getElementById(canvasId);
    if (!c) return null;
    const ctx = c.getContext('2d');
    const d = ctx.getImageData(0, 0, c.width, c.height).data;
    let dark = 0, total = 0;
    for (let i = 0; i < d.length; i += 4) { total++; if (d[i] < 128) dark++; }
    return { w: c.width, h: c.height, cssW: c.clientWidth, ratio: total ? dark / total : 0 };
  }, id);
}

async function checkCanvas(page, where, id, label) {
  const s = await canvasStats(page, id);
  if (!s) return fail(where, `${label}: canvas #${id} not in the DOM`);
  if (s.w < 50) return fail(where, `${label}: canvas never sized (${s.w}px)`);
  // The QR itself is always square. A handmade SeedQR canvas is deliberately
  // TALLER than wide: it carries the hand-written label band on the same
  // textured surface, so the card reads as one sheet of paper rather than a
  // canvas sitting inside a differently-textured card. Anything wider than tall,
  // or a band bigger than the symbol, is still a bug.
  const band = s.h - s.w;
  if (band < 0) fail(where, `${label}: canvas wider than tall (${s.w}x${s.h})`);
  else if (band > s.w * 0.3) {
    fail(where, `${label}: label band implausibly large (${band}px on a ${s.w}px symbol)`);
  }
  if (s.ratio < DARK_MIN || s.ratio > DARK_MAX) {
    fail(where, `${label}: does not look like a QR (dark ratio ${s.ratio.toFixed(3)})`);
  }
  return s;
}

/* ---------- the scan-it-back step, with a fake camera ---------------------- *
 *
 * The one part of the site with no other automated coverage: the camera path is
 * the only place where getUserMedia, k_quirc, the UR fountain decoder and the
 * signature verifier all run together, and it is exactly the part a reviewer
 * cannot check by reading.
 *
 * The camera is replaced by a canvas MediaStream, driven from inside the page
 * by the SAME WASM encoder the transaction QRs use. So the test plays a real
 * animated ur:crypto-psbt of a real signed PSBT at the real 5 fps, and every
 * link after getUserMedia — video element, downscale, grayscale conversion,
 * k_quirc, cUR's fountain decoder, the PSBT parser, secp256k1 — is the shipping
 * code.
 *
 * A fake video DEVICE (--use-file-for-fake-video-capture with a Y4M) was the
 * other option. It buys one extra link of realism (Chromium's capture pipeline)
 * and costs a 20 MB generated file and a browser-flag dependency; the canvas
 * stream tests everything the site actually owns.
 *
 * Three cases, because a checker that cannot say no is decoration:
 *   signed            -> "the signature is real"
 *   unsigned          -> "not signed yet"
 *   a different tx    -> "that is a different transaction"
 */
const SCAN_CASES = [
  ['signed', /signature is real/i],
  ['unsigned', /not signed yet/i],
  ['different transaction', /different transaction/i],
];

/* Playing one PSBT into the fake camera as a live UR fountain. Installed on the
   page rather than passed frame by frame, so the animation runs at the device's
   real 5 fps and the scanner sees genuine timing. */
function playIntoFakeCamera(page, b64) {
  return page.evaluate(async (psbtB64) => {
    const ssqr = await import('./ssqr.js');
    await ssqr.ready();
    const bin = atob(psbtB64);
    const psbt = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) psbt[i] = bin.charCodeAt(i);

    clearInterval(window.__scanTimer);
    const enc = new ssqr.UrPsbtEncoder(psbt, 80);
    const canvas = window.__fakeCam;
    const g = canvas.getContext('2d');
    window.__scanTimer = setInterval(() => {
      const frame = ssqr.qrEncode(enc.next().toUpperCase());
      const quiet = 4;
      const scale = Math.floor(Math.min(canvas.width, canvas.height)
        / (frame.m + quiet * 2));
      const size = (frame.m + quiet * 2) * scale;
      const ox = ((canvas.width - size) >> 1) + quiet * scale;
      const oy = ((canvas.height - size) >> 1) + quiet * scale;
      g.fillStyle = '#fff';
      g.fillRect(0, 0, canvas.width, canvas.height);
      g.fillStyle = '#000';
      for (let r = 0; r < frame.m; r++) {
        for (let c = 0; c < frame.m; c++) {
          const i = r * frame.m + c;
          if ((frame.bits[i >> 3] >> (7 - (i & 7))) & 1) {
            g.fillRect(ox + c * scale, oy + r * scale, scale, scale);
          }
        }
      }
    }, 200);
  }, b64);
}

/* A 2-of-3 completed one cosigner at a time, which is how it actually happens:
 * each scan carries only the signature the device just made, so the page has to
 * accumulate them the way a coordinator combines PSBTs. Judged per scan, this
 * transaction can never reach "complete" — which is the whole thing a multisig
 * demo exists to show.
 *
 * Also checks that re-reading the SAME cosigner is recognised rather than
 * counted twice; at a demo table that is the first thing anyone tries when the
 * numbers do not move. */
async function runMultisigScanCheck(browser, ctx, cases) {
  const where = 'scan';
  const alice = cases.find((c) => /2of3_p2wsh.* one of 2$/.test(c.label));
  const both = cases.find((c) => /2of3_p2wsh.* signed$/.test(c.label));
  if (!alice || !both) {
    fail(where, 'reference.json has no partial + complete 2-of-3 pair');
    return;
  }
  const scenarioId = alice.label.split(' ')[0];

  const page = await ctx.newPage();
  page.on('pageerror', (e) => fail(where, `multisig: pageerror: ${e.message}`));
  await page.goto(`${BASE}?tx=${scenarioId}&do=sign`, { waitUntil: 'networkidle' });
  await page.waitForFunction(() => document.getElementById('qr-canvas').width > 50,
    { timeout: 8000 }).catch(() => fail(where, 'multisig: page never rendered'));

  const scan = async (b64) => {
    await playIntoFakeCamera(page, b64);
    await page.click('#scan-again').catch(async () => { await page.click('#scan-start'); });
    await page.waitForSelector('#scan-result:not([hidden])', { timeout: 30000 })
      .catch(() => fail(where, 'multisig: no verdict within 30s'));
    return ((await page.textContent('#scan-result').catch(() => '')) || '')
      .replace(/\s+/g, ' ').trim();
  };

  const first = await scan(alice.psbt_base64);
  if (!/partly signed/i.test(first)) {
    fail(where, `multisig: one cosigner should read as partly signed — got "${first.slice(0, 120)}"`);
  }
  // Feeding the identical PSBT again must not inflate the count.
  const repeat = await scan(alice.psbt_base64);
  if (!/already counted/i.test(repeat)) {
    fail(where, `multisig: re-scanning one cosigner should say so — got "${repeat.slice(0, 120)}"`);
  }
  const second = await scan(both.psbt_base64);
  if (!/signature is real/i.test(second)) {
    fail(where, `multisig: the threshold should complete across scans — got "${second.slice(0, 160)}"`);
  } else {
    console.log(`  scan ${'multisig, collected'.padEnd(22)} -> ${second.split('  ')[0].slice(0, 60)}`);
  }

  await page.evaluate(() => clearInterval(window.__scanTimer));
  if (SHOT_DIR) await page.screenshot({ path: `${SHOT_DIR}/scan-multisig.png` });
  await page.close();
}

async function runScanChecks(browser) {
  const where = 'scan';
  let fixtures;
  try {
    fixtures = JSON.parse(readFileSync('tools/wasm/reference.json', 'utf8'));
  } catch (e) {
    fail(where, `tools/wasm/reference.json is missing (${e.message}) — `
      + 'run `python -m tools.wasm.reference` first');
    return;
  }

  const signed = (fixtures.signing || []).find((c) => /native_segwit.* signed$/.test(c.label));
  const unsigned = (fixtures.signing || []).find((c) => /native_segwit.* unsigned$/.test(c.label));
  const otherTx = (fixtures.signing || []).find((c) => /legacy.* signed$/.test(c.label));
  if (!signed || !unsigned || !otherTx) {
    fail(where, 'reference.json has no signed/unsigned native-segwit pair to scan');
    return;
  }
  const scenarioId = signed.label.split(' ')[0];
  const psbts = {
    'signed': signed.psbt_base64,
    'unsigned': unsigned.psbt_base64,
    'different transaction': otherTx.psbt_base64,
  };

  const ctx = await browser.newContext({
    viewport: { width: 390, height: 844 },
    deviceScaleFactor: 2,
  });

  // Stand in for the camera BEFORE any page script runs. captureStream only
  // emits a frame when the canvas is painted, so the animation's own 5 fps
  // paces the stream — exactly as a real camera watching a device would.
  await ctx.addInitScript(() => {
    window.__fakeCam = document.createElement('canvas');
    window.__fakeCam.width = 640;
    window.__fakeCam.height = 480;
    const ctx2d = window.__fakeCam.getContext('2d');
    ctx2d.fillStyle = '#fff';
    ctx2d.fillRect(0, 0, 640, 480);
    navigator.mediaDevices = navigator.mediaDevices || {};
    navigator.mediaDevices.getUserMedia = async () => window.__fakeCam.captureStream(15);
  });

  for (const [label, expected] of SCAN_CASES) {
    const page = await ctx.newPage();
    page.on('pageerror', (e) => fail(where, `${label}: pageerror: ${e.message}`));

    await page.goto(`${BASE}?tx=${scenarioId}&do=sign`, { waitUntil: 'networkidle' });
    await page.waitForFunction(() => document.getElementById('qr-canvas').width > 50,
      { timeout: 8000 }).catch(() => fail(where, `${label}: page never rendered`));

    // Play the "device screen" into the fake camera: a real UR fountain over
    // the PSBT under test, one frame every 200ms.
    await playIntoFakeCamera(page, psbts[label]);

    await page.click('#scan-start');

    // Progress must actually move before the result lands — otherwise a
    // verifier that somehow got the PSBT by another route would pass this.
    await page.waitForFunction(
      () => document.querySelectorAll('#scan-cells .scan-cell.is-read').length > 0,
      { timeout: 20000 },
    ).catch(() => fail(where, `${label}: no fragment was ever marked as read`));

    await page.waitForSelector('#scan-result:not([hidden])', { timeout: 30000 })
      .catch(() => fail(where, `${label}: no verdict within 30s`));

    const verdict = ((await page.textContent('#scan-result').catch(() => '')) || '')
      .replace(/\s+/g, ' ').trim();
    if (!expected.test(verdict)) {
      fail(where, `${label}: verdict did not match ${expected} — got "${verdict.slice(0, 140)}"`);
    } else {
      console.log(`  scan ${label.padEnd(22)} -> ${verdict.split('  ')[0].slice(0, 60)}`);
    }

    await page.evaluate(() => clearInterval(window.__scanTimer));
    if (SHOT_DIR) {
      await page.screenshot({ path: `${SHOT_DIR}/scan-${label.replace(/\s+/g, '-')}.png` });
    }
    await page.close();
  }

  await runMultisigScanCheck(browser, ctx, fixtures.signing || []);
  await ctx.close();
}

// Lets you smoke-test a custom domain before local DNS has caught up, e.g.
//   SMOKE_HOST_RULES='MAP testqrs.com 185.199.108.153' node tools/smoke_site.mjs https://testqrs.com/
const hostRules = process.env.SMOKE_HOST_RULES;
const browser = await chromium.launch(
  hostRules ? { args: [`--host-resolver-rules=${hostRules}`] } : {},
);

for (const [name, viewport, dpr] of VIEWPORTS) {
  const ctx = await browser.newContext({ viewport, deviceScaleFactor: dpr });
  const page = await ctx.newPage();
  page.on('console', (m) => { if (m.type() === 'error') fail(name, `console: ${m.text()}`); });
  page.on('pageerror', (e) => fail(name, `pageerror: ${e.message}`));

  // Optional controls live in collapsed <details>; open them all so the control
  // assertions can reach them.
  const openAll = async () => {
    await page.evaluate(() => document.querySelectorAll('details')
      .forEach((d) => { d.open = true; }));
    await page.waitForTimeout(150);
  };

  await page.goto(BASE, { waitUntil: 'networkidle' });

  // No interstitial by design: the warning lives in the sticky banner and the
  // landing paragraph, both of which stay on screen.
  if (await page.locator('#gate').count()) fail(name, 'a disclaimer dialog is back');
  const warnText = (await page.textContent('.view-intro-warn')).toLowerCase();
  for (const phrase of ['fake', 'demo keys', 'never use', 'real bitcoin']) {
    if (!warnText.includes(phrase)) fail(name, `landing warning is missing "${phrase}"`);
  }
  for (const sel of ['#fs', '#picker']) {
    if (await page.isVisible(sel).catch(() => false)) {
      fail(name, `${sel} is visible but should be hidden`);
    }
  }

  // --- landing page ---------------------------------------------------------
  if (await page.isHidden('#view-home')) fail(name, 'landing page not shown on load');
  const activities = await page.locator('.activity').count();
  console.log(`  landing lists ${activities} activities`);
  if (activities < 4) fail(name, `expected 4 activities, found ${activities}`);
  const lead = (await page.textContent('.activity-lead')).trim();
  if (!/sign a transaction/i.test(lead)) {
    fail(name, `landing should lead with signing, leads with "${lead}"`);
  }
  if (!(await page.isVisible('.banner-logo'))) fail(name, 'banner logo missing');

  await page.click('[data-goto="sign"]');
  await page.waitForTimeout(600);
  if (await page.isHidden('#view-sign')) fail(name, 'sign view did not open');
  await page.waitForFunction(() => document.getElementById('qr-canvas').width > 50,
    { timeout: 5000 }).catch(() => fail(name, 'transaction canvas never sized'));

  // The QR must be the first thing, with the knobs tucked away.
  for (const sel of ['#format-seg', '#density-seg', '#fps-slider']) {
    if (await page.isVisible(sel)) fail(name, `${sel} should start collapsed`);
  }
  const tx = await checkCanvas(page, name, 'qr-canvas', 'transaction');
  await openAll();
  const title = (await page.textContent('#scenario-title')).trim();
  console.log(`${name}: ${tx.w}px device / ${tx.cssW}px css `
    + `(${((tx.cssW / viewport.width) * 100).toFixed(0)}% of viewport), `
    + `dark ${(tx.ratio * 100).toFixed(1)}%`);
  console.log(`  ${title} | ${(await page.textContent('#qr-progress')).trim()}`);

  // --- signing path: one scrolling page, no next-step buttons ---------------
  if (await page.locator('.cta').count()) fail(name, 'a next-step CTA is back');
  if (await page.isHidden('#step-seed')) fail(name, 'seed step should be on the page');
  await checkCanvas(page, name, 'seed-canvas', 'seed');

  // CompactSeedQR must be the default selection.
  const seedSel = await page.getAttribute('#seedqr-seg button >> nth=0', 'aria-pressed');
  const seedLabel = (await page.textContent('#seedqr-seg button >> nth=0')).trim();
  if (seedSel !== 'true' || !/compact/i.test(seedLabel)) {
    fail(name, `SeedQR default is not CompactSeedQR (first=${seedLabel}, pressed=${seedSel})`);
  }

  // Animation advances. Poll rather than sample once: the frame clock is
  // requestAnimationFrame-driven, and a single 700ms window is thin enough that
  // one throttled rAF (or a slow getImageData just before it) reads as a
  // failure when playback is fine.
  const before = await page.textContent('#qr-progress');
  await page.waitForFunction(
    (prev) => document.getElementById('qr-progress').textContent !== prev,
    before, { timeout: 4000 },
  ).catch(() => fail(name, `animation did not advance within 4s (stuck at ${before})`));
  await page.click('#playpause');
  const paused = await page.textContent('#qr-progress');
  await page.waitForTimeout(500);
  if ((await page.textContent('#qr-progress')) !== paused) fail(name, 'pause did not stop playback');

  // Once a UR animation reaches the fountain parts it must STAY there — a real
  // encoder never returns to the pure prefix.
  //
  // Rewind to frame 0 first: by this point free playback has already run past
  // the pure parts, and stepping from wherever it landed sees no pure frames at
  // all, which makes the assertion below pass without testing anything.
  // Re-selecting a density reloads the payload, which resets to frame 0 and
  // leaves playback paused.
  await page.click('#density-seg button >> nth=1');
  await page.waitForTimeout(400);

  const seen = [];
  for (let i = 0; i < 45; i++) {
    seen.push((await page.textContent('#qr-progress')).trim());
    await page.click('#step-frame');
  }
  const pureHits = seen.filter((s) => /^Part \d+ of/.test(s));
  const uniquePure = new Set(pureHits);
  if (pureHits.length === 0) {
    fail(name, 'stepped 45 frames from the start without seeing one pure part — '
      + 'the fountain assertion would be vacuous');
  } else if (pureHits.length !== uniquePure.size) {
    fail(name, 'animation looped back to the pure fragments '
      + `(${pureHits.length} pure frames, only ${uniquePure.size} distinct)`);
  }
  if (!seen.some((s) => /mixed/.test(s))) {
    fail(name, 'never reached a fountain (mixed) part');
  }
  console.log(`  fountain: ${uniquePure.size} pure part(s), each shown once, `
    + 'then stays mixed');

  await page.click('#step-frame');
  if ((await page.textContent('#qr-progress')) === paused) fail(name, 'step-frame did not advance');
  await page.click('#playpause');

  // Fullscreen round trip.
  await page.click('#qr-expand');
  if (!(await page.isVisible('#fs'))) fail(name, 'fullscreen did not open');
  await page.waitForFunction(() => document.getElementById('fs-canvas').width > 50,
    { timeout: 3000 }).catch(() => fail(name, 'fullscreen canvas never sized'));
  await page.click('#fs-close');
  if (await page.isVisible('#fs')) fail(name, 'fullscreen did not close');

  // --- picker: friendly script-type names, and a multisig scenario ---------
  await openAll();
  await page.click('#open-picker');
  if (!(await page.isVisible('#picker'))) fail(name, 'picker did not open');
  const listed = await page.locator('.scenario-item').count();
  console.log(`  picker lists ${listed} scenarios`);
  if (listed === 0) fail(name, 'picker listed no scenarios');

  const scriptOpts = await page.locator('#filters select >> nth=2').locator('option')
    .allTextContents();
  const friendly = scriptOpts.filter((t) => /\(P2\w/.test(t) && /SegWit|Taproot|Legacy/i.test(t));
  if (friendly.length === 0) {
    fail(name, `script-type options lack human names: ${scriptOpts.join(' | ')}`);
  } else {
    console.log(`  script types read like: ${friendly[0]}`);
  }

  await page.selectOption('#filters select >> nth=2', 'P2WSH').catch(() => {});
  await page.waitForTimeout(200);
  if ((await page.locator('.scenario-item').count()) === 0) {
    fail(name, 'no P2WSH scenarios after filtering');
  } else {
    await page.locator('.scenario-item').first().click();
    await page.waitForTimeout(900);
    await openAll();
    if (await page.isHidden('#step-descriptor')) {
      fail(name, 'descriptor step missing on a multisig scenario');
    }
    await checkCanvas(page, name, 'descriptor-canvas', 'wallet descriptor');
    console.log('  multisig scenario shows the descriptor step');
  }

  // --- the other activities, each reached from the landing page ------------
  for (const [goto, view, canvases] of [
    ['seed', '#view-seed', [['only-seed-canvas', 'standalone seed']]],
    // Only the address canvas: the descriptor step is multisig-only and the
    // default wallet is single-sig, so asserting it renders here would be
    // asserting the bug.
    ['verify', '#view-verify', [['verify-address-canvas', 'verify address']]],
    ['message', '#view-message', [['message-canvas', 'sign message'],
                                  ['message-seed-canvas', 'message seed']]],
  ]) {
    await page.click('#home');
    await page.waitForTimeout(300);
    if (await page.isHidden('#view-home')) fail(name, 'banner logo did not return home');
    await page.click(`[data-goto="${goto}"]`);
    await page.waitForTimeout(700);
    if (await page.isHidden(view)) fail(name, `${view} did not open`);
    if (!(await page.isHidden('#view-sign'))) fail(name, `signing view still visible in ${goto}`);

    // A SeedQR starts behind a closed vault and opens on demand. Scope to the
    // visible view — both seed surfaces have a .fold-open button, and the one
    // in the hidden signing view would otherwise be matched first.
    const fold = page.locator(`${view} .fold`).first();
    if (await fold.count()) {
      const isOpen = () => fold.evaluate((v) => v.classList.contains('is-open'));
      if (await isOpen()) fail(name, `${goto}: sheet should start folded`);
      // Tapping the PAPER itself must unfold it, not just the button.
      await page.click(`${view} .fold-stage`, { position: { x: 60, y: 40 } });
      await page.waitForTimeout(1100);
      if (!(await isOpen())) fail(name, `${goto}: tapping the sheet did not unfold it`);
      // The card is permanently hidden (the stand-in faces are what's shown),
      // so the fold-back gesture lands on the stage.
      await page.click(`${view} .fold-stage`, { position: { x: 60, y: 40 } });
      await page.waitForTimeout(700);
      if (await isOpen()) fail(name, `${goto}: tapping the sheet did not re-fold it`);

      await page.click(`${view} .fold-open`);
      await page.waitForTimeout(1100);
      if (!(await isOpen())) fail(name, `${goto}: the unfold button did not work`);

      // Tapping the revealed sheet folds it away again. The gesture lands on the
      // stage, not the card: the card is permanently visibility:hidden (the
      // stand-in faces are what's on screen), and hidden elements take no
      // pointer events. This also guards the opposite bug — a toggle placed on
      // .fold would catch the very click that unfolded it and re-fold it, so the
      // sheet would never appear open at all.
      await page.click(`${view} .fold-stage`, { position: { x: 60, y: 40 } });
      await page.waitForTimeout(700);
      if (await isOpen()) fail(name, `${goto}: tapping the sheet did not re-fold it`);
      await page.click(`${view} .fold-open`);
      await page.waitForTimeout(800);
      if (!(await isOpen())) fail(name, `${goto}: sheet did not unfold again after re-folding`);
      console.log(`  activity "${goto}": sheet unfolds, tap-to-fold works`);
    }

    for (const [id, label] of canvases) await checkCanvas(page, name, id, label);
    console.log(`  activity "${goto}" renders`);
  }

  // --- verify-address: descriptor step is multisig-only ---------------------
  //
  // SeedSigner cannot import a single-sig wallet descriptor, so offering one
  // sends people looking for a device screen that does not exist. The address
  // is also the FIRST step, matching the device: you scan the address, and only
  // then does it need to know what to check it against.
  await page.click('#home');
  await page.waitForTimeout(250);
  await page.click('[data-goto="verify"]');
  await page.waitForTimeout(700);

  const firstVerifyStep = (await page.textContent('#view-verify .step .step-title')).trim();
  if (!/scan the address/i.test(firstVerifyStep)) {
    fail(name, `verify should start with the address, starts with "${firstVerifyStep}"`);
  }

  // Classify from the page's own catalog rather than by reading the option
  // labels. Parsing "2-of-3 · Native SegWit multisig" for a policy is guessing
  // at presentation, and the first attempt at it silently matched nothing.
  const walletOptions = await page.evaluate(() => {
    const offered = [...document.querySelectorAll('#verify-wallet option')].map((o) => o.value);
    return state.index.wallets
      .filter((w) => offered.includes(w.name))
      .map((w) => ({ value: w.name, text: w.policy, sig: w.sig_type }));
  });
  const single = walletOptions.find((o) => o.sig === 'single-sig');
  const multi = walletOptions.find((o) => o.sig === 'multisig');

  if (single) {
    await page.selectOption('#verify-wallet', single.value);
    await page.waitForTimeout(500);
    if (!(await page.isHidden('#verify-step-descriptor'))) {
      fail(name, `single-sig wallet "${single.text}" still offers a descriptor step`);
    }
  } else {
    fail(name, 'no single-sig wallet in the verify picker to test with');
  }
  if (multi) {
    await page.selectOption('#verify-wallet', multi.value);
    await page.waitForTimeout(600);
    if (await page.isHidden('#verify-step-descriptor')) {
      fail(name, `multisig wallet "${multi.text}" is missing its descriptor step`);
    }
    await checkCanvas(page, name, 'verify-descriptor-canvas', 'verify descriptor');
  } else {
    fail(name, 'no multisig wallet in the verify picker to test with');
  }
  console.log('  verify: address first, descriptor only for multisig');

  // --- nothing may overflow the viewport horizontally ----------------------
  //
  // A 62-character bech32 address in a table cell whose column is `nowrap`
  // pushed the amounts off the right edge of a phone with nothing to scroll to.
  // Measuring scrollWidth is the only way to catch that class of bug: it looks
  // fine in a desktop screenshot and the failure is off-camera by definition.
  await page.click('#home');
  await page.waitForTimeout(200);
  await page.click('[data-goto="sign"]');
  await page.waitForTimeout(500);
  await openAll();
  const overflow = await page.evaluate(() => {
    const doc = document.documentElement;
    const wide = [...document.querySelectorAll('#view-sign table, #view-sign .details')]
      .filter((el) => el.scrollWidth > el.clientWidth + 1)
      .map((el) => `${el.tagName.toLowerCase()}.${el.className} `
        + `${el.scrollWidth}>${el.clientWidth}`);
    return { page: doc.scrollWidth - doc.clientWidth, wide };
  });
  if (overflow.page > 1) fail(name, `page scrolls horizontally by ${overflow.page}px`);
  if (overflow.wide.length) {
    fail(name, `content overflows its container: ${overflow.wide.join('; ')}`);
  }

  // --- the browser's Back button --------------------------------------------
  //
  // On a phone Back is the primary way out of anything, and every view change
  // used replaceState — so the history stack stayed one entry deep and Back
  // from inside the signing flow left the site entirely. That reads as a crash,
  // not as navigation.
  // The root URL must stay clean. A default transaction is preloaded so the
  // signing view opens instantly, and it used to announce itself by rewriting
  // the URL to ?tx=<default> while the landing page was still showing — so a
  // refresh landed on the signing view, and the history entry the user started
  // from no longer described the page they started on. That makes Back
  // unfixable in principle, not merely broken.
  await page.click('#home');
  await page.waitForTimeout(400);
  const homeUrl = new URL(page.url());
  if (homeUrl.search !== '') {
    fail(name, `landing page rewrote the URL to "${homeUrl.search}" — a refresh `
      + 'here would not come back to the landing page');
  }
  await page.reload({ waitUntil: 'networkidle' });
  await page.waitForTimeout(600);
  if (await page.isHidden('#view-home')) {
    fail(name, 'reloading the root did not come back to the landing page');
  }

  // Entering the signing view is what puts `tx` in the URL.
  await page.click('[data-goto="sign"]');
  await page.waitForTimeout(600);
  const deep = new URL(page.url()).searchParams.get('tx');
  if (!deep) fail(name, 'opening the signing view did not put ?tx= in the URL');

  // A deep link still has to work, and still has to be the short form.
  await page.goto(`${BASE}?tx=${deep || ''}`, { waitUntil: 'networkidle' });
  await page.waitForTimeout(700);
  if (await page.isHidden('#view-sign')) fail(name, '?tx= deep link did not open the sign view');
  if (new URL(page.url()).searchParams.get('do')) {
    fail(name, `?tx= link was rewritten to include do= (${page.url()})`);
  }

  await page.goto(BASE, { waitUntil: 'networkidle' });
  await page.waitForTimeout(500);
  await page.click('[data-goto="verify"]');
  await page.waitForTimeout(500);
  if (await page.isHidden('#view-verify')) fail(name, 'verify view did not open');
  await page.goBack();
  await page.waitForTimeout(600);
  if (await page.isHidden('#view-home')) {
    fail(name, 'Back from a view did not return to the landing page');
  }
  // Forward has to work too, or Back is just destroying state.
  await page.goForward();
  await page.waitForTimeout(600);
  if (await page.isHidden('#view-verify')) fail(name, 'Forward did not restore the view');
  console.log('  back/forward navigates between views');

  await page.click('#home');
  await page.waitForTimeout(400);
  if (await page.isHidden('#view-home')) fail(name, 'home did not return to the landing page');
  // Vaults re-lock on navigation, so the next person at the demo table starts
  // from the closed state instead of inheriting the last one's.
  const stillOpen = await page.locator('.fold.is-open').count();
  if (stillOpen) fail(name, `${stillOpen} sheet(s) stayed unfolded after navigating home`);


  if (SHOT_DIR) await page.screenshot({ path: `${SHOT_DIR}/site-${name}.png` });
  await ctx.close();
}

await runScanChecks(browser);

await browser.close();

if (problems.length) {
  console.log('\nPROBLEMS:\n - ' + problems.join('\n - '));
  process.exit(1);
}
console.log('\nPASS — no problems found.');
