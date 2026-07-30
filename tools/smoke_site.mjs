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
    ['verify', '#view-verify', [['verify-descriptor-canvas', 'verify descriptor'],
                               ['verify-address-canvas', 'verify address']]],
    ['message', '#view-message', [['message-canvas', 'sign message']]],
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

await browser.close();

if (problems.length) {
  console.log('\nPROBLEMS:\n - ' + problems.join('\n - '));
  process.exit(1);
}
console.log('\nPASS — no problems found.');
