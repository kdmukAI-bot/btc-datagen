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
  if (s.w !== s.h) fail(where, `${label}: canvas not square (${s.w}x${s.h})`);
  if (s.ratio < DARK_MIN || s.ratio > DARK_MAX) {
    fail(where, `${label}: does not look like a QR (dark ratio ${s.ratio.toFixed(3)})`);
  }
  return s;
}

const browser = await chromium.launch();

for (const [name, viewport, dpr] of VIEWPORTS) {
  const ctx = await browser.newContext({ viewport, deviceScaleFactor: dpr });
  const page = await ctx.newPage();
  page.on('console', (m) => { if (m.type() === 'error') fail(name, `console: ${m.text()}`); });
  page.on('pageerror', (e) => fail(name, `pageerror: ${e.message}`));

  await page.goto(BASE, { waitUntil: 'networkidle' });

  // No interstitial by design: the warning lives in the sticky banner and the
  // landing paragraph, both of which stay on screen.
  if (await page.locator('#gate').count()) fail(name, 'a disclaimer dialog is back');
  const warnText = (await page.textContent('.view-intro-warn')).toLowerCase();
  for (const phrase of ['fake', 'not secure', 'never use', 'real bitcoin']) {
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
  const lead = (await page.textContent('.activity-lead .activity-name')).trim();
  if (!/sign a transaction/i.test(lead)) {
    fail(name, `landing should lead with signing, leads with "${lead}"`);
  }
  if (!(await page.isVisible('.banner-logo'))) fail(name, 'banner logo missing');

  await page.click('[data-goto="sign"]');
  await page.waitForTimeout(600);
  if (await page.isHidden('#view-sign')) fail(name, 'sign view did not open');
  await page.waitForFunction(() => document.getElementById('qr-canvas').width > 50,
    { timeout: 5000 }).catch(() => fail(name, 'transaction canvas never sized'));

  const tx = await checkCanvas(page, name, 'qr-canvas', 'transaction');
  const title = (await page.textContent('#scenario-title')).trim();
  console.log(`${name}: ${tx.w}px device / ${tx.cssW}px css `
    + `(${((tx.cssW / viewport.width) * 100).toFixed(0)}% of viewport), `
    + `dark ${(tx.ratio * 100).toFixed(1)}%`);
  console.log(`  ${title} | ${(await page.textContent('#qr-progress')).trim()}`);

  // --- signing path: progressive reveal via the call to action -------------
  if (!(await page.isHidden('#step-seed'))) fail(name, 'seed step visible before its CTA');
  if (!(await page.isVisible('#cta-tx button'))) fail(name, 'step 1 has no call to action');
  console.log(`  step 1 CTA: "${(await page.textContent('#cta-tx button')).trim()}"`);

  await page.click('#cta-tx button');
  await page.waitForTimeout(600);
  if (await page.isHidden('#step-seed')) fail(name, 'CTA did not reveal the seed step');
  await checkCanvas(page, name, 'seed-canvas', 'seed');

  // CompactSeedQR must be the default selection.
  const seedSel = await page.getAttribute('#seedqr-seg button >> nth=0', 'aria-pressed');
  const seedLabel = (await page.textContent('#seedqr-seg button >> nth=0')).trim();
  if (seedSel !== 'true' || !/compact/i.test(seedLabel)) {
    fail(name, `SeedQR default is not CompactSeedQR (first=${seedLabel}, pressed=${seedSel})`);
  }

  // Animation advances, pause/step work.
  const before = await page.textContent('#qr-progress');
  await page.waitForTimeout(700);
  if ((await page.textContent('#qr-progress')) === before) {
    fail(name, `animation did not advance in 700ms (${before})`);
  }
  await page.click('#playpause');
  const paused = await page.textContent('#qr-progress');
  await page.waitForTimeout(500);
  if ((await page.textContent('#qr-progress')) !== paused) fail(name, 'pause did not stop playback');
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
    // Restarts at step 1, and the descriptor step is step 3 of the signing flow.
    if (!(await page.isHidden('#step-seed'))) fail(name, 'new scenario did not reset to step 1');
    await page.click('#cta-tx button');
    await page.waitForTimeout(500);
    const seedCta = (await page.textContent('#cta-seed button')).trim();
    if (!/descriptor/i.test(seedCta)) {
      fail(name, `multisig step-2 CTA should lead to the descriptor, got "${seedCta}"`);
    }
    await page.click('#cta-seed button');
    await page.waitForTimeout(600);
    if (await page.isHidden('#step-descriptor')) {
      fail(name, 'descriptor step missing on a multisig scenario');
    }
    await checkCanvas(page, name, 'descriptor-canvas', 'wallet descriptor');
    console.log('  multisig signing flow reaches the descriptor step');
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
    for (const [id, label] of canvases) await checkCanvas(page, name, id, label);
    console.log(`  activity "${goto}" renders`);
  }

  await page.click('#home');
  await page.waitForTimeout(400);
  if (await page.isHidden('#view-home')) fail(name, 'home did not return to the landing page');


  if (SHOT_DIR) await page.screenshot({ path: `${SHOT_DIR}/site-${name}.png` });
  await ctx.close();
}

await browser.close();

if (problems.length) {
  console.log('\nPROBLEMS:\n - ' + problems.join('\n - '));
  process.exit(1);
}
console.log('\nPASS — no problems found.');
