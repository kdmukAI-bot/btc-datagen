/* SeedSigner demo QR site.
 *
 * The browser never encodes a QR. Every symbol arrives from the Python build as
 * a bare module matrix (packed bits, row-major, 1 = dark, no quiet zone); all
 * this file does is blit those modules onto a canvas and flip frames.
 *
 * Two rendering rules matter for whether a SeedSigner can actually read the
 * screen, and both are easy to get wrong:
 *
 *   1. Integer module scaling only. A fractional scale gives some modules one
 *      more pixel than their neighbours, and that asymmetry wrecks decoding.
 *      We size the canvas in *device* pixels and pick scale = floor(avail/grid).
 *   2. One scale for a whole animation. Frames within a set can differ by a QR
 *      version, so we lock to the largest frame and centre the smaller ones.
 *      Otherwise the symbol visibly resizes mid-scan and the camera re-hunts.
 *
 * The views mirror distinct device features, which is why signing and address
 * verification are kept apart: in the SIGNING flow the device verifies change
 * addresses on board and you never scan an address at it. Verify Address is a
 * separate SeedSigner tool, so it gets its own view.
 */
'use strict';

const QUIET_ZONE = 4;           // modules; spec minimum, vs Sparrow's on-screen 2

const VIEWS = ['home', 'sign', 'seed', 'verify', 'message'];

const state = {
  index: null,
  mode: 'home',
  scenario: null,
  scenarioData: null,
  revealed: 1,                  // how many signing steps are on screen
  format: 'ur',
  density: {},                  // per-format sticky density
  fps: 5,
  seedName: null,
  seedVariant: 'compact',
  descriptorUr: 'crypto-output',
  verifyWallet: null,
  verifyDescriptorUr: 'crypto-output',
  verifyAddress: { branch: 'receive', index: 0 },
  onlySeedName: null,
  onlySeedVariant: 'compact',
  messageName: null,
  filters: { network: 'main', sig_type: 'all', script_type: 'all', output_shape: 'all' },
};

const $ = (id) => document.getElementById(id);

/* ---------- data helpers -------------------------------------------------- */

function unpack(b64) {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

async function getJSON(path) {
  const res = await fetch(path, { cache: 'no-cache' });
  if (!res.ok) throw new Error(`${path}: ${res.status}`);
  return res.json();
}

function prepare(payload) {
  // Decode once, up front — decoding inside the animation loop would stutter.
  return {
    count: payload.count,
    pureCount: payload.pure_count != null ? payload.pure_count : payload.count,
    maxModules: payload.max_modules,
    maxVersion: payload.max_version,
    frames: payload.frames.map((f) => ({ m: f.m, v: f.v, bits: unpack(f.b) })),
  };
}

const sats = (n) => n.toLocaleString('en-US') + ' sats';

/* ---------- QR player ----------------------------------------------------- */

class QrPlayer {
  constructor() {
    this.payload = null;
    this.canvas = null;
    this.frame = 0;
    this.playing = true;
    this.fps = 5;
    this.accum = 0;
    this.last = 0;
    this.onFrame = null;
    requestAnimationFrame((t) => this._tick(t));
  }

  setCanvas(canvas) {
    if (this._observer) this._observer.disconnect();
    this.canvas = canvas;
    // Watch the card rather than relying on callers to re-layout at the right
    // moment. A canvas inside a `hidden` section measures 0 wide, and laying
    // out against that silently yields a 1-device-pixel-per-module QR; this way
    // the correct layout happens as soon as the section is actually shown.
    if (canvas && window.ResizeObserver) {
      this._observer = new ResizeObserver(() => this.layout());
      this._observer.observe(canvas.parentElement);
    }
    this.layout();
  }

  setPayload(payload) {
    this.payload = payload;
    this.frame = 0;
    this.accum = 0;
    this.layout();
  }

  get isAnimated() {
    return !!this.payload && this.payload.count > 1;
  }

  /* Size the canvas to whole device pixels per module, then draw. */
  layout() {
    const { canvas, payload } = this;
    if (!canvas || !payload) return;

    const dpr = window.devicePixelRatio || 1;
    const grid = payload.maxModules + QUIET_ZONE * 2;

    let availCss;
    if (canvas.id === 'fs-canvas') {
      availCss = Math.min(window.innerWidth, window.innerHeight) - 16;
    } else {
      const card = canvas.parentElement;
      const cs = getComputedStyle(card);
      availCss = card.clientWidth
        - parseFloat(cs.paddingLeft) - parseFloat(cs.paddingRight);
    }

    // Nothing to measure against yet (container hidden or not laid out). Draw
    // nothing rather than committing to a garbage scale; the ResizeObserver
    // will call back once the container has a real width.
    if (!(availCss > 0)) return;

    const scale = Math.max(1, Math.floor((availCss * dpr) / grid));
    const devPx = grid * scale;
    canvas.width = devPx;
    canvas.height = devPx;
    canvas.style.width = `${devPx / dpr}px`;
    canvas.style.height = `${devPx / dpr}px`;
    this.scale = scale;
    this.draw();
  }

  draw() {
    const { canvas, payload } = this;
    if (!canvas || !payload || !this.scale) return;
    const f = payload.frames[this.frame];
    const scale = this.scale;
    const ctx = canvas.getContext('2d');
    ctx.imageSmoothingEnabled = false;
    ctx.fillStyle = '#ffffff';
    ctx.fillRect(0, 0, canvas.width, canvas.height);
    ctx.fillStyle = '#000000';

    // Centre this frame inside the locked grid of the largest frame.
    const off = QUIET_ZONE + ((payload.maxModules - f.m) >> 1);
    const bits = f.bits;
    for (let r = 0; r < f.m; r++) {
      const rowBase = r * f.m;
      for (let c = 0; c < f.m; c++) {
        const i = rowBase + c;
        if ((bits[i >> 3] >> (7 - (i & 7))) & 1) {
          ctx.fillRect((off + c) * scale, (off + r) * scale, scale, scale);
        }
      }
    }
    if (this.onFrame) this.onFrame(this.frame, payload.count);
  }

  advance(delta = 1) {
    if (!this.payload) return;
    this.frame = (this.frame + delta + this.payload.count) % this.payload.count;
    this.draw();
  }

  _tick(ts) {
    requestAnimationFrame((t) => this._tick(t));
    if (!this.payload || !this.playing || this.payload.count < 2) {
      this.last = ts;
      return;
    }
    if (!this.last) this.last = ts;
    this.accum += ts - this.last;
    this.last = ts;
    const period = 1000 / this.fps;
    if (this.accum >= period) {
      // Drop whole periods rather than catching up frame-by-frame, so a
      // backgrounded tab doesn't fast-forward through the animation on return.
      this.accum = this.accum % period;
      this.advance(1);
    }
  }
}

const player = new QrPlayer();
const seedPlayer = new QrPlayer();
const descriptorPlayer = new QrPlayer();
const verifyDescriptorPlayer = new QrPlayer();
const verifyAddressPlayer = new QrPlayer();
const onlySeedPlayer = new QrPlayer();
const messagePlayer = new QrPlayer();
const allPlayers = [player, seedPlayer, descriptorPlayer,
                    verifyDescriptorPlayer, verifyAddressPlayer,
                    onlySeedPlayer, messagePlayer];

/* ---------- small UI builders --------------------------------------------- */

function buildSegmented(container, options, current, onPick) {
  container.innerHTML = '';
  options.forEach((opt) => {
    const b = document.createElement('button');
    b.type = 'button';
    b.textContent = opt.label;
    b.setAttribute('aria-pressed', String(opt.value === current));
    b.addEventListener('click', () => onPick(opt.value));
    container.appendChild(b);
  });
}

function buildChooser(container, options, isActive, onPick) {
  container.innerHTML = '';
  options.forEach((opt) => {
    const b = document.createElement('button');
    b.type = 'button';
    b.textContent = opt.label;
    b.setAttribute('aria-pressed', String(isActive(opt.value)));
    b.addEventListener('click', () => onPick(opt.value));
    container.appendChild(b);
  });
}

function scriptLabel(scriptType) {
  const friendly = state.index.script_labels[scriptType];
  return friendly ? `${friendly} (${scriptType})` : scriptType;
}

/* Descriptor UR type picker, shared by both paths. */
function buildDescriptorSeg(segId, urs, current, onPick) {
  buildSegmented($(segId),
    Object.keys(urs).map((t) => ({ value: t, label: urs[t].label })),
    current, onPick);
}

/* ---------- signing path: the transaction step ---------------------------- */

function formatSpec(fmt) { return state.index.formats[fmt]; }

function densityFor(fmt) {
  // Sticky per format: UR defaults to its higher-density option, BBQR to Low.
  if (!state.density[fmt]) state.density[fmt] = formatSpec(fmt).default_density;
  return state.density[fmt];
}

function renderFormatControls() {
  const fmts = Object.keys(state.index.formats);
  buildSegmented($('format-seg'),
    fmts.map((f) => ({ value: f, label: formatSpec(f).label })),
    state.format,
    (v) => { state.format = v; loadQr(); });

  const spec = formatSpec(state.format);
  buildSegmented($('density-seg'),
    spec.densities.map((d) => ({ value: d, label: state.index.density_labels[d] })),
    densityFor(state.format),
    (v) => { state.density[state.format] = v; loadQr(); });

  $('qr-note').textContent = spec.note;
}

async function loadQr() {
  const density = densityFor(state.format);
  const ref = state.scenario.qr[state.format][density];
  renderFormatControls();
  player.setPayload(prepare(await getJSON(ref.file)));
  updatePlaybackControls();
}

function updatePlaybackControls() {
  const animated = player.isAnimated;
  $('fps-control').hidden = !animated;
  $('playpause').hidden = !animated;
  $('step-frame').hidden = !animated;
  $('playpause').textContent = player.playing ? 'Pause' : 'Play';
  $('step-frame').disabled = player.playing;
}

function onFrameChange(i, count) {
  const payload = player.payload;
  const modules = payload.maxModules;
  let label;
  if (count === 1) {
    label = `Single static frame · ${modules}×${modules} modules`;
  } else if (i < payload.pureCount) {
    // Sequence numbers 1..N are the plain message fragments.
    label = `Part ${i + 1} of ${payload.pureCount} · ${modules}×${modules} modules`;
  } else {
    // Everything past N is an XOR of a random fragment subset. Sparrow emits
    // these forever; we cycle a finite window of them.
    label = `Fountain part ${i + 1} (mixed) · ${modules}×${modules} modules`;
  }
  $('qr-progress').textContent = label;
  $('fs-progress').textContent = count > 1 ? `${i + 1} / ${count}` : '';
}

function renderTxSummary() {
  const s = state.scenarioData.summary;
  const rows = s.outputs.map((o) => {
    const cls = o.kind === 'external' ? 'pill-external' : 'pill-change';
    const label = o.kind === 'external' ? 'recipient'
      : (o.kind === 'change' ? 'change' : 'self-transfer');
    return `<tr><th><span class="pill ${cls}">${label}</span><div class="addr">${o.address}</div></th>
            <td class="num">${sats(o.value)}</td></tr>`;
  }).join('');

  $('tx-summary').innerHTML = `
    <table class="kv">
      <tr><th>Inputs</th><td class="num">${s.num_inputs} · ${sats(s.input_amount)}</td></tr>
      ${rows}
      <tr><th>Network fee</th><td class="num">${sats(s.fee)}</td></tr>
      <tr><th>PSBT size</th><td class="num">${state.scenarioData.psbt_bytes.toLocaleString()} bytes</td></tr>
    </table>
    <p class="qr-note">These inputs reference transactions that do not exist on any
    chain. The PSBT is structurally valid and fully signable, but unbroadcastable.</p>`;
}

/* ---------- signing path: the seed step ----------------------------------- */

async function renderSeedStep() {
  const seeds = state.scenario.signing_seeds;
  if (!state.seedName || !seeds.includes(state.seedName)) state.seedName = seeds[0];

  const multi = seeds.length > 1;
  $('seed-hint').textContent = multi
    ? `This is a ${state.scenario.threshold}-of-${seeds.length} multisig. `
      + `Sign with any ${state.scenario.threshold} of these seeds, one at a time.`
    : 'Scan this SeedQR into the SeedSigner, or type the words in by hand.';

  const chooser = $('seed-chooser');
  chooser.hidden = !multi;
  if (multi) {
    buildChooser(chooser, seeds.map((n) => ({ value: n, label: n })),
      (v) => v === state.seedName,
      (v) => { state.seedName = v; renderSeedStep(); });
  } else {
    chooser.innerHTML = '';
  }

  const entry = state.index.seeds.find((s) => s.name === state.seedName);
  const data = await getJSON(entry.file);

  buildSegmented($('seedqr-seg'), [
    { value: 'compact', label: 'CompactSeedQR' },
    { value: 'standard', label: `SeedQR (${data.words}w)` },
  ], state.seedVariant, (v) => { state.seedVariant = v; renderSeedStep(); });

  seedPlayer.setPayload(prepare(data[state.seedVariant].qr));

  const words = data.mnemonic.split(' ')
    .map((w, i) => `<span><i>${i + 1}</i>${w}</span>`).join('');
  $('seed-words').innerHTML = `
    <div class="words">${words}</div>
    <table class="kv" style="margin-top:10px">
      <tr><th>Master fingerprint</th><td class="mono">${data.master_fingerprint}</td></tr>
    </table>`;
}

/* ---------- signing path: the wallet descriptor step ---------------------- */

/* Multisig only, and NOT address verification: without the wallet policy the
   device can't tell that a change output is its own, so it can't show you a
   verified change amount while you review the transaction. */
async function renderDescriptorStep() {
  if (!state.scenario.needs_descriptor) return;

  const entry = state.index.wallets.find((w) => w.name === state.scenario.wallet);
  const data = await getJSON(entry.file);

  $('descriptor-hint').textContent =
    `Without the ${entry.policy} wallet policy the SeedSigner can't tell that this `
    + `transaction's change output belongs to the wallet, so it can't verify the `
    + `change on board. It does that itself — you never scan an address at it here.`;

  const urs = data.descriptor_urs;
  if (!Object.keys(urs).includes(state.descriptorUr)) {
    state.descriptorUr = Object.keys(urs)[0];
  }
  buildDescriptorSeg('descriptor-seg', urs, state.descriptorUr,
    (v) => { state.descriptorUr = v; renderDescriptorStep(); });

  descriptorPlayer.setPayload(prepare(urs[state.descriptorUr].qr));
  $('descriptor-meta').textContent =
    `${entry.policy} ${entry.script_label} · single-frame ur:${state.descriptorUr}`;
  $('descriptor-text').innerHTML = `<div class="addr">${data.descriptor}</div>`;
}

/* ---------- signing path: guided flow ------------------------------------- */

function flowSteps() {
  const steps = [
    { section: 'step-tx', cta: 'cta-tx', action: 'Scan the transaction' },
    { section: 'step-seed', cta: 'cta-seed', action: 'Load the seed' },
  ];
  if (state.scenario.needs_descriptor) {
    steps.push({ section: 'step-descriptor', cta: 'cta-descriptor',
                 action: 'Load the wallet descriptor' });
  }
  return steps;
}

/* Progressive disclosure: show the revealed steps, and give the last visible
   one a big call to action. Someone handed this at a demo table should never
   have to work out what to do next. */
function renderFlow() {
  const steps = flowSteps();
  state.revealed = Math.max(1, Math.min(state.revealed, steps.length));

  steps.forEach((step, i) => {
    const revealed = i < state.revealed;
    $(step.section).hidden = !revealed;
    const cta = $(step.cta);
    cta.innerHTML = '';
    if (!revealed || i !== state.revealed - 1) return;

    if (i + 1 < steps.length) {
      const next = steps[i + 1];
      cta.appendChild(ctaButton(`Next: ${next.action}`,
        `Step ${i + 2} of ${steps.length}`,
        () => { state.revealed = i + 2; renderFlow(); scrollToStep(next.section); }));
    } else {
      cta.appendChild(ctaButton('Try another transaction',
        'Then sign it on the device', openPicker));
    }
  });

  // Hide the descriptor section entirely for single sig, even if a previous
  // multisig scenario had revealed it.
  if (!state.scenario.needs_descriptor) $('step-descriptor').hidden = true;
}

function ctaButton(label, sublabel, onClick) {
  const wrap = document.createElement('div');
  const b = document.createElement('button');
  b.type = 'button';
  b.className = 'btn btn-primary btn-cta';
  b.textContent = label;
  b.addEventListener('click', onClick);
  wrap.appendChild(b);
  if (sublabel) {
    const s = document.createElement('p');
    s.className = 'cta-sub';
    s.textContent = sublabel;
    wrap.appendChild(s);
  }
  return wrap;
}

function scrollToStep(sectionId) {
  // Wait a frame so the newly-revealed section has a layout to scroll to.
  requestAnimationFrame(() => {
    $(sectionId).scrollIntoView({ behavior: 'smooth', block: 'start' });
  });
}

/* ---------- verify path --------------------------------------------------- */

async function renderVerifyView() {
  const wallets = state.index.wallets.filter((w) => w.network === state.filters.network);
  const select = $('verify-wallet');
  if (!state.verifyWallet || !wallets.some((w) => w.name === state.verifyWallet)) {
    state.verifyWallet = wallets[0].name;
  }
  select.innerHTML = '';
  wallets.forEach((w) => {
    const o = document.createElement('option');
    o.value = w.name;
    o.textContent = `${w.policy} · ${scriptLabel(w.script_type)}`;
    o.selected = w.name === state.verifyWallet;
    select.appendChild(o);
  });

  const entry = wallets.find((w) => w.name === state.verifyWallet);
  const data = await getJSON(entry.file);

  const urs = data.descriptor_urs;
  if (!Object.keys(urs).includes(state.verifyDescriptorUr)) {
    state.verifyDescriptorUr = Object.keys(urs)[0];
  }
  buildDescriptorSeg('verify-descriptor-seg', urs, state.verifyDescriptorUr,
    (v) => { state.verifyDescriptorUr = v; renderVerifyView(); });

  verifyDescriptorPlayer.setPayload(prepare(urs[state.verifyDescriptorUr].qr));
  $('verify-descriptor-meta').textContent =
    `${entry.policy} ${entry.script_label} · ur:${state.verifyDescriptorUr}`;
  $('verify-descriptor-text').innerHTML = `<div class="addr">${data.descriptor}</div>`;

  const options = [];
  ['receive', 'change'].forEach((branch) => {
    data.addresses[branch].forEach((item) => {
      options.push({ value: `${branch}:${item.index}`, label: `${branch} ${item.index}` });
    });
  });
  const currentKey = `${state.verifyAddress.branch}:${state.verifyAddress.index}`;
  buildChooser($('verify-address-chooser'), options,
    (v) => v === currentKey,
    (v) => {
      const [branch, index] = v.split(':');
      state.verifyAddress = { branch, index: Number(index) };
      renderVerifyView();
    });

  const chosen = data.addresses[state.verifyAddress.branch]
    .find((a) => a.index === state.verifyAddress.index);
  verifyAddressPlayer.setPayload(prepare(chosen.qr));
  $('verify-address-meta').textContent = chosen.address;
}

/* ---------- standalone "load a seed" view --------------------------------- */

async function renderOnlySeedView() {
  const seeds = state.index.seeds;
  if (!state.onlySeedName || !seeds.some((s) => s.name === state.onlySeedName)) {
    state.onlySeedName = seeds[0].name;
  }
  buildChooser($('only-seed-chooser'),
    seeds.map((s) => ({ value: s.name, label: `${s.name} · ${s.words}w` })),
    (v) => v === state.onlySeedName,
    (v) => { state.onlySeedName = v; renderOnlySeedView(); });

  const entry = seeds.find((s) => s.name === state.onlySeedName);
  const data = await getJSON(entry.file);

  buildSegmented($('only-seedqr-seg'), [
    { value: 'compact', label: 'CompactSeedQR' },
    { value: 'standard', label: `SeedQR (${data.words}w)` },
  ], state.onlySeedVariant, (v) => { state.onlySeedVariant = v; renderOnlySeedView(); });

  const variant = data[state.onlySeedVariant];
  onlySeedPlayer.setPayload(prepare(variant.qr));
  $('only-seed-note').textContent = state.onlySeedVariant === 'compact'
    ? `CompactSeedQR: the raw ${data.words === 24 ? 32 : 16}-byte entropy in QR byte `
      + `mode — a smaller symbol than the standard SeedQR, so it scans more easily.`
    : `Standard SeedQR: each word's 4-digit wordlist index in QR numeric mode `
      + `(${variant.payload.length} digits).`;

  const words = data.mnemonic.split(' ')
    .map((w, i) => `<span><i>${i + 1}</i>${w}</span>`).join('');
  $('only-seed-words').innerHTML = `
    <div class="words">${words}</div>
    <table class="kv" style="margin-top:10px">
      <tr><th>Master fingerprint</th><td class="mono">${data.master_fingerprint}</td></tr>
    </table>`;
}

/* ---------- "sign a message" view ---------------------------------------- */

async function renderMessageView() {
  const msgs = state.index.messages.filter((m) => m.network === state.filters.network);
  if (!state.messageName || !msgs.some((m) => m.name === state.messageName)) {
    state.messageName = msgs[0].name;
  }
  buildChooser($('message-chooser'),
    msgs.map((m) => ({ value: m.name, label: m.label })),
    (v) => v === state.messageName,
    (v) => { state.messageName = v; renderMessageView(); });

  const entry = msgs.find((m) => m.name === state.messageName);
  const data = await getJSON(entry.file);

  messagePlayer.setPayload(prepare(data.qr));
  $('message-meta').textContent =
    `${entry.chars} characters · ${scriptLabel(entry.script_type)}`;
  $('message-note').textContent =
    `Load seed "${data.seed}" first, then Tools › Sign Message. Unlike the UR `
    + `payloads this QR is NOT upper-cased — SeedSigner detects it by a lowercase `
    + `"signmessage" prefix.`;

  $('message-detail').innerHTML = `
    <table class="kv">
      <tr><th>Message</th><td>${data.message}</td></tr>
      <tr><th>Derivation</th><td class="mono">${data.derivation}</td></tr>
      <tr><th>Signing address</th><td class="addr">${data.address}</td></tr>
      <tr><th>Seed</th><td>${data.seed}</td></tr>
    </table>`;
}

/* ---------- view routing -------------------------------------------------- */

async function setMode(mode) {
  if (!VIEWS.includes(mode)) mode = 'home';
  state.mode = mode;
  VIEWS.forEach((v) => { $(`view-${v}`).hidden = v !== mode; });

  if (mode === 'seed') await renderOnlySeedView();
  if (mode === 'verify') await renderVerifyView();
  if (mode === 'message') await renderMessageView();

  const url = new URL(window.location);
  if (mode === 'home') url.searchParams.delete('do');
  else url.searchParams.set('do', mode);
  history.replaceState(null, '', url);
  window.scrollTo({ top: 0, behavior: 'auto' });
}

/* ---------- scenario selection -------------------------------------------- */

async function selectScenario(id) {
  const scenario = state.index.scenarios.find((s) => s.id === id);
  if (!scenario) return;
  state.scenario = scenario;
  state.scenarioData = await getJSON(`data/scenario/${id}.json`);

  $('scenario-title').textContent = scenario.title;
  $('scenario-blurb').textContent = scenario.blurb;

  // Every scenario change restarts the walkthrough at step 1.
  state.revealed = 1;
  renderFlow();
  await loadQr();
  renderTxSummary();
  await renderSeedStep();
  await renderDescriptorStep();
  renderFlow();

  const url = new URL(window.location);
  url.searchParams.set('tx', id);
  history.replaceState(null, '', url);
}

/* ---------- picker -------------------------------------------------------- */

function uniq(list) { return [...new Set(list)]; }

function renderFilters() {
  const all = state.index.scenarios;
  const idx = state.index;
  const defs = [
    { key: 'network', label: 'Network',
      options: [{ value: 'main', label: 'Mainnet' }, { value: 'test', label: 'Testnet' }] },
    { key: 'sig_type', label: 'Signing',
      options: [{ value: 'all', label: 'All' },
                ...uniq(all.map((s) => s.sig_type))
                  .map((v) => ({ value: v, label: idx.sig_type_labels[v] || v }))] },
    // Human name alongside the abbreviation: "Native SegWit (P2WPKH)". The
    // abbreviation alone is jargon; the name alone loses precision.
    { key: 'script_type', label: 'Script type',
      options: [{ value: 'all', label: 'All' },
                ...uniq(all.map((s) => s.script_type))
                  .map((v) => ({ value: v, label: scriptLabel(v) }))] },
    { key: 'output_shape', label: 'Outputs',
      options: [{ value: 'all', label: 'All' },
                ...uniq(all.map((s) => s.output_shape))
                  .map((v) => ({ value: v,
                                 label: idx.output_shape_labels[v] || v.replace(/_/g, ' ') }))] },
  ];

  const box = $('filters');
  box.innerHTML = '';
  defs.forEach((def) => {
    const wrap = document.createElement('div');
    wrap.className = 'control';
    const label = document.createElement('label');
    label.textContent = def.label;
    const select = document.createElement('select');
    select.className = 'btn btn-block';
    def.options.forEach((opt) => {
      const o = document.createElement('option');
      o.value = opt.value;
      o.textContent = opt.label;
      o.selected = state.filters[def.key] === opt.value;
      select.appendChild(o);
    });
    select.addEventListener('change', () => {
      state.filters[def.key] = select.value;
      renderScenarioList();
    });
    wrap.append(label, select);
    box.appendChild(wrap);
  });
}

function renderScenarioList() {
  const f = state.filters;
  const matches = state.index.scenarios.filter((s) =>
    s.network === f.network
    && (f.sig_type === 'all' || s.sig_type === f.sig_type)
    && (f.script_type === 'all' || s.script_type === f.script_type)
    && (f.output_shape === 'all' || s.output_shape === f.output_shape));

  const list = $('scenario-list');
  list.innerHTML = '';
  if (!matches.length) {
    list.innerHTML = '<p class="empty">No transactions match those filters.</p>';
    return;
  }
  matches.forEach((s) => {
    const b = document.createElement('button');
    b.type = 'button';
    b.className = 'scenario-item';
    b.setAttribute('aria-current', String(state.scenario && s.id === state.scenario.id));
    const ref = s.qr[state.format][densityFor(state.format)];
    b.innerHTML = `<strong>${s.title}</strong>
      <span>${s.num_inputs} in · ${s.psbt_bytes.toLocaleString()} B ·
      ${ref.count === 1 ? 'static QR' : ref.count + ' frames'}${s.tags.includes('stress test') ? ' · stress test' : ''}</span>`;
    b.addEventListener('click', () => {
      closePicker();
      selectScenario(s.id);
    });
    list.appendChild(b);
  });
}

function openPicker() {
  renderFilters();
  renderScenarioList();
  $('picker').hidden = false;
}
function closePicker() { $('picker').hidden = true; }

/* ---------- fullscreen ---------------------------------------------------- */

function openFullscreen() {
  $('fs').hidden = false;
  player.setCanvas($('fs-canvas'));
}
function closeFullscreen() {
  $('fs').hidden = true;
  player.setCanvas($('qr-canvas'));
}

/* ---------- boot ---------------------------------------------------------- */

function wireControls() {
  $('home').addEventListener('click', goHome);
  document.querySelectorAll('[data-goto]').forEach((b) => {
    b.addEventListener('click', () => setMode(b.dataset.goto));
  });
  $('only-seed-chooser');
  $('verify-wallet').addEventListener('change', (e) => {
    state.verifyWallet = e.target.value;
    renderVerifyView();
  });

  $('open-picker').addEventListener('click', openPicker);
  $('picker-close').addEventListener('click', closePicker);
  $('picker').addEventListener('click', (e) => { if (e.target.id === 'picker') closePicker(); });

  $('qr-expand').addEventListener('click', openFullscreen);
  $('fs-close').addEventListener('click', closeFullscreen);

  $('playpause').addEventListener('click', () => {
    player.playing = !player.playing;
    updatePlaybackControls();
  });
  $('step-frame').addEventListener('click', () => player.advance(1));

  const slider = $('fps-slider');
  slider.addEventListener('input', () => {
    state.fps = parseFloat(slider.value);
    player.fps = state.fps;
    $('fps-value').textContent = `${state.fps} fps`;
  });

  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') { closeFullscreen(); closePicker(); }
  });

  let resizeTimer;
  const relayout = () => allPlayers.forEach((p) => p.layout());
  window.addEventListener('resize', () => {
    clearTimeout(resizeTimer);
    resizeTimer = setTimeout(relayout, 120);
  });
  window.addEventListener('orientationchange', () => setTimeout(relayout, 250));
}

/* The banner title is the way back to the landing page. */
async function goHome() {
  await setMode('home');
}

async function main() {
  player.setCanvas($('qr-canvas'));
  player.onFrame = onFrameChange;
  seedPlayer.setCanvas($('seed-canvas'));
  descriptorPlayer.setCanvas($('descriptor-canvas'));
  verifyDescriptorPlayer.setCanvas($('verify-descriptor-canvas'));
  verifyAddressPlayer.setCanvas($('verify-address-canvas'));
  onlySeedPlayer.setCanvas($('only-seed-canvas'));
  messagePlayer.setCanvas($('message-canvas'));

  wireControls();

  state.index = await getJSON('data/index.json');
  const d = state.index.defaults;
  state.format = d.format;
  state.fps = d.fps;
  state.seedVariant = d.seedqr || state.seedVariant;
  player.fps = d.fps;
  $('fps-slider').value = d.fps;
  $('fps-value').textContent = `${d.fps} fps`;
  $('foot-build').textContent =
    `${state.index.scenarios.length} transactions · ${state.index.wallets.length} wallets · `
    + `${state.index.seeds.length} seeds`;

  const params = new URL(window.location).searchParams;
  const fallback = state.index.scenarios.find((s) => s.is_default) || state.index.scenarios[0];
  const start = state.index.scenarios.find((s) => s.id === params.get('tx')) || fallback;
  state.filters.network = start.network;
  await selectScenario(start.id);
  // A ?tx= link means someone wants that transaction, not the landing page.
  await setMode(params.get('do') || (params.get('tx') ? 'sign' : 'home'));
}

main().catch((err) => {
  document.body.insertAdjacentHTML('afterbegin',
    `<p style="padding:16px;color:#b00">Failed to load site data: ${err.message}.
     Did you run <code>python -m tools.build_site</code> and start the dev server?</p>`);
  console.error(err);
});
