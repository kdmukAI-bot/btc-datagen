"""Build the static GitHub Pages demo site into site/dist/.

Everything the browser needs is precomputed here, because Pages is static and
PSBT construction needs embit. In particular the QR codes ship as **bare module
matrices** (packed bits, no quiet zone) rather than payload text, so the browser
never has to encode a QR itself — no JS QR library to keep faithful to Sparrow's
settings, and the on-screen white border stays a front-end concern.

Layout:
    site/dist/
      index.html app.js styles.css        (copied from site/)
      data/index.json                     scenario + wallet + seed catalog
      data/scenario/<id>.json             base64 PSBT, per-input/output detail
      data/qr/<id>.<format>.<density>.json  frame matrices (lazy-loaded)
      data/seed/<name>.json               SeedQR + CompactSeedQR matrices
      data/wallet/<name>.json             descriptor QR + address QRs

Run:  python -m tools.build_site            (both networks)
      python -m tools.build_site --network main
      python -m tools.build_site --quick    (skip the big input-count sweep)
"""
import argparse
import hashlib
import json
import os
import shutil
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from urtypes.crypto import PSBT as URPSBT

from common import bbqr, scenarios as scenario_defs, script_types
from common.fixtures import load_seeds, load_wallets, wallet_cosigners
from common.psbt import build_psbt, summarize
from common.qr import qr_matrix, qr_matrix_bytes
from common.seedqr import standard_seedqr_digits, compact_seedqr_bytes
from common.ur2.ur import UR
from common.ur2.ur_encoder import UREncoder

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SITE_SRC = os.path.join(ROOT, "site")
DIST = os.path.join(SITE_SRC, "dist")
STATIC_FILES = ["index.html", "app.js", "styles.css", "seedsigner-logo.svg",
                # Self-hosted rather than pulled from a font CDN: this thing gets
                # opened on conference wifi, and a webfont that fails to load
                # would silently drop the handwritten label back to a system
                # serif — the exact failure the font is there to avoid.
                "permanent-marker.woff2",
                # Custom domain. Ships inside the artifact so the domain travels
                # with the build rather than living only in repo settings.
                "CNAME"]
# Copied wholesale (font licence texts).
STATIC_DIRS = ["licenses"]

MIN_FRAGMENT_BYTES = 10          # Sparrow MIN_FRAGMENT_LENGTH
DEFAULT_FPS = 5                  # Sparrow ANIMATION_PERIOD_MILLIS = 200ms
DEFAULT_SEEDQR = "compact"       # CompactSeedQR: smaller symbol, easier scan

# How many mixed (XOR fountain) parts to append after the pure set.
#
# This is sized so the mixed tail can complete a decode ON ITS OWN, which the
# playback rule makes load-bearing: a real UR encoder never returns to the pure
# prefix, so the browser loops the mixed tail forever once it gets there. If that
# tail held too few distinct parts to solve for whatever fragments a scanner
# missed, the animation would spin without ever completing — a hang at a demo
# table rather than a slow scan. A rateless code needs roughly `seq_len` distinct
# parts, hence the 1:1 target; the floor keeps tiny payloads interesting and the
# ceiling stops the 490-frame stress case from doubling into absurdity.
MIXED_PARTS_MIN = 16
MIXED_PARTS_MAX = 256

# Sparrow's two density presets per format. "normal" is the HIGHER-density
# option (more data per frame); "low" packs less in and is easier to scan.
FORMATS = {
    "ur": {
        "label": "UR",
        "note": "ur:crypto-psbt — what Sparrow sends by default.",
        "densities": {"normal": 400, "low": 80},     # bytes of CBOR per fragment
        "default_density": "normal",
    },
    "bbqr": {
        "label": "BBQR",
        "note": "BBQR — Coldcard-Q style. Denser per frame, so Low is the sane default.",
        "densities": {"normal": 2000, "low": 1000},  # CHARS of encoded body per part
        "default_density": "low",
    },
}
DEFAULT_FORMAT = "ur"

DENSITY_LABELS = {"normal": "Normal", "low": "Low"}

# Message-signing payloads. SeedSigner's format is
#   signmessage {derivation_path} ascii:{message}
# and its type detection is `startswith("signmessage")` — lowercase, so unlike
# the UR payloads these must NOT be upper-cased for alphanumeric density.
MESSAGE_DEFS = [
    {"name": "short", "script_type": "P2WPKH", "path_suffix": "/0/0",
     "label": "Short message",
     "message": "Signed on a SeedSigner with a published test key."},
    {"name": "long", "script_type": "P2WPKH", "path_suffix": "/0/0",
     "label": "Long message (pages on device)",
     "message": ("This is a deliberately long test message, so the SeedSigner has to "
                 "page through it on a small screen before you confirm what you are "
                 "actually signing. Reading the whole thing is the point of the "
                 "exercise: a signer that shows you only the first line is a signer "
                 "that can be lied to. None of this is real -- the key is public.")},
    {"name": "legacy", "script_type": "P2PKH", "path_suffix": "/0/0",
     "label": "Legacy address path",
     "message": "Message signing from a legacy P2PKH path."},
]
MESSAGE_SEED = "alice"

WARNING = ("TEST DATA ONLY — every key on this site is published and deterministic. "
           "These transactions are synthetic and spend UTXOs that do not exist. "
           "Never send real funds to any address here.")


# --- QR payload generation ---------------------------------------------------

def ur_parts(raw_psbt: bytes, max_fragment_bytes: int) -> tuple:
    """Sparrow's animated ur:crypto-psbt frames. Returns (parts, pure_count).

    The BC-UR multi-part encoder is **rateless**, and this matters. The first
    `seq_len` parts are the "pure" fragments (sequence numbers 1..N, each a
    plain slice of the message). Every part after that is a *mixed* part: an XOR
    of a pseudorandomly chosen subset of fragments, with sequence numbers
    N+1, N+2, ... forever. Sparrow just keeps calling nextPart(), so a real
    Sparrow animation runs 1..N and then stays in fountain mode indefinitely —
    it never returns to part 1.

    We can't ship an infinite stream, so we ship the pure set plus a mixed tail
    and the browser plays the pure prefix once before looping the tail (see
    QrPlayer.advance in site/app.js). Two shortcuts were both wrong:

      * emitting only the pure fragments leaves the fountain XOR-decode path —
        the most intricate part of any UR decoder — entirely unexercised;
      * cycling pure+mixed together makes the animation jump back to part 1,
        which no real encoder does.
    """
    ur = UR("crypto-psbt", URPSBT(raw_psbt).to_cbor())
    encoder = UREncoder(ur, max_fragment_bytes, 0, MIN_FRAGMENT_BYTES)
    if encoder.is_single_part():
        return [encoder.next_part()], 1
    pure_count = encoder.fountain_encoder.seq_len()
    mixed = max(MIXED_PARTS_MIN, min(pure_count, MIXED_PARTS_MAX))
    return [encoder.next_part() for _ in range(pure_count + mixed)], pure_count


def bbqr_parts(raw_psbt: bytes, max_fragment_chars: int) -> tuple:
    """BBQR parts. Returns (parts, pure_count) — BBQR has no fountain coding, so
    it really is a fixed set of slices that a sender loops; every part is 'pure'."""
    parts, _encoding = bbqr.encode(raw_psbt, "P", max_fragment_chars)
    return parts, len(parts)


def frames_payload(parts: list, pure_count: int) -> dict:
    """Rasterize each part to a bare module matrix.

    Frames in one animation can differ by a QR version (the last pure fragment
    is often smaller, and mixed parts are full-width). The front end locks its
    scale to `max_modules` and centers smaller frames, so the symbol never
    resizes mid-scan.
    """
    frames = []
    for part in parts:
        b64, version, modules = qr_matrix(part)
        frames.append({"m": modules, "v": version, "b": b64})
    return {
        "count": len(frames),
        "pure_count": pure_count,
        "max_modules": max(f["m"] for f in frames),
        "max_version": max(f["v"] for f in frames),
        "frames": frames,
    }


def qr_variants(raw_psbt: bytes) -> dict:
    """All {format: {density: payload}} variants for one PSBT."""
    out = {}
    for fmt, spec in FORMATS.items():
        out[fmt] = {}
        for density, cap in spec["densities"].items():
            parts, pure = (ur_parts(raw_psbt, cap) if fmt == "ur"
                           else bbqr_parts(raw_psbt, cap))
            out[fmt][density] = frames_payload(parts, pure)
    return out


def _single(b64: str, version: int, modules: int) -> dict:
    return {"count": 1, "max_modules": modules, "max_version": version,
            "frames": [{"m": modules, "v": version, "b": b64}]}


def text_qr(payload: str, uppercase: bool = True) -> dict:
    return _single(*qr_matrix(payload, uppercase=uppercase))


def address_qr(address: str) -> dict:
    """Address QRs ship verbatim — see the note in common.qr.qr_matrix about
    why upper-casing a Bitcoin address is not an option."""
    return text_qr(address, uppercase=False)


def bytes_qr(payload: bytes) -> dict:
    """A byte-mode QR (CompactSeedQR)."""
    return _single(*qr_matrix_bytes(payload))


# --- writers -----------------------------------------------------------------

def write_json(path: str, obj) -> int:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        json.dump(obj, f, separators=(",", ":"))
    return os.path.getsize(path)


def build_scenario(scenario, wallets, seeds) -> tuple:
    """Returns (index_entry, files_written_bytes)."""
    wallet = wallets[scenario.wallet]
    signers = wallet_cosigners(wallet, seeds)
    psbt = build_psbt(signers, scenario.script_type, scenario.num_inputs,
                      scenario.output_shape, threshold=wallet["threshold"])
    raw = psbt.serialize()
    b64 = psbt.to_string()
    summary = summarize(psbt, wallet["network"])

    info = script_types.get(scenario.script_type)
    # The descriptor step only earns its place when there's an on-device address
    # to check it against.
    has_own_output = any(o["kind"] in ("change", "self_transfer") for o in summary["outputs"])
    needs_descriptor = info.is_multisig and has_own_output

    written = 0
    variants = qr_variants(raw)
    variant_index = {}
    for fmt, densities in variants.items():
        variant_index[fmt] = {}
        for density, payload in densities.items():
            rel = f"data/qr/{scenario.id}.{fmt}.{density}.json"
            written += write_json(os.path.join(DIST, rel), payload)
            variant_index[fmt][density] = {
                "file": rel,
                "count": payload["count"],
                "modules": payload["max_modules"],
                "version": payload["max_version"],
            }

    written += write_json(os.path.join(DIST, f"data/scenario/{scenario.id}.json"), {
        "id": scenario.id,
        "psbt_base64": b64,
        "psbt_bytes": len(raw),
        "summary": summary,
    })

    entry = {
        "id": scenario.id,
        "title": scenario.title,
        "blurb": scenario.blurb,
        "wallet": scenario.wallet,
        "script_type": scenario.script_type,
        "script_label": info.label,
        "sig_type": info.sig_type,
        "network": scenario.network,
        "num_inputs": scenario.num_inputs,
        "output_shape": scenario.output_shape,
        "tags": scenario.tags,
        "is_default": scenario.is_default,
        "psbt_bytes": len(raw),
        "signing_seeds": wallet["cosigners"],
        "threshold": wallet["threshold"],
        "needs_descriptor": needs_descriptor,
        "summary": summary,
        "qr": variant_index,
    }
    return entry, written


def build_seed_files(seeds) -> tuple:
    entries, written = [], 0
    for name, seed in seeds.items():
        words = seed["mnemonic"].split()
        digits = standard_seedqr_digits(words)
        entropy = compact_seedqr_bytes(words)
        assert entropy.hex() == seed["entropy_hex"], f"{name}: compact entropy mismatch"
        written += write_json(os.path.join(DIST, f"data/seed/{name}.json"), {
            "name": name,
            "mnemonic": seed["mnemonic"],
            "words": seed["words"],
            "master_fingerprint": seed["master_fingerprint"],
            "standard": {"payload": digits, "qr": text_qr(digits)},
            "compact": {"payload_hex": entropy.hex(), "qr": bytes_qr(entropy)},
        })
        entries.append({"name": name, "words": seed["words"],
                        "master_fingerprint": seed["master_fingerprint"],
                        "file": f"data/seed/{name}.json"})
    return entries, written


def build_wallet_files(wallets) -> tuple:
    entries, written = [], 0
    for name, wallet in wallets.items():
        info = script_types.get(wallet["script_type"])
        addresses = {}
        for branch, items in wallet["addresses"].items():
            addresses[branch] = [
                {**item, "qr": address_qr(item["address"])} for item in items
            ]
        written += write_json(os.path.join(DIST, f"data/wallet/{name}.json"), {
            "name": name,
            "descriptor": wallet["descriptor"],
            # SeedSigner imports a descriptor from either UR type, and it isn't
            # settled which one Sparrow emits, so ship both and let the UI pick.
            "descriptor_urs": {
                "crypto-output": {
                    "label": "crypto-output",
                    "payload": wallet["ur_crypto_output"],
                    "qr": text_qr(wallet["ur_crypto_output"]),
                },
                "crypto-account": {
                    "label": "crypto-account",
                    "payload": wallet["ur_crypto_account"],
                    "qr": text_qr(wallet["ur_crypto_account"]),
                },
            },
            "addresses": addresses,
            "cosigner_keys": wallet["cosigner_keys"],
        })
        entries.append({
            "name": name, "policy": wallet["policy"], "network": wallet["network"],
            "script_type": wallet["script_type"], "script_label": info.label,
            "sig_type": info.sig_type, "threshold": wallet["threshold"],
            "cosigners": wallet["cosigners"], "derivation": wallet["derivation"],
            "file": f"data/wallet/{name}.json",
        })
    return entries, written


def build_message_files(seeds, wallets, networks) -> tuple:
    """Message-signing payloads: `signmessage {path} ascii:{message}`.

    Not upper-cased — SeedSigner detects these with a lowercase
    `startswith("signmessage")`, so the alphanumeric-mode trick used for UR
    payloads would make them undetectable.
    """
    entries, written = [], 0
    for network in networks:
        for md in MESSAGE_DEFS:
            info = script_types.get(md["script_type"])
            base = scenario_defs.WALLET_FOR_SCRIPT_TYPE[md["script_type"]]
            wallet_name = base if network == "main" else f"{base}_testnet"
            wallet = wallets[wallet_name]
            account_path = wallet["derivation"]
            full_path = f"{account_path}{md['path_suffix']}"
            payload = f"signmessage {full_path} ascii:{md['message']}"

            signers = wallet_cosigners(wallet, seeds)
            address = wallet["addresses"]["receive"][0]["address"]

            name = md["name"] if network == "main" else f"{md['name']}_testnet"
            written += write_json(os.path.join(DIST, f"data/message/{name}.json"), {
                "name": name,
                "payload": payload,
                "message": md["message"],
                "derivation": full_path,
                "address": address,
                "seed": wallet["cosigners"][0],
                "qr": text_qr(payload, uppercase=False),
            })
            entries.append({
                "name": name, "label": md["label"], "network": network,
                "script_type": md["script_type"], "script_label": info.label,
                "derivation": full_path, "seed": wallet["cosigners"][0],
                "chars": len(md["message"]),
                "file": f"data/message/{name}.json",
            })
    return entries, written


def copy_static():
    for name in STATIC_FILES:
        src = os.path.join(SITE_SRC, name)
        if os.path.exists(src):
            shutil.copy2(src, os.path.join(DIST, name))
    for name in STATIC_DIRS:
        src = os.path.join(SITE_SRC, name)
        if os.path.isdir(src):
            shutil.copytree(src, os.path.join(DIST, name), dirs_exist_ok=True)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--network", choices=["main", "test", "both"], default="both")
    ap.add_argument("--quick", action="store_true",
                    help="skip input counts above 5 (fast iteration on the UI)")
    args = ap.parse_args()

    networks = ("main", "test") if args.network == "both" else (args.network,)
    seeds = load_seeds()
    wallets = load_wallets()
    all_scenarios = scenario_defs.all_scenarios(networks)
    if args.quick:
        all_scenarios = [s for s in all_scenarios if s.num_inputs <= 5]

    # Build into a staging directory and swap at the end, so the previous build
    # keeps serving throughout. Wiping DIST up front left the dev server with no
    # index.html for the ~2 minutes of a full build — anyone testing on a phone
    # in that window just got a directory listing.
    global DIST
    final = DIST
    staging = final + ".building"
    if os.path.exists(staging):
        shutil.rmtree(staging)
    os.makedirs(staging)
    DIST = staging

    started = time.time()
    total_bytes = 0
    scenario_entries = []
    for i, scenario in enumerate(all_scenarios, 1):
        entry, written = build_scenario(scenario, wallets, seeds)
        scenario_entries.append(entry)
        total_bytes += written
        biggest = max(entry["qr"][f][d]["count"]
                      for f in entry["qr"] for d in entry["qr"][f])
        print(f"  [{i:>3}/{len(all_scenarios)}] {scenario.id:<44s} "
              f"{entry['psbt_bytes']:>7,}B  up to {biggest:>3} frames")

    seed_entries, w = build_seed_files(seeds)
    total_bytes += w
    wallet_entries, w = build_wallet_files(wallets)
    total_bytes += w
    message_entries, w = build_message_files(seeds, wallets, networks)
    total_bytes += w

    total_bytes += write_json(os.path.join(DIST, "data/index.json"), {
        "warning": WARNING,
        "defaults": {"format": DEFAULT_FORMAT, "fps": DEFAULT_FPS, "network": "main",
                     "seedqr": DEFAULT_SEEDQR},
        "formats": {k: {"label": v["label"], "note": v["note"],
                        "default_density": v["default_density"],
                        "densities": list(v["densities"])}
                    for k, v in FORMATS.items()},
        "density_labels": DENSITY_LABELS,
        # Human-friendly names for the pickers. "P2SH-P2WPKH" means nothing to
        # someone at a demo table; "Nested SegWit" does.
        "script_labels": {name: info.label for name, info in
                          script_types.SCRIPT_TYPES.items()},
        "sig_type_labels": {script_types.SINGLE_SIG: "Single sig",
                            script_types.MULTISIG: "Multisig"},
        "output_shape_labels": scenario_defs.OUTPUT_SHAPE_LABELS,
        "scenarios": scenario_entries,
        "seeds": seed_entries,
        "wallets": wallet_entries,
        "messages": message_entries,
    })

    copy_static()

    # Swap the finished build in. Rename is near-instant, so the window where the
    # site is unavailable is a moment rather than the length of a build.
    DIST = final
    previous = final + ".previous"
    if os.path.exists(previous):
        shutil.rmtree(previous)
    if os.path.exists(final):
        os.rename(final, previous)
    os.rename(staging, final)
    shutil.rmtree(previous, ignore_errors=True)

    elapsed = time.time() - started
    print(f"\nBuilt {len(scenario_entries)} scenarios, {len(seed_entries)} seeds, "
          f"{len(wallet_entries)} wallets, {len(message_entries)} messages")
    print(f"  {total_bytes / 1_048_576:.1f} MiB of data in {elapsed:.1f}s -> {DIST}")


if __name__ == "__main__":
    main()
