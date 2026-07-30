#!/usr/bin/env python3
"""Generate the demo-table poster as one self-contained HTML file.

Inlines the SeedSigner logo (recolored to solid black for a B&W laser printer)
and a freshly generated QR code for testqrs.com, so the poster has zero external
dependencies and prints identically on any machine.
"""
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import qrcode
import qrcode.image.svg

REPO = Path(__file__).resolve().parent.parent
LOGO_SRC = REPO / "site" / "seedsigner-logo.svg"
OUT = REPO / "demo" / "poster.html"
PREVIEW = REPO / "demo" / "poster-preview.png"
URL = "https://testqrs.com"


def black_logo() -> str:
    """The brand logo with the orange swapped for black.

    Orange (#FF7300) halftones to a muddy grey on a monochrome laser printer,
    which is exactly the wrong look for the one element that has to read as
    'official' from across a table. The white knockout on 'SIGNER' is kept --
    it is what gives the right half its shape.
    """
    svg = LOGO_SRC.read_text()
    svg = re.sub(r"<\?xml[^>]*\?>", "", svg)
    svg = re.sub(r"<!--.*?-->", "", svg, flags=re.S)
    svg = svg.replace(".st0{fill:#FF7300;}", ".st0{fill:#000000;}")
    if "#FF7300" in svg:
        sys.exit("logo recolor failed: orange fill still present")
    # Scope the class names so .st0/.st1 cannot collide with anything else.
    svg = svg.replace("st0", "logo-fill").replace("st1", "logo-knockout")
    svg = svg.replace("<svg ", '<svg class="logo" role="img" aria-label="SeedSigner" ', 1)
    return svg.strip()


def qr_svg() -> str:
    """QR for the site.

    Error correction H so it survives toner speckle and thumbprints, and the
    full 4-module quiet zone baked in rather than borrowed from the surrounding
    layout -- the caption sits close under the code, and a scanner that cannot
    find a clear margin just silently refuses to lock on.
    """
    qr = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_H, border=4)
    qr.add_data(URL)
    qr.make(fit=True)
    img = qr.make_image(image_factory=qrcode.image.svg.SvgPathImage)
    svg = img.to_string().decode()
    svg = re.sub(r"<\?xml[^>]*\?>", "", svg).strip()
    # The mm sizing the factory emits fights the CSS box; drop it.
    svg = re.sub(r'width="[^"]*"\s*height="[^"]*"', 'class="qr"', svg, count=1)
    return svg


POSTER = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>SeedSigner demo table poster</title>
<style>
/* ---------------------------------------------------------------------------
   US Letter portrait, built for a monochrome laser printer.

   Pure black on white only -- no greys, no tints. Laser halftones turn mid
   greys into visible dot screens, and every large fill costs toner, so the
   design carries its weight with type size and rules instead of blocks of ink.

   Nothing sits within 0.4in of the paper edge: most laser printers cannot
   print there at all, and a poster with a clipped headline reads as broken.
--------------------------------------------------------------------------- */
@page { size: letter portrait; margin: 0; }

* { margin: 0; padding: 0; box-sizing: border-box; }

html { background: #999; }

body {
  font-family: "Helvetica Neue", Helvetica, Arial, "Liberation Sans", sans-serif;
  color: #000;
  -webkit-font-smoothing: antialiased;
}

.page {
  width: 8.5in;
  height: 11in;
  padding: 0.55in 0.6in 0.45in;
  background: #fff;
  margin: 0 auto;
  display: flex;
  flex-direction: column;
}

/* ---- masthead: eyebrow + headline on the left, logo on the right ----------
   The source SVG carries a viewBox but no width/height attributes, so `height:
   auto` leaves Firefox with nothing to resolve against and it collapses to a
   default box. Both dimensions are stated outright; 4.0 x 1.317in is the
   viewBox ratio (990:326) held exactly.
--------------------------------------------------------------------------- */
.masthead {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 0.4in;
}

.masthead-text { flex: 0 0 auto; }

.logo {
  display: block;
  flex: 0 0 auto;
  width: 4.0in;
  height: 1.317in;
}
.logo-fill { fill: #000; }
.logo-knockout { fill: #fff; }

/* ---- headline ------------------------------------------------------------ */
.eyebrow {
  font-size: 14pt;
  font-weight: 800;
  text-transform: uppercase;
  letter-spacing: 0.16em;
}

h1 {
  font-size: 58pt;
  line-height: 1;
  letter-spacing: -0.03em;
  font-weight: 800;
  margin-top: 0.03in;
}

.deck {
  font-size: 18pt;
  line-height: 1.3;
  margin-top: 0.20in;
  max-width: 7.2in;
}
.deck strong { font-weight: 800; }

/* ---- the call to action --------------------------------------------------
   This is the one thing someone must take away from the poster, so it gets a
   heavy frame and the largest type on the page after the headline.
--------------------------------------------------------------------------- */
.cta {
  margin-top: 0.26in;
  border: 5px solid #000;
  padding: 0.22in 0.26in;
  display: flex;
  align-items: center;
  gap: 0.26in;
}

.qr-block { flex: 0 0 auto; text-align: center; }

.qr {
  display: block;
  width: 2.05in;
  height: 2.05in;
  shape-rendering: crispEdges;   /* keeps module edges square at any scale */
}
.qr path { fill: #000; }

.qr-caption {
  font-size: 10.5pt;
  font-weight: 700;
  line-height: 1.2;
  margin-top: 0.08in;
  text-transform: uppercase;
  letter-spacing: 0.04em;
}

.cta-text { flex: 1 1 auto; min-width: 0; }

.cta-kicker {
  font-size: 16pt;
  font-weight: 700;
  line-height: 1.2;
}

.url {
  font-size: 50pt;
  font-weight: 800;
  letter-spacing: -0.025em;
  line-height: 1.05;
  margin: 0.06in 0 0.07in;
  white-space: nowrap;
}

.cta-note {
  font-size: 12.5pt;
  line-height: 1.25;
  font-weight: 700;
}

/* ---- steps ---------------------------------------------------------------- */
.steps {
  list-style: none;
  margin-top: 0.32in;
}

.steps li {
  display: flex;
  align-items: baseline;
  gap: 0.16in;
  font-size: 22pt;
  line-height: 1.2;
  margin-bottom: 0.18in;
}

/* The number discs are inline SVG, not a CSS background: browsers omit
   background colours from print by default, which would have printed a white
   numeral on white paper. An SVG fill is content and always prints. */
.steps .n {
  flex: 0 0 auto;
  width: 0.44in;
  height: 0.44in;
  /* baseline alignment nudge so the disc sits with the text, not above it */
  position: relative;
  top: 0.06in;
}

.steps b { font-weight: 800; }


/* ---- where to go next ----------------------------------------------------
   Set smaller than testqrs.com: someone at the table needs the demo URL, and
   only someone who already liked the thing needs these.
--------------------------------------------------------------------------- */
.links {
  margin-top: auto;      /* anchors the footer to the foot of the sheet */
  padding-top: 0.15in;
  border-top: 3px solid #000;
  display: flex;
  gap: 0.4in;
  align-items: flex-end;
}

.links-col { flex: 0 0 auto; }

.colophon {
  margin-top: 0.14in;
  font-size: 11pt;
  line-height: 1.3;
}

.links-label {
  font-size: 9pt;
  font-weight: 700;
  letter-spacing: 0.09em;
  text-transform: uppercase;
  margin-bottom: 0.03in;
}

.links-val {
  font-size: 15pt;
  font-weight: 800;
  letter-spacing: -0.01em;
}
.links-val span { display: inline-block; margin-right: 0.26in; }
.links-val span:last-child { margin-right: 0; }

/* ---- screen-only preview chrome ------------------------------------------ */
@media screen {
  body { padding: 24px 0; }
  .page { box-shadow: 0 2px 24px rgba(0,0,0,.45); }
}
@media print {
  html { background: #fff; }
  .page {
    box-shadow: none;
    margin: 0;
    /* Sits just under the 11in sheet. At exactly 11in, sub-pixel rounding in
       the layout can tip the box one hair over the page box and eject a blank
       second sheet -- a failure you only find out about at the print shop.
       The footer is bottom-anchored, so the 0.1in comes out of slack, not copy. */
    height: 10.95in;
    overflow: hidden;
  }
}
</style>
</head>
<body>
<div class="page">

  <!-- Written for an unattended table: the job of the top of this sheet is to
       get a stranger to physically pick the device up, so the invitation leads
       and the explanation follows. Deliberately NOT "a real bitcoin
       transaction" -- the sheet says three inches lower that the data is fake,
       and a poster that contradicts itself loses whichever half is read second.

       Logo beside the headline rather than stacked above it: side by side they
       occupy one band instead of two, which is where the vertical room for a
       fourth step and a full-size QR comes from. -->
  <header class="masthead">
    <div class="masthead-text">
      <div class="eyebrow">Hands-on demo</div>
      <h1>Try me.</h1>
    </div>
    __LOGO__
  </header>

  <p class="deck">
    Pick it up. It&rsquo;s a <strong>prototype</strong>: SeedSigner, the open-source DIY
    bitcoin signer, now running on a <strong>$43 touchscreen</strong>.
  </p>

  <div class="cta">
    <div class="qr-block">
      __QR__
      <div class="qr-caption">Scan with your phone<br>&mdash; not the SeedSigner</div>
    </div>
    <div class="cta-text">
      <!-- Break kept explicit: at this width the line wraps on its own anyway,
           and letting it choose strands "phone:" by itself. -->
      <div class="cta-kicker">Pull up the test QR codes<br>on your phone:</div>
      <div class="url">testqrs.com</div>
      <div class="cta-note">Works on any phone. Nothing to install.</div>
    </div>
  </div>

  <ol class="steps">
    <li>__STEP1__<span>Open <b>testqrs.com</b> on your phone</span></li>
    <li>__STEP2__<span>Tap <b>&ldquo;Sign a transaction&rdquo;</b></span></li>
    <!-- Hard break rather than letting it wrap: free wrapping strands a single
         word on line two, which reads as a mistake at this size. -->
    <li>__STEP3__<span>Scan the site&rsquo;s animated QR code<br>with the
        SeedSigner</span></li>
    <!-- A numbered step, not a footnote: the remaining steps sit below the fold
         on a phone, and the numbered list is the part people actually read. -->
    <li>__STEP4__<span><b>Scroll the site</b> for the next steps</span></li>
  </ol>

  <div class="links">
    <div class="links-col">
      <div class="links-label">Learn more</div>
      <div class="links-val">seedsigner.com</div>
    </div>
    <div class="links-col">
      <div class="links-label">Follow on Twitter</div>
      <div class="links-val"><span>@SeedSigner</span><span>@KeithMukai</span></div>
    </div>
  </div>

  <p class="colophon">SeedSigner is a volunteer-run open-source project.
    There is no company and no profit motive.</p>

</div>
</body>
</html>
"""


def disc(n: int) -> str:
    """A numbered step marker as inline SVG (see the .steps .n note in the CSS)."""
    return (
        '<svg class="n" viewBox="0 0 40 40" aria-hidden="true">'
        '<circle cx="20" cy="20" r="20" fill="#000"/>'
        '<text x="20" y="20" fill="#fff" font-size="25" font-weight="800"'
        ' text-anchor="middle" dominant-baseline="central"'
        ' font-family="Helvetica Neue,Helvetica,Arial,sans-serif">'
        f"{n}</text></svg>"
    )


PREVIEW_OVERRIDE = """
html { background: #fff !important; }
body { margin: 0 !important; padding: 0 !important;
       width: 1632px; height: 2112px; overflow: hidden; }
.page { transform: scale(2); transform-origin: 0 0;
        box-shadow: none !important; margin: 0 !important; }
</style>"""


def write_preview(html: str) -> None:
    """Rasterize the poster to a PNG for viewing without a print dialog.

    Scaled 2x before the screenshot: the poster is laid out in real inches, so
    at 1x it rasterizes at 96dpi and the small print turns to mush. Scaling the
    whole page is the only way to raise raster resolution without perturbing a
    single measurement in the layout.
    """
    firefox = shutil.which("firefox") or shutil.which("firefox-esr")
    if not firefox:
        print("skipping preview: firefox not found", file=sys.stderr)
        return

    with tempfile.TemporaryDirectory() as tmp:
        src = Path(tmp) / "preview.html"
        src.write_text(html.replace("</style>", PREVIEW_OVERRIDE))
        subprocess.run(
            [firefox, "--headless", "--screenshot", str(PREVIEW),
             "--window-size=1632,2112", src.as_uri()],
            check=True, capture_output=True, timeout=180,
            env={"MOZ_HEADLESS": "1", "HOME": str(Path.home()), "PATH": "/usr/bin:/bin"},
        )
    print(f"wrote {PREVIEW}")


def main() -> None:
    html = POSTER.replace("__LOGO__", black_logo()).replace("__QR__", qr_svg())
    for n in (1, 2, 3, 4):
        html = html.replace(f"__STEP{n}__", disc(n))
    if "__" in re.sub(r"[a-z]__[a-z]", "", html):
        sys.exit("a template placeholder was left unsubstituted")
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(html)
    print(f"wrote {OUT} ({len(html):,} bytes)")
    write_preview(html)


if __name__ == "__main__":
    main()
