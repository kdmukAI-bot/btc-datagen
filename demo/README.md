# Demo table print material

Companion print-outs for a live, hands-on SeedSigner demo station. `poster.html`
is a one-page US Letter sheet that points visitors at **testqrs.com** so they can
run the device themselves — including when nobody is standing at the table.

To just *look* at it, open `poster-preview.png` — a 2x raster of the same sheet,
regenerated on every build so it cannot drift from the HTML.

## Getting it to a printer

`poster.html` is a **single self-contained file** — logo and QR are inlined SVG,
no sidecar assets — so moving it is copying one file. Either:

- **Over the LAN.** `python3 -m http.server 8000 --bind 0.0.0.0` from this
  directory, then open `http://<this-box>:8000/poster.html` on the machine with
  the printer. Serves on all interfaces, so stop it when done.
- **On a USB stick.** Copy `poster.html` alone; it renders offline.

## Printing

Print `poster.html` from a real browser (Firefox or Chrome) for vector-sharp
type. In the print dialog:

- **Paper:** US Letter, portrait
- **Margins: None.** Not "Default" — the browser's default margins fight the
  sheet's own `@page { margin: 0 }` and trigger shrink-to-fit, printing the whole
  poster undersized inside a white border
- **Uncheck "Print headers and footers."** Otherwise the browser stamps the URL,
  date and page number into the margins, straight onto the poster
- **Scale:** 100%
- **Background graphics:** not required. Every black element is SVG fill, border,
  or text, so it prints correctly with backgrounds off. This is deliberate — see
  the note on `.steps .n` in the CSS.

Designed for a **monochrome laser printer**: pure black on white, no greys and no
large ink fills. The SeedSigner logo is recolored from brand orange to solid
black, because orange halftones to a muddy grey that reads as a printing fault at
this size.

On A4 the browser scales the sheet to about 97%. It still fits and stays legible.

### Don't route it through an HTML-to-PDF converter

Print the HTML itself. Two renderers were tried and both are worse:

- **WeasyPrint 69** mangles it — the layout leans on flexbox throughout, and it
  drops the inline-SVG step-number discs entirely and breaks "Try me." across two
  lines.
- **Rasterizing the browser render to PDF** is faithful but softer. Even at a
  pixel-per-dot 5100x6600 (600dpi on Letter), 0.58% of the image is antialiased
  midtone grey — the edge pixels around every glyph. A monochrome laser cannot
  print grey, so it halftones them into a dithered fringe around each letterform.
  Printing the HTML keeps the type as vector outlines, which the printer's RIP
  renders at device resolution onto flat black-or-white dots.

## Regenerating

`poster.html` is **generated** — edit `build_poster.py`, not the HTML, or your
copy changes get overwritten on the next build.

```sh
.venv/bin/python demo/build_poster.py
```

Only needs `qrcode`, already in `requirements.txt`; the preview step additionally
shells out to `firefox` and is skipped with a warning if it is not installed.
Re-run it after changing the
poster copy, or if the demo URL ever moves — the QR is generated from the `URL`
constant at the top of the script, so the printed code can never drift out of
sync with the printed text.

## What the poster assumes

- The site at **testqrs.com** leads with a "Sign a transaction" activity, and the
  remaining steps are below the fold — step 4 exists purely because people do not
  realise the page scrolls
- The transaction is presented as an **animated** QR

If either changes, steps 2–4 need updating.

**The poster carries no "test data only" warning by design.** The site states it
twice — a sticky banner and the landing line — and repeating it here crowded out
the parts that actually get someone started. Keep that in mind before pointing
this sheet at anything other than testqrs.com.
