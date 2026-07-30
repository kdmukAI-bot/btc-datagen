# Browser gotchas that cost real time on this site

Non-obvious behaviours hit while building the demo site's canvas rendering and
folding-paper animation. None are bugs in the browser; all of them fail *quietly*,
which is why they were expensive.

## Canvas does not participate in font loading

Setting `ctx.font = '16px "Permanent Marker"'` **never triggers a webfont fetch**.
The Font Loading API only downloads a face when something in the DOM is laid out
with it. The handwritten label started as a DOM element (fine), then moved into
the canvas for scan fidelity — at which point nothing in the document referenced
the family, the `@font-face` stayed unused, and every label silently painted in
the fallback serif. No console error, no network request.

Force it before the first paint and re-draw when it settles:

```js
document.fonts.load('16px "Permanent Marker"').then(() => redraw());
```

## `lineWidth = 1` is one *device* pixel, not one CSS pixel

After scaling the context by `devicePixelRatio`, all canvas units are device
pixels. `lineWidth = 1` is therefore 1/3 of a CSS pixel at dpr 3 — invisible on a
phone while looking perfectly fine in dpr-1 desktop screenshots. This is exactly
the class of bug a screenshot-based harness cannot catch: the template grid
looked correct in every capture and was absent on the user's actual device.

Anything meant to be visible needs a floor: `lineWidth = Math.max(1, dpr * w)`.
Assume any hairline that "works" at dpr 1 is untested.

## Author-origin `display` beats `[hidden]`

The UA stylesheet's `[hidden] { display: none }` has no special power — it's an
ordinary declaration and loses to any author rule with equal-or-higher
specificity. A rule like

```css
.fs { display: flex; }
```

keeps `<div class="fs" hidden>` **visible forever**. Here that shipped a
permanently-open fullscreen overlay: a blank white sheet over the whole page,
which read as "the animated QR is broken" rather than "an overlay is open".

Whenever `display` is set on a class that also gets toggled with `hidden`, pair
it with:

```css
[hidden] { display: none !important; }
```

Related failure in the same family: an element that is simply never unhidden
(`#step-seed`) also produces silence, not an error. Have the smoke test assert
that every step it expects is actually visible.

## Specificity: `.class span` (0,1,1) outranks `.class-name` (0,1,0)

A descendant selector picks up an extra element component. So

```css
.fold-back-note span { display: inline; }   /* 0,1,1 */
.fold-back-name      { display: block;  }   /* 0,1,0 — loses */
```

collapsed the fingerprint onto the label's line at desktop widths. The fix is to
scope the broad rule to the elements that actually want it
(`.fold-back-name span, .fold-back-fp span`) rather than adding weight.

## Two-element handovers pop; pin them or remove them

The unfold animation drew the QR into CSS "stand-in" faces during the transform
and handed back to the canvas at the end. The canvas is integer-scaled (a hard
requirement — see `qr-scannability-and-verification.md`), so it is up to ~5%
narrower than its container, while the stand-ins sized to the container. The
handover therefore snapped the artwork by that leftover.

Pinning the stand-in to the canvas's own box (measured delta 0,0,0,0) fixed the
QR; the paper *outline* then popped for the same reason one layer out. The real
fix was deleting the handover — animate the element that will still be there when
the animation ends. Any A→B visual swap has to match on the exact box, and
"close enough" is visible at 5%.

## Symmetric halves double their shared edge

Both halves of the folded sheet drew a full border ring plus an inset highlight.
Along the crease those edges are coincident, so the seam rendered as a bright
white double-line through the middle of the paper. Elements that meet must draw
**outer edges only** — the shared edge belongs to neither.

## Verify string edits are ordered before splicing

`s[:start] + new + s[end:]` silently **duplicates** the region when `end < start`
instead of raising. A mis-ordered pair of anchors quietly cloned two whole
functions into `site/app.js`. Likewise, a replace whose anchor doesn't exist is a
no-op that returns a perfectly valid string — one such no-op'd `ctx.restore()`
left a clip leaked, which swallowed the entire QR after the first registration
cell. `save:3 / restore:2` in a counter found it in seconds.

Assert the anchors exist and that `start < end` before splicing, and keep a
`save`/`restore` balance check in any nontrivial canvas routine.
