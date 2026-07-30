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

## Derive the URL from the view; never accumulate into it

The site preloads a default transaction on boot so the signing view opens
instantly. `selectScenario()` wrote `?tx=<id>` into the URL unconditionally, so
*merely opening the root* rewrote the address bar to `?tx=<default>` while the
landing page was still showing. Refreshing then landed on the signing view.

The interesting part is what that did to the Back button. It did not make Back
buggy — it made Back **unfixable in principle**, because the history entry the
user started from no longer described the page they had started on. No amount of
`pushState` repairs a stack whose entries lie about their own contents. The fix
had to be upstream of the history work: build the URL from the current view in
one place, as a pure function of state, so a deep link, a fresh load and a
`popstate` cannot disagree about what a URL means.

Two rules that fell out and are worth keeping:

- **Preloading must not announce itself.** Anything loaded speculatively, for
  responsiveness, has to stay invisible to the URL, the history stack and the
  title.
- **One function decides what a URL means.** `modeFromUrl(params)` is read by
  boot, by `popstate`, and by nothing else. When that logic was inlined twice it
  had already drifted — `?tx=` alone meant "signing view" on first load and
  "home" on popstate.

Also: only push an entry when the URL actually changes. Re-selecting the current
view otherwise stacks duplicates that Back has to chew through one at a time,
which reads as a broken Back button.

## Ellipsis inside a table needs `max-width: 0`

A 62-character bech32 address in a `<th>` that the stylesheet had given
`white-space: nowrap` (right for short labels) could not wrap, so the table grew
past the viewport and the amounts sat off the right edge of the phone with
nothing to scroll to.

The auto table layout sizes a column to its content, which gives a flex child
inside it no definite width to ellipsize against. `max-width: 0` combined with
`width: 100%` on the cell is the standard escape: it asks for zero and then for
everything, so the column takes exactly the space the other columns leave.

`table-layout: fixed` also fixes the overflow and was tried first — but it
divides width evenly unless *every* column is given an explicit size, which
silently degraded the other `.kv` tables on the page.

End-truncation is the wrong shape for an address: the tail is what you check
against the device screen, so `bc1q…` alone is useless. CSS cannot ellipsize in
the middle, so the address is split into two spans — the head takes the slack
and ellipsizes, the tail is `flex: none` and never shrinks.

**Test it by measuring, not by looking.** `scrollWidth > clientWidth` on the
containers, plus `documentElement.scrollWidth - clientWidth` for the page, is the
only reliable check: horizontal overflow is off-camera by definition, so it looks
perfect in every screenshot.
