# ThreatSense — Accessibility Checklist (Task 4.4)

WCAG 2.1 Level AA, per Section 7.7 of the proposal.
Measured 17 August 2026 against commit following `f5a6edc`.

Two thresholds matter below:
- **4.5:1** — normal-size text (WCAG 1.4.3)
- **3.0:1** — large text (18pt+/14pt bold) and non-text UI such as status dots,
  chart strokes and focus rings (WCAG 1.4.11)

---

## 1. Contrast — measured, not estimated

Ratios computed with the WCAG relative-luminance formula against both surfaces
the element can sit on: card `#ffffff` and page `#f4f6fc`.

### Severity tags (text on tinted background)

| Tag | Foreground | Background | Ratio | Result |
|---|---|---|---|---|
| CRITICAL | `#c81e3c` | `#feeaee` | 4.91 | PASS |
| HIGH | `#c2410c` | `#fff1e8` | 4.69 | PASS |
| MEDIUM | `#9f6408` | `#fff7e6` | 4.58 | PASS — **was `#a96a09` at 4.14, failed** |
| LOW | `#1d61c4` | `#eaf2fe` | 5.23 | PASS |
| ACKNOWLEDGED | `#515a72` | `#eef1f9` | 6.08 | PASS |

### Non-text indicators (dots, chart strokes)

The bright brand colours fail 3:1 on light backgrounds, so darker `-ink`
variants were added for small indicators. Brand colours are retained for large
filled areas (bars, hero panel) where they sit on dark or saturated
backgrounds.

| Token | Value | On page | Result |
|---|---|---|---|
| `--crit-ink` | `#d81b41` | 4.68 | PASS |
| `--high-ink` | `#e14e08` | 3.67 | PASS — raw `--high #ff7a45` was 2.39, failed |
| `--med-ink` | `#b87700` | 3.42 | PASS — raw `--med #ffb020` was 1.69, failed |
| `--ok-ink` | `#12a07f` | 3.06 | PASS — raw `--ok #16c098` was 2.15, failed |

### Body and secondary text

| Token | On card | Result |
|---|---|---|
| `--ink` `#0a0e1a` | 19.25 | PASS |
| `--ink2` `#515a72` | 6.87 | PASS |
| `--faint` `#647092` | 4.91 (4.55 on page) | PASS — **was `#97a0b8` at 2.61, failed** |
| `--accent-deep` `#1a3ce6` | 7.41 | PASS |
| `--accent` `#2b54ff` | 5.50 | PASS |

**Known exception:** white text on `--crit #f5365c` measures 3.77:1. This is
used only for the notification badge and the destructive-button label, both of
which are bold and effectively large text, where 3:1 applies. Flag it if a
checker reports it; the justification is WCAG 1.4.3's large-text allowance.

---

## 2. Severity is never colour alone (WCAG 1.4.1)

Every severity indicator carries a text label:

- Severity tags render the word — CRITICAL / HIGH / MEDIUM / LOW.
- Log Sources status shows "Receiving", "Idle", "Never received", "Error"
  beside the dot, never the dot alone.
- Severity breakdown bars are labelled with name and count.
- Detection Detail states "Open — not yet acknowledged" as text.

Verified in the browser: all rendered `.stag` elements returned non-empty text.

---

## 3. Keyboard navigation

- Skip link is the **first tab stop** on every screen, jumping to `#main`.
- Tabbed 22 stops across the dashboard: **0 had no visible focus indicator**.
- `:focus-visible` gives a 2px `--accent` outline at 2px offset.
- Bell dropdown and modals close on Escape; the bell also closes on outside click.
- Modals expose `role="dialog"` and `aria-modal="true"`.
- Transport selector is a `radiogroup` with `aria-checked`.
- Sensitivity slider is a native range input with `aria-valuemin/max/now`.

---

## 4. Forms

- Every `input`, `select` and `textarea` has an associated `<label for>` or an
  `aria-label`. Audited programmatically across all `.jsx` files: **1 flagged,
  which was a false positive inside a code comment.**
- Validation errors are text, not colour-only, and inputs carry `aria-invalid`.
- The hidden file input is triggered programmatically and excluded from tab order.

---

## 5. Other

- 24 decorative icons marked `aria-hidden="true"` / `focusable="false"` so
  screen readers announce the button label instead of the icon.
- `prefers-reduced-motion` honoured — animations reduced to near-zero duration.
- `forced-colors` mode keeps severity tags and dots distinguishable by border.
- Status messages use `role="status"`; errors use `role="alert"`.

---

## Per-screen manual pass — run before submission

For each of Login, Dashboard, Detection Detail, Log Sources, Detection
Settings and Alert Config:

- [ ] Tab from the top: skip link appears first, focus visible at every stop
- [ ] Tab order follows visual order; nothing reachable is invisible
- [ ] Escape closes any open modal, drawer or dropdown
- [ ] Zoom to 200%: no content lost or overlapping (WCAG 1.4.4)
- [ ] Every form field has a visible label
- [ ] Every error message is readable as text, not colour alone
- [ ] Run WebAIM Contrast Checker on any colour pair not listed above
- [ ] Screenshot with focus visible, for evidence

### `[YOU]` — the WebAIM run

The brief asks you to run a contrast checker per screen. The table above is
computed from the source tokens, but a checker samples what is actually
rendered and may catch a pair I have not enumerated — a hover state, a
disabled control, or text over the hero gradient. Paste any flagged pair back
and it can be corrected the same way.
