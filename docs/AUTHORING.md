# Authoring STRATA labs

This guide is for two authors at once: a human writing a lab by hand, and
an AI asked to produce one ("build me a lab from this HackerOne report",
"give me a harder XSS lab"). Both work from the same contract, the same
helpers, the same validator. If you can make `STRATA.registerLab()` accept
your object, your lab is done — it appears in the catalog, runs in the
7-plane instrument, carries objectives and hints, and works with
intercept mode.

A lab file is **a plain `.js` file that calls `STRATA.registerLab({...})`**.
Load it by dropping it onto the catalog page (or *Your labs → Load a lab
file*). The validator smoke-runs your engine before the lab is accepted.

> **Trust model:** a lab file is *local code* with the page's full
> privileges — same trust level as opening any HTML file. Validation checks
> **shape, not safety**; it exists to catch authoring mistakes, not to
> sandbox hostile labs. Only load files you trust. Keep this in mind before
> any community catalog exists.

The best documentation is the source: `strata.html` contains 14 golden-reference
labs. Read `LAB_SQLI` (the canonical attack lab), `LAB_FOUNDATIONS` (a guided
tour, not an attack), and `LAB_SSRF` (free-typed engine with real parsing).

---

## 1. The mental model

A lab is **one vulnerable (or correctly-built) app, sliced into seven
layers**, all rendering the same student input at once:

| plane | typical content |
|---|---|
| L0 Surface | the app as the victim sees it — a simulated browser window |
| L1 Client/DOM | browser code, the DOM, the URL bar |
| L2 Request/Wire | the HTTP request, exactly what Burp would show |
| L3 Edge | proxy / WAF / CDN — anything between client and origin |
| L4 Server | the app's code (Flask-ish Python by house convention) |
| L5 *the weak spot* | query / authz / crypto / design / the missing check |
| L6 Data/Parse | the database, the DOM tree, the advisory, the outcome |

The student's input is drawn **amber (taint)** at every layer, without
exception. Nothing else in the UI is warm. The teachable moment is always
the same shape: amber bytes stop being *data* and become *syntax* (SQL),
*markup* (HTML), a *decision* (authz), or a *destination* (redirect).
Layer 5 is usually where that promotion is decided — that is also where
the dashed **trust boundary** membrane floats by convention.

## 2. The contract

```js
STRATA.registerLab({
  // ── identity (required) ─────────────────────────────────────────
  id: "my-lab",              // lowercase slug, unique, 2–32 chars
  code: "A01",               // short badge (OWASP id, "LAB 07", …)
  cat: "Broken Access Control",   // groups the catalog; reuse existing cats when possible
  title: "One sentence, what's broken where",
  difficulty: "Apprentice",   // Beginner | Apprentice | Practitioner
  goal: "HTML string — what the student must achieve",   // shown in the top bar

  // ── structure (required) ───────────────────────────────────────
  layers: [                  // 7 entries (4–9 allowed; 7 is the house style)
    { code:"L0", title:"Surface", meta:"login page" },   // meta = the small label
    // ... L1..L6
  ],
  boundary: 4,               // membrane floats between layers[boundary] and [boundary+1]
  boundaryLabel: "Redirect check",
  boundaryTone: "breach",    // "breach" (red, default) | "safe" (green — Foundations uses this)

  // ── interaction (required) ─────────────────────────────────────
  defaultQ: "/account",      // opening state of the input
  presets: [                 // console buttons; ≥1 required
    { q:"/account", label:"Honest path" },
    { q:"//evil.example", label:"Off-site", spoiler:true },  // spoiler = hidden until solved
  ],
  consoleLabel: "returnTo values",   // label above the presets (default "Payloads")

  // ── the engine (required) ──────────────────────────────────────
  analyze(q){ /* pure function of the input string → analysis object */ },
  layerState(i, a){ /* taint state of layer i → vocabulary word */ },
  render: { 0: a => `…`, /* ...one function per layer... */ },
  trace(a){ /* [{h:"L0 · Surface", state:"present", b:"…"}, × per layer] */ },
  verdict(a){ /* [["Status","302",""], ...] rows for the verdict box */ },
  solved(a){ /* final objective test */ },     // required unless tour:true

  // ── challenge (strongly recommended) ───────────────────────────
  //    hints[] and reveal are REQUIRED on every step; ids must be unique
  //    (they key saved progress).
  challenge: { steps: [
    { id:"offsite", label:"Redirect off-site",          // shown in the Objectives rail
      test: a => a.offsite,                             // runs against live analysis
      hints: ["The check is startswith(\"/\")…",        // revealed one rung at a time
              "Two slashes also start with one."],
      reveal: "//evil.example" },                       // last rung shows + can run
  ]},

  // ── intercept (optional; omit for tour-style labs) ─────────────
  wire: { type:"query", path:"/login", param:"returnTo" },
  //   type: "query" | "path" | "json" | "form" | "login"
  //         | "fragment" (DOM labs — intercept button explains there's nothing to intercept)
  //         | "offline" (no live request, e.g. hash cracking)
  //         — or ANY custom type, if you also supply build(q) → raw
  //           and parse(raw) → {q} | {error} (see LAB_JWT for the reference)

  // ── optional behavior hooks ────────────────────────────────────
  // onFire(a): called when a run actually FIRES (Enter / preset / intercept)
  //   — never on keystrokes. Use for per-fire side effects like attempt logs;
  //   analyze() must stay pure.
  // domMode: "parser" | "innerHTML" — how buildDomTree badges <script> nodes
  //   for your lab. Set "innerHTML" for DOM-sink labs (the built-in xss-dom
  //   lab sets it implicitly).

  // ── catalog card (optional for external labs) ──────────────────
  card: { sig: ["a","a","a","a","x","x","a"],           // per-layer preview strip
          blurb: "One or two sentences, may use <code>…</code>" },

  tour: false,   // true = guided tour: no solve state, "Guided tour" pill (see Foundations)
});
```

### `layerState` vocabulary — the taint signature

Each layer returns exactly one word; the shell colors planes, callouts
and trace steps from it:

| state | meaning | visual |
|---|---|---|
| `present` | your input is here, inert | amber dot |
| `promoted` | your bytes became syntax/markup here | amber, promoted |
| `sink` | a client source→sink flow (DOM bugs) | amber, sink |
| `boundary` | the trust boundary that failed here | red crossed |
| `blocked` | a defense stopped the payload here | red crossed |
| `absent` | your input never reached this layer | dim |
| `clean` | untouched/normal | neutral |

The signature IS the lesson. Reflected XSS: amber everywhere. DOM XSS:
`present, sink, absent, absent, absent, absent, promoted` — the network
goes dark because the fragment never leaves the browser. WAF lab: `blocked`
at L3 unless bypassed. Choose states so the cross-section view (`⌥space`)
tells the bug's story at a glance.

### `analyze(q)` — the honesty rules

1. **Pure.** Same input string, same output object, no DOM access, no
   randomness, no stored state. The shell calls it on every keystroke.
2. **Free-typed, not enumerated.** The engine must actually reason about
   arbitrary input — a regex, a parser, a normalizer, real arithmetic.
   A lookup table that only accepts the preset answers is not a lab.
   (Golden examples: the SQL lexer, `scanVectors`, the IP canonicalizer,
   the real `md5()` + wordlist.)
3. **Simulated effect, real reasoning.** Prove the vector *would* fire;
   never execute it. `alert()` on the surface is a simulated dialog
   (`alertSim()`), shown only after the engine proved execution.

### `render[i](a)` — building layer content

Return an HTML string. Helpers are available as globals (also exported on
`STRATA.helpers`): `esc`, `taint`, `taintMarkup`, `codeLines`, `note`,
`explain`, `kv`, `field`, `siteFrame`, `productCard`, `safeRender`,
`buildDomTree`, `intendedVsParsed`, `vectorList`, `alertSim`, `scanVectors`,
`wafScan`, `md5`, `clip`, `plural`.

**Safety rules (non-negotiable):**

- `esc()` every dynamic byte that isn't deliberately taint-marked. The
  payload must never reach the page as live HTML.
- To *show* how a payload would render, use `safeRender()` (whitelist
  renderer — script/svg/handlers are dropped, `<img>` becomes a glyph).
  To *tokenize* it for display, use `taintMarkup()`.
- For DOM trees, `buildDomTree(html, hostSel)` parses into a **detached**
  document and only reads it.
- Never `fetch`, never load remote resources, never `eval`.

House style for layer content: L2/L4/L1 use `codeLines([...])` with
`note("warn", "Layer N · label", "…")` annotations; explainers use
`explain("Question?", "…")`; comparisons use `kv([[k, v, cls]])`. Notes
are titled `Layer N · short label` — one idea per note, terse, concrete,
pointing at the layer the student is looking at.

### Presets & spoilers

Presets are guided examples, not answers. Mark the preset that completes
the **final objective** `spoiler: true` — it stays hidden until the lab is
solved, then unlocks. Failure-state presets ("Blocked · script") are
teaching moments: keep them visible. **At least one preset must stay
visible** (the validator enforces it — an all-spoiler console leaves the
student nothing to click). Convention: `defaultQ` equals the first
(non-spoiler) preset, so the opening state has a highlighted button.

### Challenges

`test(a)` runs against the live analysis on every keystroke/fire —
objectives complete when the *engine* says so, whichever way the input
arrived. A full set of objectives counts as a **clean solve** only if the
completing run was typed or intercepted; presets/hints yield "Solved ·
hints". Progress persists in `localStorage` (`strata.progress.v1`).

Write 2–4 steps that mirror the real attack: recon → first effect →
impact. Hints escalate: nudge toward a layer → describe the technique →
the last rung reveals the payload. One sentence each, in the lab's voice.

### Wire / intercept mode

With a `wire`, the student can toggle **Intercept** and edit the raw HTTP
request (the shell builds it, URL-encodes the payload, and re-derives
everything from the edited bytes — your `analyze()` receives the decoded
parameter exactly as an origin would). Use `type:"fragment"` for DOM labs
(the button explains why there's nothing to intercept — that's the
lesson) and `type:"offline"` for labs with no request (cracking, log
replay).

## 3. Validation & the dev loop

1. Copy `templates/lab-template.js`, fill it in.
2. Open `strata.html`, drop your file on the catalog (or *Load a lab file*).
3. The validator checks structure AND smoke-runs the whole engine — not
   just on `defaultQ`, but on **every preset and a battery of hostile
   probes** (`""`, `<`, `'`, `"`, `//`, a long string). For each probe it
   runs `analyze` → `layerState(i, a)` → `render[i](a)` → `trace(a)` →
   `verdict(a)` → `solved(a)` → every `step.test(a)`. A lab that crashes at
   the first keystroke fails validation, not in front of a student.
4. Iterate until it loads, then play it: complete every objective, use
   every hint rung, try intercept mode, check the cross-section view.

**Replacing labs.** Dropping a lab file whose `id` matches a lab you
registered earlier *replaces* it in place — that's the iterate loop.
Built-in ids are reserved (a clear error says so). When you replace a lab
whose challenge changed, its saved progress resets (progress is
fingerprinted by step ids + title). `registerLab(lab, { silent: true })`
registers without navigating; by default the catalog rebuilds and your lab
opens immediately.

Add `?perf` to the URL for the timing HUD if you want to see what your
`analyze`/renders cost.

## 4. Style guide (the STRATA voice)

- **Terse, concrete, second person.** "Your `'` closed the literal the
  developer opened." Not: "In this section we will explore…"
- One idea per note. Point at the layer the student is on.
- Drafting-annotation register: short uppercase labels, wide tracking,
  monospace. `Layer 4 · the bug is a missing line` — not `Why this is
  vulnerable!!!`
- The fix is always named, in one line, next to the flaw:
  `db.execute(sql, (q,))`, `.textContent`, one generic login error.
- Every lab names its **defense** somewhere — a lab that can't state the
  patch isn't finished.
- Difficulty calibration: *Beginner* (tour), *Apprentice* (classic
  payload, one step), *Practitioner* (bypass something, multiple steps).

## 5. AI authoring recipe

You are an AI writing a STRATA lab. Work like this:

1. **Read the references first**: this file, `templates/lab-template.js`,
   one golden lab that matches your bug class (`LAB_SQLI` for injection,
   `LAB_IDOR` for access control, `LAB_SSRF` for anything
   request-forging, `LAB_FOUNDATIONS` for tours).
2. **From the source material, extract the anatomy**: where the input
   enters, what it crosses, where it's trusted, what the impact is. Map
   it onto the seven planes and decide the taint signature.
3. **Write the engine first** — a pure `analyze()` that actually parses
   the input. Then `layerState`, then the seven renders, then trace,
   verdict, challenge, wire. Presets last (and mark the answer
   `spoiler:true`).
4. **Validate in a loop**: write the file, load it in `strata.html`,
   fix every validator error, then *play the lab end to end* and fix
   every objective whose `test` doesn't fire when it should.
5. **Self-review against the checklist** below before handing it over.

Common AI failure modes (all caught by review, most by the validator):
missing `esc()` around dynamic bytes, states outside the vocabulary,
an `analyze()` that only accepts the exact preset strings, the answer
as a non-spoiler preset, executing instead of simulating, seven layers
of prose with no engine, and forgetting to name the fix.

### Worked prompts

- *From a report:* "Here is a vulnerability report: ⟨paste⟩. Build a
  STRATA lab that reproduces what the reporter did, layer by layer, with
  objectives matching the report's reproduction steps."
- *Harder variant:* "Here is lab X. Build a harder version: keep the
  same bug class and instrument, add ⟨a defense to bypass / a constraint
  (no angle brackets, blind only, second-order) / a nastier context⟩,
  and raise the hint ladder accordingly."
- *Dev risk:* "Here is my code: ⟨paste⟩. Build a lab demonstrating how
  this exact code is exploited — use my real function names on L4."

## 6. Pre-submit checklist

- [ ] Loads via drag-drop with zero validator errors
- [ ] Every objective completes — and *only* when it should
- [ ] Free-typed variants work (misspellings, encodings, neighbors)
- [ ] The answer preset is `spoiler:true`; no note text hands it over
- [ ] `esc()` on every dynamic byte; payload never executes
- [ ] Taint signature tells the story in cross-section view
- [ ] The one-line fix is named on the right layer
- [ ] Intercept mode works (or is deliberately `fragment`/`offline`)
- [ ] Trace, verdict and notes read in the STRATA voice
