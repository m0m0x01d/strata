# Build a STRATA lab with an AI

**This file is the brief you hand to an AI.** It is written *to the AI*, not
about it. Everything needed to produce a working STRATA lab is here: what to
build, what to deliver, the exact contract the validator enforces, the house
voice, and how to check the result before handing it over.

A lab is one `.js` file. There is no build step, no dependency, no server.
That is why the lab catalog is open-ended: *"teach me XSS"*, *"turn this
HackerOne report into a lab"*, *"the last one was too easy"*, *"we just got
this finding — make me an attack **and** defense lab"* all end at the same
place, a single file that drops onto the page and runs.

### How to use it

**With a coding agent in this repo** — the best path, because the agent can
run the validator:

```
claude "Read docs/AI-LAB-BRIEF.md, then build me a lab that teaches
        second-order SQL injection. Validate it before you hand it over."
```

**With a chat assistant and no repo** — paste this file, plus
`templates/lab-template.js` and one golden lab from `labs/`, then ask. You
lose the automatic validation loop, so run `node scripts/strata.mjs validate`
yourself, or just drop the file on `strata.html` and read the error box.

**Ground truth.** Where this brief and the code disagree, the code wins:
`validateLab()` in `strata.html` is the contract, and `docs/AUTHORING.md` is
the same contract written for a human reading it start to finish.

---

## 0. What you are building

STRATA renders a vulnerable app as a **cross-section**: seven layers stacked
in depth, all rendering the same student input at once.

| plane | what lives there |
|---|---|
| L0 Surface | the app as the victim sees it — a simulated browser window with a live input |
| L1 Client | browser code, the DOM, the URL bar |
| L2 Request | the HTTP request, as Burp would show it |
| L3 Edge | proxy / WAF / CDN — whatever sits between client and origin |
| L4 Server | the app's code (Flask-ish Python, by house convention) |
| L5 **the weak spot** | the query / the authz check / the crypto / the missing line |
| L6 Data | the database, the DOM tree, the outcome |

**The one rule that makes it teach:** every byte that came from the student is
drawn **amber** at every layer, without exception. Nothing else in the
interface is warm. The student tracks their own payload down the stack without
being told where to look.

**The moment you are staging** is always the same shape: amber stops being
*data* and becomes *syntax* (SQL), *markup* (HTML), *source* (shell), a
*decision* (authz), or a *destination* (redirect). That promotion is the
lesson. Your job is to make it visible on a specific layer, not to narrate it.

A lab that fails this test is not a lab: **could a student who types a
slightly different payload still learn something true?** If your engine only
recognises the three strings you put in `presets`, you have written a
slideshow. Write a parser.

---

## 1. Turn the request into a spec

Before any code, you must be able to fill in the worksheet in §1.2. Get there
using whichever of these four shapes matches the request.

### 1.1 The four request shapes

**A. "Teach me ⟨bug class⟩."** — *"make me a lab to learn XSS"*

The request is a syllabus, not a spec; you choose the scenario. Pick the
*smallest realistic app* where the bug is inevitable, not a toy. Decide which
**one** thing this lab teaches — "reflected XSS" is a topic, "your bytes leave
the server already inside an attribute, so quotes are the whole game" is a
lab. Check `strata.html` for what already exists (17 built-ins) and do not
rebuild one; if the class is covered, either pick a different *context* for
the same class (a different sink, a different encoder in the way) or say so
and propose the variant.

> Ask one clarifying question at most, and only if the answer changes the
> instrument — e.g. "server-reflected or DOM sink?" Otherwise choose, build,
> and say what you chose and why.

**B. "Build a lab from this ⟨report / writeup / CVE / URL⟩."**

The report is the source of truth for the *anatomy*; you supply the app.
Extract, in order:

1. **Where the input enters** — parameter, header, path, fragment, body field.
2. **What it crosses** — is there a WAF, an encoder, a normaliser, a proxy?
   Each one is a layer with a job.
3. **Where it is trusted** — the exact line that treats data as something
   else. This is L5.
4. **What the impact was** — this is L6, and it is what `solved()` tests.
5. **The reproduction steps** — these become your `challenge.steps`, in order.

Reproduce the *mechanism*, never the target. Rename the affected company to
the house fiction (`aperture.lab`, `shop.strata.lab`), drop real hostnames,
tokens and PII, and keep anything that is genuinely technical: the encoding
trick, the parser disagreement, the ordering bug. If the report is thin on a
layer, say what you inferred rather than inventing detail that reads as fact.

**C. "I finished lab X — make me a harder one."**

Keep the bug class and the instrument; raise exactly one axis, and name which
one you raised:

- **A defense to bypass.** Add L3 with a real filter and make your engine
  actually run it (see `wafScan`). The lesson becomes the grammar the
  blocklist cannot enumerate.
- **A constraint.** No angle brackets. No quotes. Length-capped. Blind — the
  response body never changes and the student reads a side channel.
- **A nastier context.** The reflection lands inside an attribute, a
  `<script>` string, a URL, a template.
- **Second order.** Input is stored on one request and detonates on another.
- **Chained.** Two small flaws, neither exploitable alone.

Raise `difficulty` to `Practitioner`, add a step to `challenge.steps`, and
make the hint ladder *longer*, not more generous — the first rung should now
point at a layer, not at a technique.

**D. "We received a report: ⟨finding⟩ — make an attack/defense lab."**

Build the attack lab exactly as in B, then add the `defense` block (§8). This
is the shape to use whenever a team wants the *fix* understood and not just
the bug. Your patch options must include the tempting wrong answers the team
actually proposed — a lab where every option works teaches nothing.

### 1.2 The spec worksheet

State these before writing code. If you cannot fill a row, you do not
understand the bug well enough to teach it yet.

| row | your answer |
|---|---|
| One-line lesson | the single sentence a student should be able to say afterwards |
| The app | what it is, what it legitimately does |
| Input | where the student's bytes enter (`consoleLabel`, `wire`) |
| Promotion | the exact layer and line where data becomes something else |
| Impact | what `solved(a)` tests |
| Taint signature | one `layerState` word per layer (§5) |
| Objectives | 2–4 steps: recon → first effect → impact |
| The fix | one line of code, named on the layer that carries the flaw |
| Defender? | if yes: 2+ real vectors, 2+ patches, ≥1 that holds and ≥1 that fails |

---

## 2. What you deliver

### The one required file

```
labs/<id>.lab.js
```

A plain `.js` file that calls `STRATA.registerLab({ ... })` exactly once.
No imports, no exports, no module wrapper, no build step. Naming:

- The filename stem **must** match the lab's `id`: `labs/blind-sqli.lab.js`
  registers `id: "blind-sqli"`.
- `id` is a lowercase slug, 2–32 chars, `[a-z0-9][a-z0-9-]*`, and must not
  collide with a built-in (`sqli`, `xss-reflected`, `xss-dom`, `xss-waf`,
  `idor`, `crypto`, `design`, `misconfig`, `components`, `auth`, `jwt`,
  `logging`, `ssrf`, `cmdi`, `lfi`, `csrf`, `foundations`) — the page rejects
  reserved ids with a clear error.

That file is the whole deliverable for a lab someone loads by hand.

### When the lab is published on a shelf

```
labs/catalog.json     # refresh, never hand-edit:  node scripts/strata.mjs catalog
```

The catalog pins each lab's SHA-256. Shelf labs are fetched, hash-verified and
run in a sandboxed worker. Re-run the command after *every* edit to the lab
file or CI fails on a stale hash.

### What you must NOT do

- **Never edit `strata.html`.** A lab is data; if you find yourself wanting to
  add a helper to the engine, you are solving the wrong problem. (The one
  exception is a genuine engine bug — raise it separately, do not smuggle it
  into a lab.)
- Do not add dependencies, a `package.json`, a bundler, or a test framework.
- Do not add your lab to `README.md`'s built-in table — that table is the 17
  labs inside `strata.html`.
- Do not write a separate test file. `tests/labs.test.mjs` discovers every
  `labs/*.lab.js` automatically and runs the real validator against it.

### Sandbox compatibility (only if it will be published on a shelf)

Shelf labs run in a worker with no DOM and no storage. So: no `domMode`, and a
custom `wire.build`/`wire.parse` disables intercept for that lab (the standard
wire types keep working). Everything your renders emit is sanitized on the way
back into the page. Stick to the helper library and you are already compliant.

---

## 3. The contract

Every field the validator checks, in the order it checks them. Copy
`templates/lab-template.js` rather than typing this from scratch.

```js
STRATA.registerLab({

  /* ── identity ─────────────────────────────────── REQUIRED ── */
  id: "my-lab",                 // lowercase slug, 2–32 chars, unique
  code: "A03",                  // badge: an OWASP id, or "LAB 07"
  cat: "Injection",             // catalog group — reuse an existing one (§3.1)
  title: "One sentence: what is broken, and where",
  difficulty: "Apprentice",     // "Beginner" | "Apprentice" | "Practitioner"
  goal: "HTML — what the student must achieve",

  severity: ["CRIT", "9.8"],    // optional; the bug class's typical real-world
                                // CVSS 3.1 base, as strings. "CRIT"|"HIGH"|"MED"|"LOW"
                                // + the number. Renders the same chip built-ins wear.

  /* ── structure ────────────────────────────────── REQUIRED ── */
  layers: [                     // 4–9 entries; 7 is the house style
    { code:"L0", title:"Surface", meta:"the page" },
    { code:"L1", title:"Client",  meta:"browser code" },
    { code:"L2", title:"Request", meta:"GET /search" },
    { code:"L3", title:"Edge",    meta:"no filter" },
    { code:"L4", title:"Server",  meta:"app.py" },
    { code:"L5", title:"Parser",  meta:"the weak spot" },   // name it after the bug
    { code:"L6", title:"Data",    meta:"the outcome" }
  ],
  boundary: 4,                  // membrane floats between layers[4] and [5]; 0..N-2
  boundaryLabel: "Trust boundary",
  boundaryTone: "breach",       // "breach" (red, default) | "safe" (green; tours)

  /* ── interaction ──────────────────────────────── REQUIRED ── */
  defaultQ: "lens",             // opening state; convention: == first preset
  presets: [                    // ≥1, and ≥1 must stay visible (non-spoiler)
    { q:"lens",          label:"Normal search" },
    { q:"the payload",   label:"The answer", spoiler:true }   // hidden until solved
  ],
  consoleLabel: "Payloads",     // heading above the preset buttons

  /* ── the engine ───────────────────────────────── REQUIRED ── */
  analyze(q){ /* pure fn of the input string → analysis object (§4) */ },
  layerState(i, a){ /* → one vocabulary word per layer (§5) */ },
  render: { 0: a => "…", 1: a => "…", /* … one per layer index … */ },
  trace(a){ /* exactly N entries: [{h, state, b}, …] */ },
  verdict(a){ /* rows: [[key, value, cls], …]  cls ∈ "" | "bad" | "hot" | "good" */ },
  solved(a){ /* the final objective */ },      // REQUIRED unless tour:true

  /* ── objectives ─────────────────────── strongly recommended ── */
  challenge: { steps: [        // ids unique; hints[] and reveal REQUIRED per step
    { id:"break-out", label:"Break the literal",
      test: a => a.error,                       // runs against live analysis
      hints: ["The value goes straight into the string the server builds.",
              "One quote is all it takes to end it early."],
      reveal: "'" }
  ]},

  /* ── intercept ────────────────────────────────── optional ── */
  wire: { type:"query", path:"/search", param:"q" },   // §9

  /* ── hooks ────────────────────────────────────── optional ── */
  // onFire(a): called when a run FIRES (Enter / preset / intercept), never on
  //   keystrokes. For per-fire side effects like attempt logs. analyze() stays pure.
  // domMode: "parser" | "innerHTML" — how buildDomTree badges <script> nodes.

  /* ── explanation ───────────────────── optional but expected ── */
  notes:`The bug in plain words, 2–5 sentences. <b>The fix:</b> <code>one line</code>.`,

  /* ── catalog card ─────────────────────────────── optional ── */
  card: { sig:["a","a","a","a","x","x","a"],   // exactly N marks, each of a|x|d|s
          blurb:"Two sentences for the card. <code>code</code> allowed." },

  tour: false,   // true = guided tour: no solve state (see LAB_FOUNDATIONS)

  /* ── defender edition ─────────────────────────── optional ── */
  defense: { /* §8 */ }
});
```

### 3.1 Categories and badges

Reuse an existing `cat` whenever the bug fits one — it groups the catalog:

`Foundations` · `Broken Access Control` · `Cryptographic Failures` ·
`Injection` · `Insecure Design` · `Security Misconfiguration` ·
`Vulnerable & Outdated Components` · `Authentication Failures` ·
`Software & Data Integrity` · `Logging & Monitoring Failures` ·
`Server-Side Request Forgery`

`code` is the badge on the card: the OWASP id (`A01`…`A10`) when the class
maps to one, otherwise a short label of your own.

---

## 4. The engine — `analyze(q)`

This is the lab. Everything else renders what it returns.

**1. Pure.** Same input string, same output object. No DOM, no randomness, no
stored state, no clock. It runs on every keystroke.

**2. Free-typed, not enumerated.** Actually parse. A lexer, a normaliser, real
arithmetic, a regex that encodes a rule rather than a list of answers. The
built-ins set the bar: a real SQL lexer with quote-state and comment offsets, a
vector scanner that knows which handlers auto-fire, an IP canonicaliser that
collapses `2852039166` and `0xA9FEA9FE` to `169.254.169.254`, RFC-1321 MD5
against a wordlist, Python-faithful `os.path.join` semantics. If a student
types a *neighbouring* payload — different casing, an extra space, a different
encoding, a synonym tag — your engine should still be right.

**3. Simulate, never execute.** Prove the vector *would* fire; do not run it.
`alert()` on the surface is a drawing (`alertSim`), shown only once the engine
proved execution. Never `eval`, never `fetch`, never inject live HTML.

**4. The live box echoes what the student typed.** If your L0 renders an input
with `data-live` (`field()` does), its `value` must be the student's own bytes
— never a trimmed, defaulted or reformatted version. The surface repaints on
every keystroke, so a value that differs from what they typed is rewritten
under the caret: trimming eats the space they just typed (`a b c` can only be
entered as `abc`), and a default re-fills a box they just cleared so the next
keystrokes prepend to text nobody typed. Carry the raw string through:

```js
analyze(q){
  const typed = String(q);        // what the box shows
  const val   = typed.trim();     // what the server sees
  …
  return { typed, val, … };
},
render: {
  0: a => `…${field("returnTo", a.typed, "Continue", "/account")}…`
}
```

`tests/regression.test.mjs` enforces this for every lab. Trim, parse and
default all you like *below* the input; just never feed it back into the box.

**5. Never crash.** The validator smoke-runs `analyze` on `defaultQ`, every
preset, and a hostile battery — `""`, `<`, `'`, `"`, `//`, and a 64-char
string — then runs every `layerState`, every `render`, `trace`, `verdict`,
`solved` and every `step.test` against each result. Guard your indexing and
your regex groups.

---

## 5. `layerState(i, a)` — the taint signature

One word per layer. The shell colours planes, callouts and trace steps from it.

| state | meaning | reads as |
|---|---|---|
| `present` | your input is here, inert | amber dot |
| `promoted` | your bytes became syntax/markup here | amber, promoted |
| `sink` | a client source→sink flow (DOM bugs) | amber, sink |
| `boundary` | the trust boundary that failed here | red, crossed |
| `blocked` | a defense stopped the payload here | red, crossed |
| `absent` | your input never reached this layer | dim |
| `clean` | untouched / normal | neutral |

**The signature is the lesson.** Choose it so the cross-section view
(`⌥space`) tells the story with no words at all:

- Reflected XSS — amber all the way down, promoted at the parser.
- DOM XSS — `present, sink, absent, absent, absent, absent, promoted`: the
  network planes go dark because the fragment never leaves the browser.
- WAF bypass — `blocked` at L3 until the payload slips the grammar, then amber
  continues past it.
- CSRF — the student's amber never crosses the boundary at all; the victim's
  cookie rides along by itself.

If every layer of your lab is `present`, you have not thought about the
signature yet.

---

## 6. The helper library

Available as globals inside a lab file (also exported on `STRATA.helpers`).
Use them: they carry the house look, and they are what the sandbox ships.

```js
esc(s)                       // HTML-escape. Every dynamic byte, every time.
taint(s, cls = "tn")         // wrap in the amber span (escapes for you)
taintMarkup(frag)            // tokenize a payload for display, amber-marked
clip(s, n)                   // "long string…"
plural(n, one, many)         // "1 row" / "3 rows"

codeLines([{ t, hot }, …])   // source listing; hot:true = the vulnerable line
note(kind, callout, html)    // kind: "" | "warn"; callout: "Layer 4 · label"
explain(question, html)      // beginner explainer block
kv([[key, value, cls], …])   // comparison rows; cls ∈ "" | "bad" | "hot" | "good"

field(label, value, btn, ph) // ONE live input + submit button (see §4 rule 4)
siteFrame({ path, q, editFrag, search, body })   // the simulated browser window
productCard(p)               // a storefront card for the demo shop

safeRender(frag)             // show how a payload WOULD render — allowlist only
buildDomTree(html, hostSel)  // parse into a DETACHED document and draw the tree
intendedVsParsed(pre, payload, suf)   // the "what you meant vs what parsed" split
vectorList(vectors, hasMarkup)        // list scanned vectors
alertSim(host, payload)      // the simulated alert dialog — a drawing, not a call

scanVectors(html, mode)      // which vectors fire, and how ("parser"|"innerHTML")
wafScan(payload)             // the built-in blocklist edge
md5(s)                       // real RFC-1321
```

Layer content house style: L1/L2/L4 are `codeLines([...])` with a
`note("warn", "Layer N · label", "…")` underneath; L5/L6 explain the promotion;
tours use `explain("Question?", "…")`.

---

## 7. Objectives, hints and presets

**Objectives** mirror the real attack: recon → first effect → impact. Two to
four steps. `test(a)` runs against the live analysis on every keystroke, so a
step completes whichever way the input arrived. Write `test` against the
*meaning* (`a.union && a.leaked.length`), never against the payload string.

**Hints escalate over three rungs:** point at a layer → describe the technique
→ reveal the payload. One sentence each, in the lab's voice. A solve earned
from the reveal is labelled "Solved · hints" — that is deliberate, so make the
earlier rungs genuinely useful.

**Presets are guided examples, not answers.** Mark the preset that completes
the final objective `spoiler: true`; it stays hidden until the lab is solved.
Failure-state presets ("Blocked · script") are teaching moments — keep those
visible. At least one preset must stay visible; the validator enforces it.
Convention: `defaultQ` equals the first non-spoiler preset.

---

## 8. Defender editions

Add `defense` and the lab also appears on the home page's **Defender** tab.
The student deploys a candidate patch and the engine runs the full attack
battery against it, live. Deployed patches are **actually applied**: benign
traffic keeps flowing, attacks die at a layer with the reason on screen, and
anything that still burns through reads "✗ bypassed".

```js
defense: {
  blurb: "HTML for the defender card — why patching here matters.",
  vectors: [                       // ≥2, and each MUST breach the unpatched lab
    { q:"' UNION SELECT id,email,password,NULL,NULL FROM users-- ", label:"UNION exfil" },
    { q:"' OR 1=1-- ",  label:"tautology" }
  ],
  options: [                       // ≥2 candidate patches
    { id:"parameterize", label:"Parameterized query",
      code:'db.execute("… WHERE name LIKE ?", (f"%{q}%",))',
      apply(q){ return /['"]/.test(String(q))
        ? { blocked:true, at:4, why:"The value is bound, not concatenated — the parser never sees your quote as syntax." }
        : { blocked:false, at:null, why:"An ordinary search — bound and served exactly as before." }; } },

    { id:"hide-errors", label:"Hide SQL errors from users",
      code:"except DBError: return generic_500()",
      apply(q){ return /'/.test(String(q))
        ? { blocked:false, at:5, why:"Quieter, not safer. The UNION still executes and its rows still render." }
        : { blocked:false, at:null, why:"An ordinary search — served, with a quieter error page." }; } }
  ]
}
```

Rules the validator enforces — they *are* the pedagogy:

- **Vectors are real attacks.** Each must make `solved(analyze(v.q))` true
  against the unpatched lab. A vector that does not currently work is a lie.
- **`apply(q)` answers per input**, returning `{ blocked, at, why }`. `at` is
  the layer index where it dies (required when `blocked`), and the panel shows
  "✓ dies at L4".
- **At least one option must block every vector** (the lab is fixable) **and
  at least one must fail** (the wrong fixes are the lesson).
- **Be honest about benign traffic.** A real fix is invisible to honest input:
  `apply("lens")` under a parameterized query must return `blocked:false` with
  a *why* that says the search was served normally. A patch that "blocks"
  everything is not a patch, and the student will see it.
- **Re-run your own engine inside `apply`** — escape, strip, resolve,
  classify — rather than returning hardcoded booleans. That is what keeps the
  bypass verdict truthful when the student invents a payload you never listed.
- Optionally give an option `respond(analysis, q) → HTML` to render a
  lab-specific patched response instead of the generic panel.

Pick the wrong fixes from life: hide the errors, add `LIMIT 1`, wrap it in
quotes, extend the blocklist, rotate to a longer secret, rate-limit it, hide
it in the UI. Each one should fail *for the reason it fails in production*.

Worked reference: `labs/xss-waf-plus.lab.js`.

---

## 9. Wire / intercept

With a `wire`, the student can toggle **Intercept**, pause the lab's virtual
request and edit the raw HTTP bytes Burp-style before sending. The shell
builds the request, URL-encodes the payload, and re-derives every layer from
the edited bytes — your `analyze()` receives the decoded parameter exactly as
an origin would. STRATA makes no network calls; the request is virtual.

| `type` | use for | needs |
|---|---|---|
| `query` | `?q=…` | `path`, `param` |
| `path` | the path itself is the input | `path` |
| `json` | a JSON body field | `path`, `param` |
| `form` | a form-encoded field | `path`, `param` |
| `login` | credential pairs | `path` |
| `fragment` | DOM labs — the pill explains there is nothing to intercept, which *is* the lesson | — |
| `offline` | no live request at all (cracking, log replay) | — |

Anything else is allowed if you also supply `build(q) → raw` and
`parse(raw) → {q} | {error}` (see `LAB_JWT`), at the cost of intercept in the
sandbox.

---

## 10. The STRATA voice

The interface reads like a drafting annotation: terse, concrete, second
person, lowercase prose under short uppercase labels. Match it.

- **Second person, present tense, specific.**
  Yes: *"Your `'` closed the literal the developer opened."*
  No: *"In this section, we will explore how attackers can leverage…"*
- **One idea per note**, pointing at the layer the student is on. Notes are
  titled `Layer 4 · short label`.
- **Name the fix, in one line, next to the flaw.** `db.execute(sql, (q,))`,
  `.textContent`, one generic login error. A lab that cannot state its patch
  is not finished.
- **No exclamation marks, no "simply", no "just", no cheerleading.** The
  material is interesting; do not sell it.
- **Let the instrument narrate.** If the taint signature already shows the
  network planes going dark, do not write a paragraph explaining that the
  network planes are dark. Say the thing the picture cannot: *why*.
- **Be honest about limits.** When a fix is real but has a footnote, write the
  footnote: *"(DNS rebinding is this fix's real-world caveat — pin the IP you
  checked.)"* The built-ins do this everywhere, and it is why they are
  trusted.
- **Difficulty calibration.** *Beginner* = a tour. *Apprentice* = the classic
  payload, one technique. *Practitioner* = bypass something, multiple steps.

---

## 11. Verify before you hand it over

Do not present a lab you have not run. From the repo root:

```sh
node scripts/strata.mjs validate labs/my-lab.lab.js   # the REAL page validator
node tests/labs.test.mjs                              # every disk lab + catalog hashes
node scripts/strata.mjs catalog                       # only if publishing on a shelf
```

`validate` checks the shape **and smoke-runs the whole engine** against
`defaultQ`, every preset and a hostile battery. Fix every error; there are no
acceptable warnings.

Then play it, in `strata.html`:

```sh
python3 -m http.server 8641     # then open http://127.0.0.1:8641/strata.html
```

Drag the file onto the catalog (or *Your labs → Load a lab file*), and check:

1. **Every objective completes — and only when it should.** Type each step's
   payload by hand; watch the rail tick over.
2. **Free-typed neighbours work.** Change the case, add a space, re-encode it,
   swap the tag. Does the engine still tell the truth?
3. **The box behaves.** Type a space. Clear it and type again. Your bytes must
   appear exactly as typed (§4 rule 4).
4. **The cross-section tells the story.** Press `⌥space` and look at it with
   the prose out of frame.
5. **Intercept works**, or is deliberately `fragment`/`offline`.
6. **The defender battery is honest**, if you shipped one: deploy the real fix
   and search for something benign — it must be served normally.

Iterating is cheap: dropping a file whose `id` matches a lab you already
loaded **replaces** it in place.

---

## 12. Failure modes to check yourself for

These are the ways AI-authored labs actually go wrong. Re-read your file
looking for each one.

- **A lookup table wearing a parser's clothes.** `analyze` recognises the
  three presets and returns `solved:false` for everything else.
- **Seven layers of prose with no engine** — beautiful renders, an `analyze`
  that returns `{ q }`.
- **Missing `esc()`** on a dynamic byte. Every one, every time.
- **Executing instead of simulating.** If your lab can pop a real alert, it
  is broken, not realistic.
- **The answer as a visible preset.** Mark it `spoiler: true`.
- **`test` matching the payload string** instead of the analysis — the student
  who finds a *different* working payload is told they failed.
- **States outside the vocabulary**, or a signature that is `present` × 7.
- **The fix never named**, or named vaguely ("use proper validation").
- **Defender options that all work**, or vectors that do not actually breach.
- **Feeding a trimmed/defaulted value back into the live input** (§4 rule 4).
- **Inventing detail the report did not contain** and presenting it as fact.

---

## 13. Hand-over checklist

- [ ] `labs/<id>.lab.js`, filename stem == `id`, registers exactly once
- [ ] `node scripts/strata.mjs validate` passes with zero errors
- [ ] `node tests/labs.test.mjs` passes (catalog re-hashed if publishing)
- [ ] `analyze()` is pure and genuinely parses free-typed input
- [ ] The live box echoes exactly what was typed
- [ ] Every objective completes, and only when it should
- [ ] The answer preset is `spoiler:true`; no note hands it over
- [ ] `esc()` on every dynamic byte; nothing executes
- [ ] The taint signature tells the story in cross-section
- [ ] The one-line fix is named on the layer that carries the flaw
- [ ] Intercept works, or is deliberately `fragment` / `offline`
- [ ] Defender edition (if any): vectors breach, ≥1 patch holds, ≥1 fails,
      benign traffic flows through every real fix
- [ ] Trace, verdict and notes read in the STRATA voice
- [ ] You state, in your hand-over, what you chose and what you inferred
