/* ════════════════════════════════════════════════════════════════════
   STRATA LAB TEMPLATE — copy me, fill me in, drop me on the catalog.
   The full contract is documented in docs/AUTHORING.md. Everything the
   validator checks is marked REQUIRED below. Delete unused fields.
   ════════════════════════════════════════════════════════════════════ */

STRATA.registerLab({

  /* ── identity ── REQUIRED ── */
  id: "my-lab",                       // unique lowercase slug
  code: "A01",                        // badge shown on the card and top bar
  cat: "Broken Access Control",       // catalog group (reuse an existing one when it fits)
  title: "One sentence: what is broken, and where",
  difficulty: "Apprentice",           // REQUIRED enum: Beginner | Apprentice | Practitioner
  goal: "Impacting HTML — what the student must achieve.",

  /* ── structure ── REQUIRED ── */
  layers: [                           // 7 entries is the house style (4–9 allowed)
    { code:"L0", title:"Surface", meta:"the page" },
    { code:"L1", title:"Client",  meta:"browser code" },
    { code:"L2", title:"Request", meta:"HTTP out" },
    { code:"L3", title:"Edge",    meta:"proxy / WAF" },
    { code:"L4", title:"Server",  meta:"app.py" },
    { code:"L5", title:"Logic",   meta:"the weak spot" },   // name this layer after the bug
    { code:"L6", title:"Data",    meta:"the outcome" }
  ],
  boundary: 4,                        // membrane floats between layers[boundary] and the next
  boundaryLabel: "Trust boundary",
  // boundaryTone: "safe",            // only for tour-style labs

  /* ── interaction ── REQUIRED ── */
  defaultQ: "benign opening state",
  presets: [                          // guided examples; the ANSWER gets spoiler:true
    { q:"benign opening state", label:"Normal" },
    { q:"the winning payload",  label:"The answer", spoiler:true }
  ],
  consoleLabel: "Things to try",

  /* ── the engine ── REQUIRED ────────────────────────────────────────
     analyze must be PURE and must genuinely parse the input — a lookup
     table that only accepts the preset strings is not a lab. */
  analyze(q){
    const a = { q: String(q) };
    // a.parsed = …; a.impact = …; a.solved = …;
    return a;
  },

  /* taint signature: which layers hold your input, and in what state.
     Vocabulary: present | promoted | sink | boundary | blocked | absent | clean */
  layerState(i, a){
    return ["present","present","present","present","present",
            a.solved ? "boundary" : "present", a.solved ? "promoted" : "present"][i];
  },

  /* one renderer per layer — REQUIRED for every layer index */
  render: {
    0: a => `<div class="applayer">${siteFrame({ path:"/", search:false,
        body:`<h1 class="s-h">The app</h1>${field("Input", a.q, "Go", "…")}` })}</div>`,
    1: a => `<pre class="src">${codeLines([
        { t:`<span class="cm">// the client code that matters</span>` }
      ])}</pre>${note("", "Layer 1 · label", "One idea, in the STRATA voice.")}`,
    2: a => `<pre class="src">${codeLines([
        { t:`<span class="kw">GET</span> /?x=${taint(esc(a.q))} <span class="kw">HTTP/1.1</span>`, hot:true }
      ])}</pre>`,
    3: a => note("", "Layer 3 · label", "What the edge sees — or doesn't."),
    4: a => `<pre class="src">${codeLines([
        { t:`<span class="cm"># the vulnerable line, with the fix named next to it</span>` }
      ])}</pre>`,
    5: a => explain("The question this layer answers?", "Two or three sentences."),
    6: a => note("", "Layer 6 · label", "The outcome, and the one-line fix.")
  },

  /* REQUIRED — one entry per layer, states from the vocabulary */
  trace(a){
    const S = i => this.layerState(i, a);
    return [
      { h:"L0 · Surface", state:S(0), b:`You sent <em>${esc(clip(a.q, 24))}</em>.` },
      { h:"L1 · Client",  state:S(1), b:"…" },
      { h:"L2 · Request", state:S(2), b:"…" },
      { h:"L3 · Edge",    state:S(3), b:"…" },
      { h:"L4 · Server",  state:S(4), b:"…" },
      { h:"L5 · Logic",   state:S(5), b:"…" },
      { h:"L6 · Data",    state:S(6), b:"…" }
    ];
  },

  /* REQUIRED — rows of [key, value, class] where class ∈ "", "bad", "hot", "good" */
  verdict(a){
    return [
      ["Status", a.solved ? "exploited" : "normal", a.solved ? "bad" : ""],
      ["Lab", a.solved ? "Solved" : "Not solved", a.solved ? "good" : ""]
    ];
  },

  /* REQUIRED unless tour:true */
  solved: a => !!a.solved,

  /* ── challenge — strongly recommended ──
     Steps mirror the real attack: recon → first effect → impact.
     hints[] and reveal are REQUIRED per step; ids must be unique. */
  challenge: { steps: [
    { id:"step1", label:"First observable effect",
      test: a => !!a.solved,                       // refine per step
      hints: ["A nudge pointing at a specific layer.",
              "The technique, one sentence."],
      reveal: "the winning payload" }
  ]},

  /* ── optional behavior hooks ──
     onFire(a)  — called when a run FIRES (Enter/preset/intercept), never
                  per keystroke; use for attempt logs. analyze() stays pure.
     domMode    — "parser" | "innerHTML": how <script> nodes are badged in
                  buildDomTree. Set "innerHTML" for DOM-sink labs. */

  /* ── intercept — optional ──
     type: query | path | json | form | login | fragment | offline
     (or a custom type with your own build(q) and parse(raw)) */
  wire: { type:"query", path:"/", param:"q" },

  /* ── explanation ── optional but expected ──
     HTML string for the bottom-right "Explanation" popup: the bug in plain
     words, two to five sentences, ending with the one-line fix. */
  notes:`The bug: <b>what happens and where</b>. <b>The fix:</b> <code>one line</code>.`,

  /* ── catalog card ── optional (built-in labs keep theirs in the file)
     sig: one mark per layer — a=your input active · x=weak spot ·
          d=absent · s=safe */
  card: { sig:["a","a","a","a","x","x","a"],
          blurb:"Two sentences for the catalog card. <code>code</code> allowed." }
});
