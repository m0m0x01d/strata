/* ════════════════════════════════════════════════════════════════════
   STRATA COMMUNITY LAB — Reflected XSS behind a tag blocklist, v2.
   The "harder XSS" variant: the obvious tags are all gone. Written as
   community-format reference: sandbox-safe (no domMode, string helpers
   only), with a defender edition. See docs/AUTHORING.md.
   ════════════════════════════════════════════════════════════════════ */

const HOSTX = "hard.strata.lab";

STRATA.registerLab({
  id: "xss-waf-plus",
  code: "X-01",
  cat: "Injection",
  title: "Reflected XSS when every obvious tag is blocked",
  difficulty: "Practitioner",

  goal: "Fire <b>alert()</b>. The WAF eats <code>&lt;script&gt;</code>, <code>&lt;img&gt;</code>, <code>&lt;svg&gt;</code> and <code>&lt;iframe&gt;</code> before they reach the server — the tag list is not the language.",

  notes:`This blocklist bans the four most famous XSS tags and feels airtight. It isn't: the HTML grammar has <b>110+ elements</b>, and <code>&lt;details open ontoggle=…&gt;</code> auto-fires without a single banned byte. Blocklists enumerate what you know; parsers accept what exists. <b>The fix:</b> escape the reflection at the origin — then the filter's job stops mattering.`,

  layers: [
    { code:"L0", title:"Surface",  meta:"search page" },
    { code:"L1", title:"Client",   meta:"browser" },
    { code:"L2", title:"Request",  meta:"GET /search" },
    { code:"L3", title:"Edge",     meta:"WAF · tag blocklist" },
    { code:"L4", title:"Server",   meta:"app.py" },
    { code:"L5", title:"Parser",   meta:"HTML tokenizer" },
    { code:"L6", title:"Runtime",  meta:"the page's JS" }
  ],
  boundary: 5,
  boundaryLabel: "HTML parser",
  boundaryTone: "breach",

  wire: { type:"query", path:"/search", param:"q" },
  consoleLabel: "Search terms",
  defaultQ: "tripod",

  presets: [
    { q:"tripod",                                   label:"Benign search" },
    { q:"<script>alert(1)<\/script>",               label:"Blocked · script" },
    { q:"<img src=x onerror=alert(1)>",             label:"Blocked · img" },
    { q:"<details open ontoggle=alert(1)>",         label:"The tag they forgot", spoiler:true }
  ],

  challenge:{ steps:[
    { id:"blocked", label:"Watch the blocklist say no", test:a => !!a.waf.blocked,
      hints:["Send the classic payloads first — seeing the wall is step one.",
             "<script>alert(1)<\/script>"],
      reveal:"<script>alert(1)<\/script>" },
    { id:"bypass", label:"Fire alert() with zero banned tags", test:a => !!a.fires,
      hints:["The blocklist bans TAGS. The tokenizer accepts 110+ elements and never read the list.",
             "It auto-fires only as <details> with the open attribute.",
             "<details open ontoggle=alert(1)>"],
      reveal:"<details open ontoggle=alert(1)>" }
  ]},

  analyze(q){
    const blocked = /<\s*(script|img|svg|iframe|object|embed)\b/i.test(q);
    const waf = { blocked, rule: blocked ? "tag-blocklist" : null };
    const vectors = scanVectors(q, "parser");
    const fires = !blocked && vectors.some(v => v.fires);
    const hasMarkup = /<[a-z!/]/i.test(q);
    return { q, waf, vectors, fires, hasMarkup, solved:fires };
  },
  solved: a => a.fires,
  layerState(i, a){
    if (a.waf.blocked) return ["present","present","present","blocked","absent","absent","absent"][i];
    return ["present","present","present","present","present", a.hasMarkup ? "promoted" : "present", a.fires ? "sink" : "present"][i];
  },
  render:{
    0: a => {
      const path = `/search?q=${clip(encodeURIComponent(a.q), 30)}`;
      let body;
      if (a.waf.blocked){
        body = `<div class="blockpage"><div class="hd">Request blocked</div>
          <div class="msg">Rule TAG-BL: the element <b>${esc((/<\s*([a-z0-9]+)/i.exec(a.q) || [])[1] || "?")}</b> is not allowed here.</div>
          <div class="ref">waf-plus · 403</div></div>`;
      } else {
        body = `<h1 class="s-h">0 search results for ‘<span class="s-reflect">${safeRender(a.q)}</span>’</h1>
          <p class="s-empty">Nothing matched.</p>`;
      }
      return `<div class="applayer">${siteFrame({ path, q:a.q, body })}${alertOnce(a.solved, HOSTX, a.q)}</div>`;
    },
    1: a => explain("What the browser did", "Sent the bytes, drew the response. If markup comes back unescaped, the tokenizer — not the attacker — turns it into elements."),
    2: a => `<pre class="src">${codeLines([
        {t:`<span class="kw">GET</span> /search?q=${taint(encodeURIComponent(a.q))} <span class="kw">HTTP/1.1</span>`, hot:true},
        {t:`<span class="kw">Host:</span> ${HOSTX}`}
      ])}</pre>`,
    3: a => a.waf.blocked
      ? note("warn","Layer 3 · the blocklist answered","The four famous tags die here. Feel safe? The tokenizer two layers down accepts 110+ elements and never read this list.")
      : note("","Layer 3 · nothing matched","No banned byte sequence — forwarded. The filter checks spelling; the parser reads grammar."),
    4: a => `<pre class="src">${codeLines([
        {t:`<span class="kw">return</span> render(<span class="str">"0 results for {}"</span>, q)`, hot:true},
        {t:`<span class="cm"># q goes into the HTML unescaped</span>`}
      ])}</pre>${note("warn","Layer 4 · unescaped reflection","The origin never escapes q. Every patch that lives at the edge is renting; this line is owning.")}`,
    5: a => a.fires
      ? explain("Promotion", "The tokenizer built an element from your bytes and read its attribute as an event handler. Data became structure became behavior.")
      : explain("Text, for now", "Without an auto-firing vector, your bytes render as text. The promotion is one forgotten tag away."),
    6: a => a.fires
      ? note("warn","Layer 6 · alert() ran", "Same-origin script context, DOM access, keys, credentials — the dialog is just the proof of purchase.")
      : note("","Layer 6 · quiet", "Fire a vector to hear it speak.")
  },
  trace(a){ const S = i => this.layerState(i, a);
    return [
      {h:"L0 · Surface", state:S(0), b:`You search <em>${esc(clip(a.q, 30))}</em>.`},
      {h:"L1 · Client",  state:S(1), b:`Bytes on their way.`},
      {h:"L2 · Request", state:S(2), b:`Ordinary query string.`},
      {h:"L3 · Edge",    state:S(3), b:a.waf.blocked ? `<strong>Blocked — banned tag.</strong>` : `No banned sequence.`},
      {h:"L4 · Server",  state:S(4), b:a.waf.blocked ? `Never reached.` : `Reflected unescaped.`},
      {h:"L5 · Parser",  state:S(5), b:a.fires ? `<strong>Your bytes became an element + handler.</strong>` : (a.hasMarkup ? `Markup built; no auto-fire.` : `Text.`)},
      {h:"L6 · Runtime", state:S(6), b:a.fires ? `<strong>alert() executed.</strong>` : `Quiet.`}
    ];
  },
  verdict(a){
    return [
      ["WAF", a.waf.blocked ? "blocked (tag list)" : "passed", a.waf.blocked ? "" : "bad"],
      ["Fired", a.fires ? "yes" : "no", a.fires ? "bad" : ""],
      ["Lab", a.solved ? "Solved" : "Not solved", a.solved ? "good" : ""]
    ];
  },

  defense:{
    blurb:"Escape the reflection, extend the tag list, or protect the cookie — the engine fires both bypasses at every patch.",
    vectors:[
      {q:"<details open ontoggle=alert(1)>", label:"details ontoggle"},
      {q:"<body onload=alert(1)>",           label:"body onload"}
    ],
    options:[
      { id:"origin-escape", label:"Escape the reflection at the origin", code:"return render('search.html', q=escape(q))",
        apply(q){ let fires = false; try { fires = scanVectors(String(q), "parser").some(v => v.fires); } catch(_){}
          return fires
            ? { blocked:true, at:4, why:"Whatever slips the edge now arrives at the tokenizer pre-neutralized — &lt;details&gt; is visible text. Both vectors die at the same line, and the WAF becomes optional." }
            : { blocked:false, at:null, why:"Served normally — text and harmless markup render exactly as before." }; } },
      { id:"add-details", label:"Add <details> to the blocklist", code:"deny <script|img|svg|iframe|object|embed|details",
        apply(q){ const s = String(q);
          if (/^<\s*details\b/i.test(s)) return { blocked:true, at:3, why:"details dies — and <body onload> never needed it. The list grew by one; the grammar didn't shrink." };
          if (/^<\s*body\b/i.test(s)) return { blocked:false, at:5, why:"body onload was never on any list. Your bytes become an element + handler two layers past the filter." };
          return { blocked:false, at:null, why:"No banned tag in it — served normally." }; } },
      { id:"httponly", label:"Set the session cookie HttpOnly", code:"Set-Cookie: session=…; HttpOnly; Secure",
        apply(q){ let fires = false; try { fires = scanVectors(String(q), "parser").some(v => v.fires); } catch(_){}
          if (fires) return { blocked:false, at:6, why:"HttpOnly hides the cookie from script — a real mitigation for cookie theft, not for injection. The alert fires, the DOM is theirs, keylogging works. Wrong layer, real flag." };
          return { blocked:false, at:null, why:"Nothing fires here — and when something does, HttpOnly still won't stop it." }; } },
      { id:"allowlist", label:"Reject input containing < entirely", code:'if (q.includes("<")) return 400',
        apply(q){ return q.includes("<")
          ? { blocked:true, at:4, why:"No markup can enter — both vectors die. Search is text-only on this endpoint, so the door can be this blunt." }
          : { blocked:false, at:null, why:"No markup in it — plain search, correctly served." }; } }
    ]
  }
});
