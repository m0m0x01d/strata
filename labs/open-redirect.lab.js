/* ════════════════════════════════════════════════════════════════════
   STRATA EXAMPLE LAB — Unvalidated open redirect (CWE-601).
   A complete, self-contained lab in the STRATA format: real engine,
   objectives with hint ladders, intercept support, catalog card.
   Load it by dropping this file onto the STRATA catalog page.
   Written as a reference for authors (humans and AIs) — see
   docs/AUTHORING.md.
   ════════════════════════════════════════════════════════════════════ */

STRATA.registerLab({
  id: "open-redirect",
  code: "A01",
  cat: "Broken Access Control",
  title: "Unvalidated redirect after login",
  difficulty: "Apprentice",

  goal: "The login page sends users wherever <b>returnTo</b> says. Land a victim on a site you control.",

  notes:`The login page redirects wherever <code>returnTo</code> says, and the "local" check is <code>startswith("/")</code> — one character short, because <code>//host</code> is a protocol-relative URL. The phish writes itself: the victim sees your domain in the link, then lands on a pixel-perfect clone. And <code>location.href</code> accepts schemes — <code>javascript:</code> turns the redirect into XSS. <b>The fix:</b> parse the URL and require the host to be empty (<code>urlsplit(returnTo).netloc == ""</code>).`,

  layers: [
    { code:"L0", title:"Surface",  meta:"the login page" },
    { code:"L1", title:"Client",   meta:"where you land" },
    { code:"L2", title:"Request",  meta:"GET /login" },
    { code:"L3", title:"Edge",     meta:"proxy" },
    { code:"L4", title:"Server",   meta:"app.py" },
    { code:"L5", title:"Logic",    meta:"the redirect check" },
    { code:"L6", title:"Navigate", meta:"the browser obeys" }
  ],
  boundary: 4,
  boundaryLabel: "Redirect check",
  boundaryTone: "breach",

  wire: { type:"query", path:"/login", param:"returnTo" },
  consoleLabel: "returnTo values",
  defaultQ: "/account",

  presets: [
    { q:"/account",                          label:"Honest return path" },
    { q:"/\\evil.example",                   label:"Backslash trick" },
    { q:"//evil.example",                    label:"Protocol-relative", spoiler:true },
    { q:"https://evil.example/phish",        label:"Absolute URL",      spoiler:true },
    { q:"javascript:alert(1)",               label:"Scheme swap",       spoiler:true }
  ],

  /* ── engine ── classifies where the browser would actually go.
     Real parsing, free-typed: any scheme, any spelling. */
  analyze(q){
    const typed = String(q);      // the live box must echo your bytes, not the trimmed ones
    const val = typed.trim();
    const js = /^\s*javascript:/i.test(val);
    const hasScheme = /^[a-z][a-z0-9+.-]*:/i.test(val);
    const protoRel = val.startsWith("//") || /^[\\/]{2}/.test(val);   // // and \/\ — browsers treat \ as /
    const offsite = !js && (protoRel || hasScheme);
    const safe = !js && !offsite && val.startsWith("/");
    return { typed, val, js, offsite, safe, hasScheme, solved: offsite || js };
  },
  solved: a => a.solved,
  layerState(i, a){
    return ["present","present","present","present","present",
            a.solved ? "boundary" : "present", a.solved ? "promoted" : "present"][i];
  },

  render: {
    0: a => {
      let panel;
      if (a.js)
        panel = `<div class="ownerbad">⚠ The redirect target was a <b>javascript:</b> URI — location.href executes it, not navigates to it.</div>`;
      else if (a.offsite)
        panel = `<div class="ownerbad">⚠ The browser is now on <b>evil.example</b>. Same login pixel-for-pixel — the victim never noticed the hop. Password, please.</div>`;
      else if (a.safe)
        panel = `<div class="ownerok">✓ Signed in — returning you to <b>${esc(a.val)}</b> on this site.</div>`;
      else
        panel = `<div class="loginerr">“${esc(a.val)}” isn’t a path. Try something starting with <code>/</code>.</div>`;
      const body = `<h1 class="s-h">Sign in to Aperture</h1>
        <p class="s-sub">you’ll be returned to the page you came from</p>
        ${field("returnTo", a.typed, "Continue", "/account")}
        <div style="margin-top:12px">${panel}</div>`;
      return `<div class="applayer">${siteFrame({ path:"/login", search:false, body })}
        ${alertOnce(a.js, "shop.strata.lab", a.val)}</div>`;
    },
    1: a => explain("What the client does with the answer",
        "After a successful login the server replies <b>302 Found</b> with a <code>Location</code> header, and the browser follows it <em>automatically</em> — no prompt, no rendering of the redirect body. Whatever string sits in that header is where you land.")
      + `<pre class="src">${codeLines([
          { t:`<span class="cm">// the browser does this for you:</span>` },
          { t:`location.href = response.headers[<span class="str">'Location'</span>];`, hot:true }
        ])}</pre>`,
    2: a => `<pre class="src">${codeLines([
        { t:`<span class="kw">GET</span> /login?returnTo=${taint(encodeURIComponent(a.val))} <span class="kw">HTTP/1.1</span>`, hot:true },
        { t:`<span class="kw">Host:</span> shop.aperture.lab` }
      ])}</pre>${note("", "Layer 2 · the target travels with the link",
        "Phishing links like <code>https://shop.aperture.lab/login?returnTo=//evil.example</code> look exactly like the real site — the domain in the address bar IS yours until the hop happens.")}`,
    3: a => note("", "Layer 3 · a perfectly legitimate request",
      "A GET to your login page with a query parameter. No payload signature, nothing to block — this class of bug is invisible to filters because the request isn’t the attack; the <em>response</em> is."),
    4: a => `<pre class="src">${codeLines([
        { t:`<span class="kw">@app.route</span>(<span class="str">"/login"</span>)` },
        { t:`<span class="kw">def</span> login():` },
        { t:`    returnTo = request.args.get(<span class="str">"returnTo"</span>, <span class="str">"/account"</span>)`, hot:true },
        { t:`    <span class="kw">if</span> returnTo.startswith(<span class="str">"/"</span>):      <span class="cm"># ✗ "//evil…" starts with "/" too</span>`, hot:true },
        { t:`        <span class="kw">return</span> redirect(returnTo)` },
        { t:`    <span class="cm"># fix: allowlist the host — urlsplit(returnTo).netloc must be empty</span>` }
      ])}</pre>${note("warn", "Layer 4 · one character short",
        "The developer tried to keep redirects local — “starts with a slash” — but <code>//host</code> is a <b>protocol-relative URL</b>: it starts with a slash and still leaves the site.")}`,
    5: a => explain("What “local” should have meant",
        "A safe redirect target has <b>no scheme and no authority</b> — just a path. The check that says so is one line: parse the URL and require <code>scheme == \"\" and netloc == \"\"</code>. String-prefix checks (“starts with /”, “contains our domain”) all fail to the same family of bypasses.")
      + kv([
          ["Your value", `<span class="mono">${esc(clip(a.val, 40))}</span>`, a.solved ? "leak" : ""],
          ["Starts with “/”?", a.val.startsWith("/") ? "yes — check passes" : "no", a.offsite && a.val.startsWith("/") ? "bad" : ""],
          ["Actually local?", a.safe ? "yes" : "<b style='color:var(--breach)'>no</b>", a.solved ? "bad" : ""]
        ]),
    6: a => {
      if (a.js) return note("warn", "Layer 6 · scheme swap executed",
        "<code>location.href = \"javascript:…\"</code> runs the URI instead of navigating — the redirect became XSS in one move. The fix (no netloc) kills this too.");
      if (a.offsite) return note("warn", "Layer 6 · the victim is gone",
        "The browser followed the Location header to a server you control. Clone the login page and the phish is indistinguishable from the real thing — the victim saw your domain in the link the whole time.");
      if (a.safe) return note("", "Layer 6 · home again", `Back on <b>${esc(a.val)}</b> — same origin, nothing lost. This is the baseline you're breaking.`);
      return note("", "Layer 6 · nowhere to go", "That value isn’t a path the browser can follow.");
    }
  },

  trace(a){
    const S = i => this.layerState(i, a);
    return [
      { h:"L0 · Surface",  state:S(0), b:`returnTo = <em>${esc(clip(a.val, 28))}</em>.` },
      { h:"L1 · Client",   state:S(1), b:"Browser follows the Location header." },
      { h:"L2 · Request",  state:S(2), b:"The target rides in the link." },
      { h:"L3 · Edge",     state:S(3), b:"An ordinary GET." },
      { h:"L4 · Server",   state:S(4), b:"Startswith(\"/\") — one character short." },
      { h:"L5 · Logic",    state:S(5), b:a.solved ? "<strong>Local check fooled.</strong>" : "Target stayed local." },
      { h:"L6 · Navigate", state:S(6), b:a.js ? "<strong>javascript: executed.</strong>" : a.offsite ? "<strong>Off-site.</strong>" : a.safe ? "Same origin." : "No navigation." }
    ];
  },

  verdict(a){
    return [
      ["Starts with “/”", a.val.startsWith("/") ? "yes" : "no", ""],
      ["Actually local", a.safe ? "yes" : "no", a.solved ? "bad" : ""],
      ["Lands on", a.js ? "javascript:" : a.offsite ? (hostOf(a.val) || "off-site") : a.safe ? "this site" : "—", a.solved ? "bad" : ""],
      ["Lab", a.solved ? "Solved" : "Not solved", a.solved ? "good" : ""]
    ];
  },

  challenge: { steps: [
    { id:"honest", label:"Complete an honest redirect", test:a => a.safe,
      hints:["A plain path starting with a single / is what the developer intended."],
      reveal:"/account" },
    { id:"offsite", label:"Send the victim off-site", test:a => a.offsite,
      hints:["The check is startswith(\"/\") — what else starts with a slash?",
             "Two slashes make a protocol-relative URL: the browser reads //host as https://host."],
      reveal:"//evil.example" },
    { id:"scheme", label:"Turn the redirect into XSS", test:a => a.js,
      hints:["location.href doesn’t only navigate — one scheme executes.",
             "javascript:alert(1) as the whole value."],
      reveal:"javascript:alert(1)" }
  ]},

  card: {
    sig: ["a","a","a","a","x","x","a"],
    blurb:"The login page redirects wherever <code>returnTo</code> says, and the “local” check is one character too short. Phish with your own domain; then swap the scheme."
  }
});
