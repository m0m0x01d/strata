/* ════════════════════════════════════════════════════════════════════
   STRATA COMMUNITY LAB — Server-Side Template Injection (Jinja2 → RCE).
   Written by following docs/AI-LAB-BRIEF.md end to end, as the worked
   proof that the brief produces a valid lab. Sandbox-safe (string helpers
   only, no domMode), free-typed engine (a real arithmetic parser proves
   the template EVALUATED your bytes), full objective ladder + defender
   edition. See docs/AUTHORING.md for the contract.
   ════════════════════════════════════════════════════════════════════ */

const SSTI_HOST = "app.strata.lab";
const SSTI_SECRET = "s3cr3t-prod-key-9f2c4b71a0";

/* Recursive-descent arithmetic over + - * / and parens on non-negative
   integers. Returns a number, or null if the source is not a pure
   arithmetic expression. This is how the lab knows {{7*7}} was EVALUATED
   (→ 49) rather than echoed — without ever calling eval(). */
function sstiCalc(src){
  const toks = src.match(/\d+|[+\-*/()]/g);
  if (!toks || toks.join("") !== src.replace(/\s+/g, "")) return null;
  let i = 0, bad = false;
  const peek = () => toks[i], eat = () => toks[i++];
  function expr(){ let v = term(); while (peek() === "+" || peek() === "-"){ const o = eat(); const r = term(); v = o === "+" ? v + r : v - r; } return v; }
  function term(){ let v = fac(); while (peek() === "*" || peek() === "/"){ const o = eat(); const r = fac(); v = o === "*" ? v * r : (r === 0 ? (bad = true, 0) : Math.trunc(v / r)); } return v; }
  function fac(){ const t = eat(); if (t === "("){ const v = expr(); if (eat() !== ")") bad = true; return v; } if (/^\d+$/.test(t || "")) return +t; bad = true; return 0; }
  const v = expr();
  return (bad || i !== toks.length) ? null : v;
}

/* Faked stdout for the command an RCE gadget runs — simulated, never run. */
function sstiCmdOut(cmd){
  if (!cmd || /^\s*id\b/.test(cmd)) return "uid=33(www-data) gid=33(www-data) groups=33(www-data)";
  if (/whoami/.test(cmd)) return "www-data";
  if (/cat\s+\/etc\/passwd/.test(cmd)) return "root:x:0:0:root:/root:/bin/bash\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin";
  return "[stdout of `" + cmd + "`]";
}

/* PURE. Parses the FIRST {{ … }} expression the way Jinja would reach it. */
function sstiAnalyze(q){
  const typed = String(q);
  const m = typed.match(/\{\{([\s\S]*?)\}\}/);
  const injected = !!m;
  const expr = m ? m[1].trim() : "";

  const math = injected ? sstiCalc(expr) : null;
  const evaluated = math !== null && /[-+*/]/.test(expr);      // 7*7, not a bare 7
  const config = injected && /\bconfig\b/.test(expr);
  const gadget = injected && /(__globals__|__subclasses__|__mro__|__import__|__builtins__|popen|system|cycler|lipsum|os\.)/.test(expr);
  const cmdM = expr.match(/(?:popen|system)\(\s*['"]([^'"]*)['"]/);
  const cmd = cmdM ? cmdM[1] : null;
  const rce = gadget;

  let rendered;
  if (!injected) rendered = typed;                            // printed as literal text
  else if (rce) rendered = sstiCmdOut(cmd);
  else if (config) rendered = SSTI_SECRET;
  else if (math !== null) rendered = String(math);
  else rendered = "";                                         // Jinja Undefined → empty

  return { typed, injected, expr, evaluated, math, config, gadget, rce, cmd, rendered,
           solved: rce };
}

STRATA.registerLab({
  id: "ssti-jinja",
  code: "A03",
  cat: "Injection",
  title: "A display name rendered as a template — {{7*7}} becomes 49",
  difficulty: "Practitioner",
  severity: ["CRIT", "9.8"],

  goal: "The profile page greets you by name through <code>render_template_string</code>. Turn your name into <b>server-side code</b>: confirm evaluation, read the app secret, then run a shell command.",

  notes:`The server builds the greeting by <em>compiling a string it concatenated your name into</em> — <code>render_template_string("Welcome back, " + name)</code>. Jinja treats <code>{{ … }}</code> as an expression to evaluate, so your bytes stop being a name and become code: <code>{{7*7}}</code> proves it (renders <code>49</code>), <code>{{ config }}</code> reads the app config, and a sandbox-escape gadget reaches <code>os.popen</code> for full RCE. <b>The fix:</b> never compile user input — pass the name as data: <code>render_template("hi.html", name=name)</code>.`,

  layers: [
    { code:"L0", title:"Surface",  meta:"profile page" },
    { code:"L1", title:"Client",   meta:"the form" },
    { code:"L2", title:"Request",  meta:"POST /profile" },
    { code:"L3", title:"Edge",     meta:"no filter" },
    { code:"L4", title:"Server",   meta:"app.py" },
    { code:"L5", title:"Template", meta:"Jinja2 compiler" },
    { code:"L6", title:"Outcome",  meta:"what rendered" }
  ],
  boundary: 4,
  boundaryLabel: "Template compiler",
  boundaryTone: "breach",

  wire: { type:"form", path:"/profile", param:"name" },

  defaultQ: "Ada Lovelace",
  consoleLabel: "Display names to try",
  presets: [
    { q:"Ada Lovelace",           label:"A real name" },
    { q:"{{7*7}}",                label:"Probe · does it evaluate?" },
    { q:"{{ config.SECRET_KEY }}", label:"Read the app secret" },
    { q:"{{ cycler.__init__.__globals__.os.popen('id').read() }}", label:"Remote code execution", spoiler:true }
  ],

  analyze: sstiAnalyze,
  solved: a => a.solved,

  layerState(i, a){
    return [
      "present", "present", "present", "present", "present",
      (a.evaluated || a.config || a.rce) ? "promoted" : "present",
      a.rce ? "boundary" : ((a.config || a.evaluated) ? "promoted" : "present")
    ][i];
  },

  render: {
    0: a => {
      let panel;
      if (a.rce)
        panel = `<div class="ownerbad">⚠ Your "name" ran on the server. <code>${esc(a.cmd || "id")}</code> returned:</div>
          <pre class="leakfile">${esc(a.rendered)}</pre>`;
      else if (a.config)
        panel = `<div class="ownerbad">⚠ The greeting rendered the app's config. <b>SECRET_KEY</b> = <code>${esc(a.rendered)}</code> — session forgery from here.</div>`;
      else if (a.evaluated)
        panel = `<div class="ownerbad">⚠ Welcome back, <b>${esc(a.rendered)}</b>. The server did the arithmetic — your name was <em>evaluated</em>, not printed. That is the whole vulnerability.</div>`;
      else if (a.injected)
        panel = `<div class="s-empty">Welcome back, <b>${esc(a.rendered) || "&nbsp;"}</b>. The expression evaluated to nothing (Jinja Undefined) — try one that returns a value.</div>`;
      else
        panel = `<div class="ownerok">Welcome back, <b>${esc(a.rendered)}</b>. An ordinary name, printed as text.</div>`;
      const body = `<h1 class="s-h">Your profile</h1>
        <p class="s-sub">set the name the app greets you by</p>
        ${field("Display name", a.typed, "Save", "your name")}
        <div style="margin-top:12px">${panel}</div>`;
      return `<div class="applayer">${siteFrame({ path:"/profile", search:false, body })}</div>`;
    },
    1: a => `<pre class="src">${codeLines([
        { t:`<span class="cm">// the form just posts what you typed — no client-side anything</span>` },
        { t:`<span class="kw">const</span> name = form.name.value;` },
        { t:`fetch(<span class="str">'/profile'</span>, { method:<span class="str">'POST'</span>, body:<span class="str">'name='</span> + encodeURIComponent(name) });` }
      ])}</pre>${note("", "Layer 1 · client", "Nothing here inspects the name. The bug is entirely server-side.")}`,
    2: a => `<pre class="src">${codeLines([
        { t:`<span class="kw">POST</span> /profile <span class="kw">HTTP/1.1</span>` },
        { t:`Content-Type: application/x-www-form-urlencoded` },
        { t:`` },
        { t:`name=${taint(esc(a.typed))}`, hot:a.injected }
      ])}</pre>${note("", "Layer 2 · request", "Your name on the wire — amber. Whether it is data or code is decided two layers down.")}`,
    3: a => note(a.injected ? "warn" : "", "Layer 3 · edge",
        a.injected
          ? `No WAF, no allowlist. <code>{{</code> and <code>}}</code> are ordinary characters to the edge — it forwards them untouched. There is nothing here to bypass because there is nothing here.`
          : `The request passes straight through to the app.`),
    4: a => `<pre class="src">${codeLines([
        { t:`<span class="nd">@app.route</span>(<span class="str">'/profile'</span>, methods=[<span class="str">'POST'</span>])` },
        { t:`<span class="kw">def</span> profile():` },
        { t:`    name = request.form[<span class="str">'name'</span>]` },
        { t:`    <span class="cm"># builds a NEW template out of the name, then compiles it</span>` },
        { t:`    <span class="kw">return</span> render_template_string(<span class="str">"Welcome back, "</span> + name)`, hot:true }
      ])}</pre>${note("warn", "Layer 4 · the bug is this line", `<code>render_template_string</code> compiles its argument as a Jinja template. Concatenating <code>name</code> into it means the attacker writes template source. <b>The fix:</b> <code>render_template("hi.html", name=name)</code> — the name becomes a variable, never code.`)}`,
    5: a => {
      if (!a.injected) return note("", "Layer 5 · Jinja compiler", "No <code>{{ }}</code> in the input — the whole string is literal text. This is the safe baseline you are breaking.");
      if (a.rce) return note("warn", "Layer 5 · sandbox escaped",
        `The expression walks Python's object graph — <code>__globals__</code> reaches the <code>os</code> module, and <code>popen</code> runs a command. Jinja's sandbox never stood between your bytes and the interpreter, because <em>you wrote the template</em>.`);
      if (a.config) return note("warn", "Layer 5 · attribute access",
        `<code>config</code> is a name in the template's global scope. The compiler resolves it and hands back the live config object — including <code>SECRET_KEY</code>.`);
      if (a.evaluated) return note("warn", "Layer 5 · expression evaluated",
        `<code>${esc(a.expr)}</code> was compiled and run as a Python expression → <code style="color:var(--taint)">${esc(a.rendered)}</code>. Data would have been printed verbatim; this was executed.`);
      return note("", "Layer 5 · Undefined", `<code>${esc(a.expr)}</code> evaluated to nothing — a valid expression, but with no value to print.`);
    },
    6: a => {
      const rows = [
        ["Input treated as", a.injected ? "template source" : "literal text", a.injected ? "bad" : "good"],
        ["Evaluation", a.evaluated || a.config || a.rce ? "executed" : "printed", a.rce || a.config ? "bad" : (a.evaluated ? "hot" : "")],
        ["Impact", a.rce ? "remote code execution" : a.config ? "secret disclosure" : a.evaluated ? "code evaluation proven" : "none", a.rce ? "bad" : a.config ? "hot" : ""]
      ];
      const n = a.rce
        ? note("warn", "Layer 6 · full compromise", "From a display name to shell output. The template engine was a code interpreter the whole time; the only question was whether you fed it code.")
        : a.config
          ? note("warn", "Layer 6 · key disclosed", "With <code>SECRET_KEY</code> an attacker forges any session. This is already critical — and RCE is one gadget further.")
          : a.evaluated
            ? note("", "Layer 6 · proven", "Arithmetic you did not ask the app to do. Escalate: read <code>config</code>, then reach <code>os</code>.")
            : note("", "Layer 6 · as intended", "The name rendered as text, which is all a name should ever do.");
      return kv(rows) + n;
    }
  },

  trace(a){
    const st = i => this.layerState(i, a);
    return [
      { h:"L0 · Surface",  state:st(0, a), b:`<em>${a.typed.length}</em> ${plural(a.typed.length, "byte", "bytes")} captured as your name.` },
      { h:"L1 · Client",   state:st(1, a), b:`Posted unmodified.` },
      { h:"L2 · Request",  state:st(2, a), b:`<em>name=${esc(clip(a.typed, 20))}</em> on the wire.` },
      { h:"L3 · Edge",     state:st(3, a), b:a.injected ? `<code>{{…}}</code> forwarded untouched.` : `Forwarded.` },
      { h:"L4 · Server",   state:st(4, a), b:a.injected ? `Concatenated into a template. <strong>Trust boundary crossed.</strong>` : `Concatenated into a template.` },
      { h:"L5 · Template", state:st(5, a), b:a.rce ? `Sandbox escaped → <em>os.popen</em>.` : a.config ? `Resolved <em>config</em>.` : a.evaluated ? `Evaluated <em>${esc(clip(a.expr, 16))}</em>.` : `Printed as text.` },
      { h:"L6 · Outcome",  state:st(6, a), b:a.rce ? `<strong>Shell output returned.</strong>` : a.config ? `<strong>SECRET_KEY leaked.</strong>` : a.evaluated ? `Computed value shown.` : `Name rendered.` }
    ];
  },

  verdict(a){
    const sev = a.rce ? ["Critical", "bad"] : a.config ? ["High", "hot"] : a.evaluated ? ["Confirmed", "hot"] : ["No finding", "good"];
    return [
      ["Status", "200", ""],
      ["Rendered as", a.injected ? "code" : "text", a.injected ? "bad" : "good"],
      ["Impact", a.rce ? "RCE" : a.config ? "secret leak" : a.evaluated ? "eval proven" : "none", a.rce ? "bad" : a.config ? "hot" : ""],
      ["Severity", sev[0], sev[1]]
    ];
  },

  challenge: { steps: [
    { id:"confirm", label:"Confirm the name is evaluated",
      test: a => a.evaluated,
      hints: ["A real name renders as text. What if the value could do arithmetic the app never coded?",
              "Jinja evaluates whatever sits inside double curly braces.",
              "Send {{7*7}} and read the greeting — 49 means it ran."],
      reveal: "{{7*7}}" },
    { id:"secret", label:"Read the server's SECRET_KEY",
      test: a => a.config,
      hints: ["Arithmetic proves execution; now reach for something worth reading.",
              "The Flask config object is in scope inside every template.",
              "{{ config.SECRET_KEY }} prints it."],
      reveal: "{{ config.SECRET_KEY }}" },
    { id:"rce", label:"Run a shell command",
      test: a => a.rce,
      hints: ["Expressions can walk Python's object graph, not just read config.",
              "From any object you can reach __globals__, and from there the os module.",
              "{{ cycler.__init__.__globals__.os.popen('id').read() }}"],
      reveal: "{{ cycler.__init__.__globals__.os.popen('id').read() }}" }
  ]},

  card: { sig:["a","a","a","a","a","x","a"],
          blurb:"A profile greeting compiled as a Jinja template. <code>{{7*7}}</code> → <code>49</code> → <code>config</code> → shell." },

  defense: {
    blurb:"The greeting compiles user input as a template. Stop compiling it — or watch the classic non-fixes fail: escaping runs on the result <em>after</em> the code already ran, and throttling changes how fast, not whether.",
    vectors: [
      { q:"{{ cycler.__init__.__globals__.os.popen('id').read() }}", label:"RCE · cycler gadget" },
      { q:"{{ self.__init__.__globals__.__builtins__.__import__('os').popen('whoami').read() }}", label:"RCE · builtins gadget" }
    ],
    options: [
      { id:"context-var", label:"Pass the name as data, not a template",
        code:'return render_template("hi.html", name=name)',
        apply(q){ const s = String(q);
          return /\{\{|\{%/.test(s)
            ? { blocked:true, at:4, why:"The name is a context variable now — the template is a fixed file. Your {{…}} renders as the literal text {{…}}; nothing is ever compiled from user input. This is the fix; everything else is scenery." }
            : { blocked:false, at:null, why:"An ordinary name — bound to a variable and printed, exactly as before." }; } },
      { id:"autoescape", label:"Turn on autoescaping",
        code:"env.autoescape = True",
        apply(q){ const a = sstiAnalyze(q);
          return a.injected
            ? { blocked:false, at:5, why:"Autoescape HTML-encodes the template's OUTPUT — after the expression already executed. The command ran, config leaked, the arithmetic evaluated; escaping only encodes the result's angle brackets. Wrong layer entirely." }
            : { blocked:false, at:null, why:"A plain name — escaped output looks identical to the input." }; } },
      { id:"ratelimit", label:"Rate-limit the profile endpoint",
        code:"@limiter.limit('5/minute')",
        apply(q){ const a = sstiAnalyze(q);
          return a.injected
            ? { blocked:false, at:2, why:"SSTI needs one request. Throttling caps how many names you can save per minute; the one that runs code still runs it." }
            : { blocked:false, at:null, why:"Normal traffic, well under the limit — served." }; } }
    ]
  }
});
