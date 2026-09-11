import { readFileSync } from "node:fs";
const html = readFileSync(new URL("../strata.html", import.meta.url).pathname, "utf8");
const script = html.match(/<script>\n([\s\S]*)<\/script>/)[1];
const shellAt = script.lastIndexOf("/*", script.indexOf("SHELL — lab-agnostic"));
globalThis.window = globalThis;
new Function(script.slice(0, shellAt) + `
;globalThis.__T = { LABS, validateLab, md5, RAINBOW, jwtToken, splitCreds, safeHref,
  callsAlert, autoFires, scanVectors, AUTH_LOG, normalizePath };`)();
// encodePath lives in the DOM shell — run its REAL source headless
const encodePathSrc = script.match(/function encodePath\(p\)\{[\s\S]*?\n\}/)[0];
const encodePath = new Function(encodePathSrc + "; return encodePath;")();
const T = globalThis.__T;
let fails = 0;
const ok = (cond, msg) => { if (!cond){ fails++; console.log("FAIL:", msg); } };
const by = id => T.LABS.find(l => l.id === id);
let a;

/* 1. every built-in lab passes the NEW probe-based validator */
for (const L of T.LABS){
  const v = T.validateLab(L, { allowReplace:true });
  ok(v.ok, `${L.id} validator: ${JSON.stringify(v.errs)}`);
}

/* 2. SQLi: keywords inside the literal can never be SQL */
const sqli = by("sqli");
a = sqli.analyze("union select id,email,password from users");
ok(!a.error && !a.union && a.leaked.length === 0, "sqli: benign keyword search does NOT solve");
ok(a.rows.length === 0, "sqli: benign keyword needle gives 0 rows");
a = sqli.analyze("OR 1=1");
ok(!a.tautology && !a.error, "sqli: in-literal OR is not a tautology");
a = sqli.analyze("' OR '1'='1");
ok(a.tautology && !a.error, "sqli: classic no-comment tautology credited");
ok(a.rows.filter(p => !p.released).length === 2, "sqli: ' OR '1'='1 releases withheld rows");
a = sqli.analyze("' UNION SELECT id,email,password FROM users--");
ok(a.leaked.length === 3 && !a.error, "sqli: correct UNION leaks");
a = sqli.analyze("' UNION SELECT 1,2,3 FROM users--");
ok(!a.error && a.unionLiterals?.length === 3 && a.leaked.length === 0, "sqli: 3 constants → runs, leaks nothing (constants note)");
ok(sqli.render[6](a).includes("constants, not columns"), "sqli: L6 explains the constants result");
a = sqli.analyze("' UNION SELECT email,password FROM users--");
ok(a.error && /result columns/.test(a.error.msg), "sqli: 2-column UNION errors");
a = sqli.analyze("' UNION SELECT id,email,password FROM products--");
ok(a.error && /no such table/.test(a.error.msg), "sqli: UNION from wrong table errors");
a = sqli.analyze("' FOOBAR--");
ok(a.error && /near "FOOBAR"/.test(a.error.msg), "sqli: garbage syntax error");
a = sqli.analyze("'; DROP TABLE users;--");
ok(a.error && /one statement/.test(a.error.msg), "sqli: stacked statements rejected");
a = sqli.analyze("' ORDER BY 4--");
ok(a.error && /out of range/.test(a.error.msg), "sqli: ORDER BY 4 out of range");
a = sqli.analyze("' ORDER BY 3--");
ok(!a.error && a.rows.some(p => !p.released), "sqli: ORDER BY 3 releases withheld (honest)");
a = sqli.analyze("don't");
ok(!!a.error, "sqli: unmatched text after quote errors (unterminated literal)");
a = sqli.analyze("lens''");
ok(!a.error, "sqli: '' escaped quote stays balanced");
/* challenge steps still complete via reveals */
for (const st of sqli.challenge.steps){
  const r = sqli.analyze(st.reveal);
  ok(st.test(r), `sqli: reveal "${st.reveal.slice(0,30)}" completes "${st.id}"`);
}

/* 3. XSS engine */
const modes = ["parser", "innerHTML"];
const F = (html, mode, want, why) => {
  const v = T.scanVectors(html, mode);
  ok(v.some(x => x.fires) === want, `scanVectors ${why} (${mode})`);
};
for (const m of modes){
  F("<input onfocus=alert(1) autofocus>", m, true, "autofocus after handler");
  F("<input autofocus onfocus=alert(1)>", m, true, "autofocus before handler");
  F("<div autofocus onfocus=alert(1)>", m, false, "autofocus on non-control");
  F("<video onerror=alert(1)>", m, false, "onerror without a resource");
  F("<img src=x onerror=alert(1)>", m, true, "img onerror with src");
  F("<details open ontoggle=alert(1)>", m, true, "details ontoggle+open");
  F("<marquee onstart=alert(1)>", m, true, "marquee onstart");
  F("<img src=x onerror=alert&lpar;1&rpar;>", m, true, "entity-encoded call");
  F("<img src=x onerror=al\\u0065rt(1)>", m, true, "unicode-escaped call");
  F("<img src=x onerror=alert`1`>", m, false, "backtick is not a call");
}
F("<body onload=alert(1)>", "parser", true, "body onload at parse");
F("<body onload=alert(1)>", "innerHTML", false, "body onload via innerHTML");

/* 4. DOM lab decodes the fragment */
const dom = by("xss-dom");
a = dom.analyze("%3Csvg%20onload%3Dalert(1)%3E");
ok(a.fires, "dom: URL-encoded fragment fires (source decodes it)");
a = dom.analyze("<scriptx>alert(1)</scriptx>");
ok(!a.scriptOnly, "dom: <scriptx> is not the script trap");
a = dom.analyze("<script>alert(1)</script>");
ok(a.scriptOnly, "dom: real <script> triggers trap step");

/* 5. SSRF: userinfo, hex-mapped v6, numeric-only altForm */
const ssrf = by("ssrf");
a = ssrf.analyze("http://user@169.254.169.254/latest/meta-data/iam/security-credentials/");
ok(a.solved, "ssrf: userinfo-prefixed metadata steals creds");
a = ssrf.analyze("http://evil.example@169.254.169.254/latest/meta-data/iam/security-credentials/");
ok(a.solved, "ssrf: decoy-userinfo metadata steals creds");
a = ssrf.analyze("http://169.254.169.254:80@evil.example/");
ok(!a.solved && a.external, "ssrf: userinfo-trick does NOT reach metadata (connects to evil)");
ok(ssrf.analyze("http://169.254.169.254:80/x").solved, "ssrf: port stripped");
a = ssrf.analyze("http://[::ffff:a9fea9fe]/latest/meta-data/iam/security-credentials/");
ok(a.solved && a.altForm, "ssrf: hex-mapped IPv6 metadata recognized as disguise");
a = ssrf.analyze("http://169.254.169.254./latest/meta-data/iam/security-credentials/");
ok(a.solved && !a.altForm, "ssrf: trailing dot is an alias, not a disguise");
/* XSS-through-display regression: hostile host renders escaped */
a = ssrf.analyze("x://<svg onload=alert(1)>");
const L5 = ssrf.render[5](a);
ok(!L5.includes("<svg onload"), "ssrf: hostile host is escaped on L5");
ok(L5.includes("&lt;svg onload=alert(1)&gt;"), "ssrf: escaped host present");

/* 6. misconfig: %-decoding, /.git/HEAD, trailing slash */
const misc = by("misconfig");
a = misc.analyze("/static/%2e%2e/.env");
ok(a.file?.kind === "secrets" && a.traversed, "misconfig: %-encoded traversal reaches .env");
a = misc.analyze("/.git/HEAD");
ok(a.file?.kind === "source", "misconfig: /.git/HEAD served");
a = misc.analyze("/.env/");
ok(!a.file, "misconfig: trailing slash on a file is 404");

/* 7. IDOR / design / auth / logging / crypto */
const idor = by("idor");
ok(!idor.analyze("-1000").acct, "idor: -1000 finds nothing");
ok(idor.analyze("1000").acct?.owner === "admin", "idor: 1000 is admin");
const design = by("design");
a = design.analyze("abc");
ok(!a.valid && a.charged === null, "design: garbage price is invalid (400)");
a = design.analyze("1e3");
ok(a.valid && a.charged === 1000, "design: 1e3 parses as 1000");
const auth = by("auth");
const before = T.AUTH_LOG.total;
auth.analyze("admin@aperture.lab : password"); auth.analyze("admin@aperture.lab : passwo");
ok(T.AUTH_LOG.total === before, "auth: analyze() logs nothing (pure)");
auth.onFire(auth.analyze("admin@aperture.lab : password"));
ok(T.AUTH_LOG.total === before + 1, "auth: onFire logs the attempt");
const brute = auth.analyze("j.lindqvist@aperture.lab : *bruteforce*");
ok(brute.brute && !brute.brute.found && brute.brute.tries === 8, "auth: brute miss reports 8 tries, no find");
const L0auth = auth.render[0](brute);
ok(L0auth.includes("NOT in this list"), "auth: brute-miss copy says NOT in this list");
ok(auth.analyze("a : b : c").pw === "b : c", "auth: colon-in-password survives splitCreds");
const logging = by("logging");
ok(logging.analyze(" normal ").key === "normal" && !logging.analyze(" normal ").solved, "logging: trailing space → normal, not takeover");
ok(logging.analyze("bogus").key === "normal", "logging: unknown scenario → normal");
let threw = false; try { logging.analyze("constructor"); logging.render[0](logging.analyze("constructor")); } catch(e){ threw = true; }
ok(!threw, "logging: prototype-key input does not crash");
ok(logging.analyze("account takeover").solved, "logging: real takeover still solves");
const cryptoL = by("crypto");
ok(cryptoL.render[0](cryptoL.analyze("")).includes("Paste a hash"), "crypto: empty input gets a starter message");

/* 8. intercept wire: path encoding round-trip + login splitCreds */
ok(encodePath("/backup files/sql") === "/backup%20files/sql", "encodePath: spaces encoded");
ok(encodePath("/100%off") === "/100%25off", "encodePath: bare % escaped");
ok(encodePath("/.env") === "/.env", "encodePath: plain path untouched");
ok(T.splitCreds("a : b : c")[1] === "b : c", "splitCreds: first-colon split");

/* 9. safeHref: control-char scheme bypass closed */
ok(T.safeHref("jav\tascript:alert(1)") === "#", "safeHref: tab-embedded javascript: → #");
ok(T.safeHref("jav\nascript:alert(1)") === "#", "safeHref: newline-embedded javascript: → #");
ok(T.safeHref("JavaScript:alert(1)") === "#", "safeHref: case-insensitive");
ok(T.safeHref("data:text/html,x") === "#", "safeHref: data: blocked");
ok(T.safeHref("/account") === "/account", "safeHref: relative path kept");
ok(T.safeHref("https://x.example/") === "https://x.example/", "safeHref: https kept");

/* 10. the example lab still validates and plays (fixed backslash preset) */
const file = readFileSync(new URL("../labs/open-redirect.lab.js", import.meta.url).pathname, "utf8");
let captured = null;
globalThis.STRATA = { registerLab(l){ captured = l; } };
new Function(script.slice(0, shellAt) + ";globalThis.STRATA={registerLab(l){globalThis.__cap=l;}};" + file)();
const v = T.validateLab(globalThis.__cap, { allowReplace:true });
ok(v.ok, "example lab validates: " + JSON.stringify(v.errs));
ok(globalThis.__cap.analyze("/\\evil.example").offsite, "example: backslash preset now demonstrates the bypass");
for (const st of globalThis.__cap.challenge.steps)
  ok(st.test(globalThis.__cap.analyze(st.reveal)), `example: reveal completes "${st.id}"`);

console.log(fails ? `\n${fails} FAILURES` : "\nALL REGRESSION TESTS PASS");
process.exit(fails ? 1 : 0);
