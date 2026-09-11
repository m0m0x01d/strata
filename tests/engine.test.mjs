import { readFileSync } from "node:fs";
const html = readFileSync(new URL("../strata.html", import.meta.url).pathname, "utf8");
const script = html.match(/<script>\n([\s\S]*)<\/script>/)[1];
const shellAt = script.lastIndexOf("/*", script.indexOf("SHELL — lab-agnostic"));
if (shellAt === -1) throw new Error("shell marker not found");
const head = script.slice(0, shellAt);
globalThis.window = globalThis;
const expose = `\n;globalThis.__T = { LABS, validateLab, md5, RAINBOW, b64url, b64urlDec, jwtToken };`;
new Function(head + expose)();

const T = globalThis.__T;
let fails = 0;
const ok = (cond, msg) => { if (!cond){ fails++; console.log("FAIL:", msg); } };

/* 1. every built-in lab passes our own validator */
for (const L of T.LABS){
  const v = T.validateLab(L, { allowReplace:true });
  ok(v.ok, `${L.id} validator: ${JSON.stringify(v.errs)}`);
}

/* 2. every challenge step's reveal completes that step (and defaultQ doesn't pre-solve finals) */
for (const L of T.LABS){
  if (!L.challenge) continue;
  const base = L.analyze(L.defaultQ);
  for (const st of L.challenge.steps){
    const a = L.analyze(st.reveal);
    let passes = false; try { passes = !!st.test(a); } catch(e){ ok(false, `${L.id}/${st.id} test threw: ${e.message}`); }
    ok(passes, `${L.id}: reveal "${st.reveal.slice(0,40)}" does not complete its step "${st.label}"`);
  }
  const final = L.challenge.steps[L.challenge.steps.length - 1];
  let pre = false; try { pre = !!final.test(base); } catch(_){}
  ok(!pre, `${L.id}: defaultQ already completes the FINAL step (lab pre-solved)`);
  /* every step must also be derivable from a *typed* run of the reveal */
  for (const st of L.challenge.steps){
    ok(typeof st.reveal === "string" && st.reveal.length > 0 && Array.isArray(st.hints) && st.hints.length >= 1,
       `${L.id}/${st.id}: challenge shape`);
  }
}

/* 3. free-typed engine checks — inputs NOT present in any preset */
const by = id => T.LABS.find(l => l.id === id);

const sqli = by("sqli");
let a = sqli.analyze("' OR 1=1#");
ok(a.tautology, "sqli: free-typed tautology variant recognized");
ok(sqli.analyze("' OR 1=1 -- ").tautology, "sqli: spaced -- comment variant recognized");
a = sqli.analyze("x' UNION SELECT id,email,password FROM users--");
ok(a.leaked.length === 3, "sqli: free-typed UNION leaks users");

const cryptoL = by("crypto");
const h = T.md5("letmein");   // in wordlist, NOT any preset
a = cryptoL.analyze(h);
ok(a.plain === "letmein", "crypto: real wordlist cracks a non-preset word");
ok(cryptoL.analyze(T.md5("zqxwvu123!")).plain === null, "crypto: word outside list does not crack");
ok(cryptoL.analyze("not-a-hash").pwMode === "not-a-hash", "crypto: word mode works");

const ssrf = by("ssrf");
a = ssrf.analyze("http://0x7f000001/admin");
ok(a.internal && !a.solved, "ssrf: hex loopback recognized (internal, not creds)");
a = ssrf.analyze("http://2852039166/latest/meta-data/iam/security-credentials/");
ok(a.solved && a.altForm, "ssrf: decimal-IP metadata steal recognized as disguised");
a = ssrf.analyze("http://[::ffff:169.254.169.254]/latest/meta-data/");
ok(a.solved, "ssrf: IPv6-mapped metadata steal works");
a = ssrf.analyse ? null : ssrf.analyze("http://8.8.8.8/x");
ok(a.external && !a.internal, "ssrf: public IP stays external");
a = ssrf.analyze("http://169.254.43518/latest/meta-data/");
ok(a.solved && a.altForm, "ssrf: 3-part packed shorthand works");

const misc = by("misconfig");
a = misc.analyze("/static/../.env");
ok(a.file?.kind === "secrets" && a.traversed, "misconfig: traversal reaches .env");
ok(misc.analyze("/.git/HEAD").file?.kind === "source", "misconfig: /.git/HEAD served");

const auth = by("auth");
a = auth.analyze("r.okafor@aperture.lab : abc123");
ok(a.ok && !a.admin, "auth: free-typed correct creds sign in non-admin");

const jwt = by("jwt");
const tok = T.jwtToken("admin");
ok(tok.split(".").length === 3 && tok.endsWith("."), "jwt: alg:none token minted");
const round = JSON.parse(T.b64urlDec(tok.split(".")[1]));
ok(round.role === "admin", "jwt: b64 round-trip");

const dom = by("xss-dom");
a = dom.analyze("<body onload=alert(1)>");
ok(!a.fires, "dom: body onload is inert via innerHTML (fragment parsing drops body attrs)");
a = dom.analyze("<a href=javascript:alert(1)>x</a>");
ok(!a.fires, "dom: javascript: anchor needs click (no auto-fire)");

const waf = by("xss-waf");
a = waf.analyze("<ScRiPt>alert(1)</ScRiPt>");
ok(a.waf.blocked, "waf: case trick still blocked (blocklist is case-insensitive)");

console.log(fails ? `\n${fails} FAILURES` : "\nALL ENGINE TESTS PASS");
process.exit(fails ? 1 : 0);
