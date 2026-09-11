/* Every lab shipped on disk validates through the REAL page validator,
   and the catalog's hashes match the files. */
import { readFileSync, readdirSync } from "node:fs";
import { createHash } from "node:crypto";

const html = readFileSync(new URL("../strata.html", import.meta.url).pathname, "utf8");
const script = html.match(/<script>\n([\s\S]*)<\/script>/)[1];
const shellAt = script.lastIndexOf("/*", script.indexOf("SHELL — lab-agnostic"));
globalThis.window = globalThis;
globalThis.state = { alertSeen: null };
const expose = `;globalThis.__T={LABS,validateLab};
  Object.assign(globalThis, { esc, taint, taintMarkup, codeLines, note, explain, kv, field,
    siteFrame, productCard, safeRender, buildDomTree, intendedVsParsed, vectorList,
    alertSim, alertOnce, alertArg, scanVectors, wafScan, autoFires, callsAlert, entDec,
    safeHref, safeRenderRaw, md5, memoFn, clip, plural, parseIPv4, classifyHost, hostOf,
    normalizePath, b64url, b64urlDec, TOK, HOST, ALERT_CALL, SAFE_TAGS });`;
new Function(script.slice(0, shellAt) + expose)();
const { validateLab } = globalThis.__T;

let fails = 0;
const ok = (cond, msg) => { if (!cond){ fails++; console.log("FAIL:", msg); } };

const dir = new URL("../labs/", import.meta.url).pathname;
const files = readdirSync(dir).filter(f => f.endsWith(".lab.js"));
ok(files.length >= 2, "labs/ ships lab files");
for (const f of files){
  const captured = [];
  new Function("STRATA", readFileSync(dir + f, "utf8"))({ registerLab: l => captured.push(l) });
  ok(captured.length === 1, `${f}: registers exactly one lab`);
  for (const lab of captured){
    const v = validateLab(lab, { allowReplace: true });
    ok(v.ok, `${f} (${lab.id}) validator: ${v.errs.join(" · ")}`);
  }
}
const cat = JSON.parse(readFileSync(dir + "catalog.json", "utf8"));
for (const e of cat.labs){
  const h = createHash("sha256").update(readFileSync(dir + e.file)).digest("hex");
  ok(h === e.sha256, `catalog hash current for ${e.file} (run: node scripts/strata.mjs catalog)`);
}
console.log(fails ? `\n${fails} FAILURES` : "\nALL LAB-FILE TESTS PASS");
process.exit(fails ? 1 : 0);
