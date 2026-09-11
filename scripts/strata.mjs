#!/usr/bin/env node
/* STRATA lab CLI — optional developer tooling, zero dependencies.
   new       <id>          scaffold labs/<id>.lab.js from the template
   validate  <file>…       run the REAL page validator against lab files
   hash      <file>…       print SHA-256 (for catalog.json entries)
   catalog                re-hash every labs/*.lab.js into labs/catalog.json
   check                  syntax-check the engine + run the built-in smoke */
import { readFileSync, writeFileSync, existsSync, readdirSync, unlinkSync } from "node:fs";
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { dirname, join, basename } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const HTML = join(ROOT, "strata.html");
const [,, cmd, ...args] = process.argv;

function loadEngine(){
  const html = readFileSync(HTML, "utf8");
  const script = html.match(/<script>\n([\s\S]*)<\/script>/)[1];
  const shellAt = script.lastIndexOf("/*", script.indexOf("SHELL — lab-agnostic"));
  if (shellAt === -1) throw new Error("shell marker not found");
  globalThis.window = globalThis;
  globalThis.state = { alertSeen:null };   // alertOnce/ingest helpers expect it
  // lab files on the page see the whole engine scope; mirror the authoring surface
  const expose = `;globalThis.__T={LABS,validateLab};
    Object.assign(globalThis, { esc, taint, taintMarkup, codeLines, note, explain, kv, field,
      siteFrame, productCard, safeRender, buildDomTree, intendedVsParsed, vectorList,
      alertSim, alertOnce, alertArg, scanVectors, wafScan, autoFires, callsAlert, entDec,
      safeHref, safeRenderRaw, md5, memoFn, clip, plural, parseIPv4, classifyHost, hostOf,
      normalizePath, b64url, b64urlDec, TOK, HOST, ALERT_CALL, SAFE_TAGS });`;
  new Function(script.slice(0, shellAt) + expose)();
  return globalThis.__T;
}

if (cmd === "new"){
  const id = args[0];
  if (!id || !/^[a-z0-9][a-z0-9-]{1,31}$/.test(id)){
    console.error("usage: strata new <id>   (lowercase slug: letters, digits, dashes)"); process.exit(1);
  }
  const out = join(ROOT, "labs", `${id}.lab.js`);
  if (existsSync(out)){ console.error(`exists: ${out}`); process.exit(1); }
  const tpl = readFileSync(join(ROOT, "templates", "lab-template.js"), "utf8");
  writeFileSync(out, tpl.replaceAll("__LAB_ID__", id));
  console.log(`scaffolded ${out} — now fill in the engine; validate with: node scripts/strata.mjs validate ${out}`);
}

else if (cmd === "validate"){
  if (!args.length){ console.error("usage: strata validate <lab-file>…"); process.exit(1); }
  const T = loadEngine();
  let bad = 0;
  for (const f of args.map(p => join(process.cwd(), p))){
    const code = readFileSync(f, "utf8");
    const captured = [];
    const STRATA = { registerLab(lab){ captured.push(lab); } };
    new Function("STRATA", code)(STRATA);
    if (!captured.length){ console.error(`✗ ${f}: file never called STRATA.registerLab(lab)`); bad++; continue; }
    for (const lab of captured){
      const v = T.validateLab(lab, { allowReplace:true });
      if (v.ok) console.log(`✓ ${f} — ${lab.id} (${lab.layers.length} layers${lab.defense ? ", defender edition" : ""})`);
      else { bad++; console.error(`✗ ${f} — ${lab.id}:`); v.errs.forEach(e => console.error("   · " + e)); }
    }
  }
  process.exit(bad ? 1 : 0);
}

else if (cmd === "hash"){
  for (const f of args){
    const h = createHash("sha256").update(readFileSync(f)).digest("hex");
    console.log(`${h}  ${f}`);
  }
}

else if (cmd === "catalog"){
  const dir = join(ROOT, "labs");
  const catPath = join(dir, "catalog.json");
  const cat = JSON.parse(readFileSync(catPath, "utf8"));
  let changed = 0;
  for (const entry of cat.labs){
    const file = join(dir, entry.file);
    if (!existsSync(file)){ console.error(`  ? ${entry.file} missing — entry kept as-is`); continue; }
    const h = createHash("sha256").update(readFileSync(file)).digest("hex");
    if (entry.sha256 !== h){ entry.sha256 = h; changed++; console.log(`  ↻ ${entry.file} → ${h.slice(0, 12)}…`); }
    else console.log(`  ✓ ${entry.file} already current`);
  }
  writeFileSync(catPath, JSON.stringify(cat, null, 2) + "\n");
  console.log(changed ? `${changed} hash(es) updated` : "catalog already current");
}

else if (cmd === "check"){
  const html = readFileSync(HTML, "utf8");
  const script = html.match(/<script>\n([\s\S]*)<\/script>/)[1];
  const tmp = join(process.env.TMPDIR || "/tmp", "strata-engine-check.js");
  writeFileSync(tmp, script);
  try { execFileSync(process.execPath, ["--check", tmp], { stdio: "inherit" }); }
  finally { try { unlinkSync(tmp); } catch(_){} }
  console.log("engine syntax OK");
}

else {
  console.log(`STRATA lab CLI (optional tooling)

  new <id>        scaffold labs/<id>.lab.js from the template
  validate <f>…   run the real page validator against lab files
  hash <f>…       SHA-256 for catalog entries
  catalog         re-hash labs/*.lab.js into labs/catalog.json
  check           syntax-check the engine

Everything here is a convenience — the app itself has zero dependencies.`);
}
