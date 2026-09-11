/* The worker-sandbox protocol, run headlessly in a real VM context that
   mirrors a worker's global lexical environment. Proves: shelf labs
   validate + eval + apply inside the sandbox, hijacked ids are refused,
   and there is no DOM or storage to snoop. */
import { readFileSync } from "node:fs";
import * as vm from "node:vm";

const html = readFileSync(new URL("../strata.html", import.meta.url).pathname, "utf8");
const script = html.match(/<script>\n([\s\S]*)<\/script>/)[1];
const shellAt = script.lastIndexOf("/*", script.indexOf("SHELL — lab-agnostic"));
globalThis.window = globalThis;
const bwsStart = script.indexOf("function buildWorkerSource");
const bwsEnd = script.indexOf("/* main-side: sanitize");
new Function(script.slice(0, shellAt) + script.slice(bwsStart, bwsEnd)
  + "\n; globalThis.__T = { buildWorkerSource, LABS };")();
const { buildWorkerSource, LABS } = globalThis.__T;

let fails = 0;
const ok = (cond, msg) => { if (!cond){ fails++; console.log("FAIL:", msg); } };

function mkWorker(){
  const messages = [];
  const sandbox = { console };
  sandbox.self = sandbox;
  sandbox.postMessage = m => messages.push(m);
  vm.createContext(sandbox);
  vm.runInContext(buildWorkerSource(), sandbox, { filename: "worker.js" });
  return { messages, onmessage: sandbox.onmessage };
}

/* 1. both shipped community labs load and answer through the protocol */
for (const file of ["labs/xss-waf-plus.lab.js", "labs/open-redirect.lab.js"]){
  const code = readFileSync(new URL("../" + file, import.meta.url).pathname, "utf8");
  const { messages, onmessage } = mkWorker();
  onmessage({ data: { cmd: "init", code, name: file, builtinIds: LABS.map(l => l.id) } });
  const ready = messages.find(m => m.type === "ready");
  ok(ready, `${file}: worker ready (got: ${messages.map(m => m.error || m.type).slice(0, 2).join("; ")})`);
  if (!ready) continue;
  const snap = ready.snapshot;
  ok(snap.layers.length === 7 && !!snap.challenge, `${file}: snapshot shape`);
  ok(snap.wire && !snap.wire.custom, `${file}: standard wire survives serialization`);
  const cached = new Map(ready.cached);
  const spoiler = snap.presets.find(p => p.spoiler);
  const r = cached.get(spoiler.q);
  ok(r && r.solved === true, `${file}: spoiler preset pre-solved in worker`);
  const fresh = "<z" + Math.random().toString(36).slice(2, 7) + ">";
  onmessage({ data: { cmd: "eval", q: fresh, gen: 1 } });
  const res = messages.find(m => m.type === "result" && m.q === fresh);
  ok(res && res.renders.length === 7 && res.trace.length === 7, `${file}: on-demand eval full shape`);
}

/* 2. defense apply roundtrip (xss-waf-plus has a defender edition) */
{
  const code = readFileSync(new URL("../labs/xss-waf-plus.lab.js", import.meta.url).pathname, "utf8");
  const { messages, onmessage } = mkWorker();
  onmessage({ data: { cmd: "init", code, name: "x", builtinIds: [] } });
  const snap = messages.find(m => m.type === "ready")?.snapshot;
  ok(snap?.defense, "defense snapshot present");
  onmessage({ data: { cmd: "apply", optId: "origin-escape", q: snap.defense.vectors[0].q } });
  const ap = messages.find(m => m.type === "apply");
  ok(ap?.r?.blocked === true, "origin-escape blocks inside the sandbox");
}

/* 3. built-in id hijack refused */
{
  const h = mkWorker();
  h.onmessage({ data: { cmd: "init", code: "STRATA.registerLab({id:'sqli'})", name: "evil", builtinIds: ["sqli"] } });
  ok(h.messages.some(m => m.type === "fatal" && /reserved/.test(m.error)), "builtin-id hijack refused");
}

/* 4. the sandbox has no DOM and no storage to snoop */
{
  const p = mkWorker();
  const snooper = `let leaked = [];
    try { document.title = "x"; leaked.push("document"); } catch(e){}
    try { localStorage.setItem("x","1"); leaked.push("localStorage"); } catch(e){}
    try { fetch("https://evil.example").catch(()=>{}); leaked.push("fetch"); } catch(e){}
    STRATA.registerLab({ id:"snooper", code:"S", cat:"x", title:"t", difficulty:"Beginner",
      goal:"g", layers: [...Array(4)].map((_,i)=>({code:"L"+i,title:"a",meta:"b"})), boundary:0,
      presets:[{q:"a",label:"a"}], defaultQ:"a",
      analyze:() => ({ leaked }), layerState:() => "present",
      trace:() => [...Array(4)].map(()=>({h:"a",b:"b",state:"present"})),
      verdict:() => [["leaked", leaked.join(",") || "nothing", ""]], solved:() => false,
      render:{0:a=>String(a.leaked), 1:()=>"", 2:()=>"", 3:() => ""} });`;
  p.onmessage({ data: { cmd: "init", code: snooper, name: "snoop", builtinIds: [] } });
  const ready = p.messages.find(m => m.type === "ready");
  ok(ready, "snooper lab registers despite trying document/localStorage/fetch");
  const r = ready?.cached?.[0]?.[1];
  ok(r?.a?.leaked?.length === 0, "document, localStorage and fetch all unavailable in the sandbox");
}

/* 5. lab-facing fields validate inside the worker, which has NO shell
   globals. A severity-bearing lab is the regression guard: validateLab is
   inlined into the worker, so any dependency on a shell-only symbol
   (SEV_CLS, SEV, …) fails EVERY such lab with a "not defined" fatal that
   the two severity-less reference labs above would never catch. */
{
  const s = mkWorker();
  const sevLab = `STRATA.registerLab({ id:"sevcheck", code:"A0", cat:"x", title:"t",
    difficulty:"Beginner", goal:"g", severity:["CRIT","9.8"],
    layers:[...Array(4)].map((_,i)=>({code:"L"+i,title:"a",meta:"b"})), boundary:0,
    presets:[{q:"a",label:"a"}], defaultQ:"a",
    analyze:()=>({}), layerState:()=>"present",
    trace:()=>[...Array(4)].map(()=>({h:"a",b:"b",state:"present"})),
    verdict:()=>[["k","v",""]], solved:()=>false,
    render:{0:()=>"",1:()=>"",2:()=>"",3:()=>""} });`;
  s.onmessage({ data: { cmd: "init", code: sevLab, name: "sev", builtinIds: [] } });
  const ready = s.messages.find(m => m.type === "ready");
  const fatal = s.messages.find(m => m.type === "fatal");
  ok(ready, `severity-bearing lab validates in the sandbox (fatal: ${fatal?.error || "none"})`);
  ok(ready?.snapshot?.severity?.[0] === "CRIT", "severity survives into the worker snapshot");
}

console.log(fails ? `\n${fails} FAILURES` : "\nALL SANDBOX TESTS PASS");
process.exit(fails ? 1 : 0);
