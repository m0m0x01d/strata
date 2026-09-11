# STRATA

**A multi-layered security lab where you learn *why* a vulnerability works — not just how to trigger it.**

STRATA renders a vulnerable web application as a **cross-section**: seven layers stacked in depth — the page, the browser code, the network, the edge, the server, the weak spot, the data — all showing the same request at once. Every byte you type is drawn in **amber** at every layer, so you watch your own input travel the stack until the moment it stops being *data* and becomes *syntax*, *markup*, or a *decision*. Then you switch sides and put it back together.

Open source. One file. Zero dependencies. Zero network calls of its own (the opt-in community shelf is the only exception, and only when you ask). Everything runs — and stays — in your browser.

---

## Run it

Open `strata.html`. That's it.

Or serve the folder so the community shelf and the Authoring-doc link work:

```sh
python3 -m http.server 8641     # then http://127.0.0.1:8641/strata.html
```

No build step, no install, no accounts. Progress persists in `localStorage` (`strata.progress.v1`).

---

## Two directions

### Attacker — the classic STRATA

Pick a lab from the catalog and you get a real, working vulnerable app sliced into seven planes you can fly through (focus mode) or see edge-on (cross-section, `⌥space`). The input is yours — **type the payload yourself**, or toggle **Intercept** to pause the lab's *virtual* request and edit the raw HTTP bytes Burp-style (URL-encoding and all) before sending. Every layer re-derives from those bytes exactly as an origin would decode them. The host page's traffic is never touched; STRATA makes no network calls.

Each lab carries **objectives** — phases of the real attack ("break the literal" → "read withheld rows" → "exfiltrate the table") — that complete only when the *engine* says so. Hints reveal rung by rung; the final rung shows the payload, but a solve earned that way is labeled. The answer preset stays locked until you've solved the lab. A clean solve requires typing (or intercepting) the payload yourself.

### Defender — flip every lab

The home page's **Defender** tab lists the labs that ship defense data. The same vulnerable build stays live, and you **deploy candidate patches** — parameterize the query, escape the reflection, check the owner, verify the signature, require a metadata token… The patch is *actually applied*:

- **Honest traffic flows normally.** A real fix is invisible to benign input — every patch's engine answers per-payload, so a search for `lens` still returns products under a parameterized query.
- **Attacks die at a layer, visibly.** Send `' OR 1=1--` against the patched build and the response area explains what happened: *"✓ Nothing fired. You sent `' OR 1=1--` — and the app just did its job. Parameterized query stopped it at L4."* The blocking plane turns blocked, everything below it goes cold, the trace narrates the kill — and the input stays live so you can keep probing.
- **Wrong fixes fail on screen.** The engine runs the full attack battery against your choice. Hide-the-errors, `LIMIT 1`, quote-wrapping, string blocklists for SSRF (watch `2852039166` canonicalize to `169.254.169.254` and sail past), `HttpOnly` for XSS, algorithm-pinning for an unsigned JWT — each non-fix is shown *failing*, with the reason. A patch only counts when **every vector dies**; if your own payload still burns through, the verdict reads **✗ bypassed**.

Progress is tracked per lab in both directions (solved / solved·hints / patched).

---

## The 17 built-in labs

| # | Lab | Category | Difficulty | Objectives | Severity¹ | Defender | Intercept |
|---|-----|----------|-----------|------------|----------|----------|-----------|
| LAB 00 | How a web app is wired | Foundations | Beginner | guided tour | — | — | — |
| A01 | IDOR in the account page | Broken Access Control | Apprentice | 2 | HIGH 7.5 | ✓ | query |
| A01 | Path traversal in a docs viewer | Broken Access Control | Apprentice | 2 | HIGH 7.7 | ✓ | query |
| A01 | CSRF — the browser as deputy | Broken Access Control | Practitioner | 3 | HIGH 8.8 | ✓ | — (that IS the lesson) |
| A02 | Passwords stored as unsalted MD5 | Cryptographic Failures | Apprentice | 2 | HIGH 7.4 | — | offline |
| A03 | UNION-based SQL injection | Injection | Apprentice | 3 | CRIT 9.8 | ✓ | query |
| A03 | Reflected XSS in the search response | Injection | Apprentice | 2 | MED 6.1 | ✓ | query |
| A03 | DOM XSS in an innerHTML sink | Injection | Practitioner | 3 | MED 6.1 | ✓ | fragment (nothing to intercept) |
| A03 | Reflected XSS behind a blocklist WAF | Injection | Practitioner | 3 | MED 6.1 | ✓ | query |
| A03 | OS command injection in a ping utility | Injection | Apprentice | 2 | CRIT 9.8 | ✓ | query |
| A04 | The checkout trusts a price from the browser | Insecure Design | Apprentice | 2 | HIGH 8.1 | — | JSON body |
| A05 | Config and backup files served to the world | Security Misconfiguration | Apprentice | 3 | HIGH 7.5 | — | path |
| A06 | A 9-year-old markdown library | Vulnerable & Outdated Components | Practitioner | 2 | HIGH 8.8 | — | form |
| A07 | Username enumeration + no rate limit | Authentication Failures | Practitioner | 3 | CRIT 9.8 | — | login |
| A08 | A JWT the server never verifies | Software & Data Integrity | Practitioner | 2 | CRIT 9.1 | ✓ | JWT header |
| A09 | An account takeover nobody sees | Logging & Monitoring Failures | Practitioner | 2 | LOW 3.7 | — | offline replay |
| A10 | "Import image from URL" fetches anything | Server-Side Request Forgery | Practitioner | 3 | CRIT 9.8 | ✓ | JSON body |

¹ Typical real-world CVSS 3.1 base scores for the bug class — the number a report gets, next to the number of lines that fix it.

**10 labs ship defender editions**, covering the access-control, injection, integrity and forgery sets.

---

## The instrument

- **Seven planes, one request.** The surface (a simulated browser with a working input), the client code, the wire, the edge, the server source, the weak spot (parser / shell / filesystem / session), and the data — all rendering your input simultaneously.
- **The one rule that makes it teach:** every byte that originated from you is amber, at every layer, without exception. Nothing else in the interface is warm. You track your payload from keystroke to query string to parser to DOM without being told where to look — and the moment amber stops being *data* and becomes *syntax* (SQL), *markup* (HTML), *source* (shell), or a *path operator* (`..`) is visible, not narrated.
- **Every lab has a different taint signature.** DOM XSS tunnels through the client and skips the network entirely (the request/edge/server planes go dark — the fragment never leaves the browser). The WAF lab stops amber at the edge until you slip past its grammar. CSRF's amber never crosses the boundary at all — you attack the *victim's browser*, and the cookie rides along by itself.
- **Honest engines, simulated effects.** A real SQL lexer (quote balance, comment offsets, UNION column projection), a real XSS vector scanner (it knows `<script>` runs server-reflected but is inert via `innerHTML`; which handlers auto-fire, and when), a genuine RFC-1321 MD5 against a wordlist hashed at load, a real IP canonicalizer (decimal/hex/octal/IPv6-mapped/userinfo) for SSRF, a quote-state shell scanner for command injection, Python-faithful `os.path.join` semantics for traversal, and a form/action/auto-submit parser for CSRF. Nothing executes — the `alert()` on the surface is a simulated dialog the engine *proves* would fire.

---

## Infinite labs

A lab is **data**: layers, presets, a pure `analyze(q)`, per-layer renderers, a taint signature, objectives with hint ladders, an optional defender edition — one contract, validated and smoke-run on load (including a battery of hostile probes). That makes every workflow real: *"build me a lab from this HackerOne report," "harder XSS please," "show me how this code gets exploited."*

**[docs/AUTHORING.md](docs/AUTHORING.md)** is the full authoring guide — the contract, the helper library, the style guide, an AI authoring recipe, and the pre-submit checklist. Start from [`templates/lab-template.js`](templates/lab-template.js) (includes a commented-out `defense` skeleton); [`labs/xss-waf-plus.lab.js`](labs/xss-waf-plus.lab.js) is a complete worked example with a defender edition.

### Two load paths, two trust models

| | Drag & drop a local file | Community shelf |
|---|---|---|
| How | Drop any `…lab.js` calling `STRATA.registerLab({...})` onto the catalog | Fetch a published `catalog.json`, click Load |
| Validation | Real validator + smoke run | Same — inside the sandbox |
| Trust | **Local code with the page's full privileges.** Only load files you trust. | **SHA-256 verified** against the catalog entry (mismatch = refused by design; no hash = refused), then executed in a **sandboxed worker**: no DOM, no localStorage, no network from the lab, all output sanitized on the way back in |
| Intercept | All wire types incl. custom | Standard wire types (custom wires get the lesson, not the tool) |

The shelf is the only network STRATA ever performs, and only when you click Fetch. Publish a catalog by putting `labs/` + `catalog.json` on any static host (GitHub Pages works); refresh hashes with `node scripts/strata.mjs catalog`.

---

## Repository layout

```
strata.html                  the entire app + the 17 golden-reference labs (one file, ~6.2k lines)
docs/AUTHORING.md            the lab format, helper library, style guide, AI recipe
templates/lab-template.js    scaffold to copy (with defense skeleton)
labs/                        community labs + catalog.json (SHA-256 pinned);
                             open-redirect.lab.js doubles as the annotated reference
scripts/strata.mjs           optional CLI — new · validate · hash · catalog · check
tests/                       engine · regression · sandbox · lab-file suites (zero deps)
.github/workflows/ci.yml     runs everything on push/PR
backups/                     frozen snapshots (gitignored)
```

### Optional developer tooling

Nothing depends on these — the app itself has zero dependencies and zero build:

```sh
node scripts/strata.mjs new my-lab        # scaffold labs/my-lab.lab.js
node scripts/strata.mjs validate labs/…   # run the REAL page validator against lab files
node scripts/strata.mjs hash labs/…       # SHA-256 for a catalog entry
node scripts/strata.mjs catalog           # refresh labs/catalog.json hashes
node scripts/strata.mjs check             # engine syntax check

node tests/engine.test.mjs                # validator + reveal/benign invariants, all labs
node tests/regression.test.mjs            # per-lab behavioral regression
node tests/sandbox.test.mjs               # the worker protocol in a VM (hijacks, no-DOM canaries)
node tests/labs.test.mjs                  # disk labs validate + catalog hashes current
```

The engine test also guards the file structurally: it fails if any `</script>` appears before the final one (a payload string closing the page's script tag is this repo's most dangerous typo class).

---

## Keyboard & controls

| Keys | Action |
|---|---|
| `⌥↑/↓` or `j/k` | move through layers |
| `⌥0–9` | jump to a layer |
| `⌥space` | cross-section view (see every layer at once) |
| `Enter` | fire the payload |
| `Esc` | close popup → close intercept → back to catalog |

Scrolling inside a layer's content scrolls the content; the wheel only changes layers when there's nothing left to scroll. `?perf` in the URL adds a timing HUD. The lab picker (top right) keeps your current side; the home page always resets to the attacker tab.

---

## Threat model, honestly

- The app executes nothing: payloads are *analyzed*, effects are *simulated* once the engine proves they'd fire. `alert()` is a drawing.
- A lab file you load by hand is local code with full page privileges — validation checks shape, not safety. That's a feature (labs are trivial to write) with a responsibility attached.
- Shelf labs are hash-pinned and sandboxed, and their HTML output is sanitized — but a catalog is only as trustworthy as its publisher. The hash proves *the file you fetched is the file they catalogued*, nothing more.
- Progress lives in your browser. Nothing is sent anywhere, because nothing is ever sent anywhere.

---

## Status & roadmap

Early and evolving. Shipped: the cross-section engine, 17 labs, both attacker and defender modes, virtual intercept, the lab format + validator + sandbox, community catalog mechanics, CLI, tests and CI.

Next: report-derived labs (each modeled on a real public writeup), a published community catalog, sandboxed backends for server-side labs (free-typed exploits against a real origin), teacher/course mode, progress sync.

## License

MIT — see [LICENSE](LICENSE).
