# STRATA

**A multi-layered security lab where you learn *why* a vulnerability works — not just how to trigger it.**

STRATA renders a vulnerable web application as a cross-section: seven layers stacked in depth — the page, the browser code, the network, the edge, the server, the weak spot, the data — all showing the same request at once. Every byte you type is drawn in amber at every layer, so you watch your own input travel the stack until the moment it stops being *data* and becomes *syntax*, *markup*, or a *decision*.

Open source, single file, zero dependencies, zero network calls. Everything runs — and stays — in your browser.

## Run it

Open `strata.html`. That's it. (Or serve the folder if you want external lab-file links and the community shelf to work: `python3 -m http.server`.)

## What's inside

- **17 built-in labs** — Foundations (how a safe app is wired), the OWASP Top 10 (IDOR, crypto failures, injection ×4, insecure design, misconfiguration, outdated components, auth failures, unverified JWT, logging failures, SSRF), plus command injection, path traversal, and CSRF.
- **Two directions.** The home page has an **Attacker** tab (the classic STRATA: type the payload, watch it cross) and a **Defender** tab — the same vulnerable build stays live, you deploy candidate patches, and the engine runs the *full attack battery* against your choice. A patch only counts when every vector dies; the tempting non-fixes (hide the errors, `LIMIT 1`, quotes around it) fail on screen, with the reason. 12 labs ship defender editions.
- **Real labs, not click-throughs.** Every lab carries objectives you complete by *typing the payload yourself*. Hints reveal rung by rung; the answer-preset stays locked until you've solved it; progress persists locally.
- **An honest engine.** A real SQL lexer, a real XSS vector scanner (it knows `<script>` runs server-reflected but is inert via `innerHTML`), a real MD5 against a wordlist hashed at load, a real IP canonicalizer for SSRF, a quote-state shell scanner for command injection, real `..` path resolution for traversal, and a form/action/auto-submit parser for CSRF. Nothing executes — effects are simulated once the engine proves they'd fire.
- **Virtual intercept.** Toggle Intercept and edit the lab's raw HTTP request Burp-style — URL-encoding and all — before sending it. Scoped entirely to the lab's simulated request; STRATA itself makes no network calls.
- **Infinite labs, two ways.** Drop any `…lab.js` calling `STRATA.registerLab({...})` onto the catalog — it's validated and smoke-run on load. Or use the **community shelf**: fetch a published `catalog.json`, and each lab file is SHA-256-verified against its entry, then executed inside a **sandboxed worker** — no DOM, no storage, sanitized output. The shelf is the only network STRATA ever does, and only when you ask.

## Authoring labs

Read [`docs/AUTHORING.md`](docs/AUTHORING.md) — the full lab contract (including the optional `defense` block for defender editions), the helper library, the style guide, and an AI authoring recipe. Start from [`templates/lab-template.js`](templates/lab-template.js); complete worked examples live in [`labs/`](labs/). Note the trust model: a lab file you load by hand is local code with the page's full privileges — only load files you trust. Shelf-loaded labs are hash-verified and sandboxed.

```
docs/AUTHORING.md            the lab format, style guide, AI recipe
templates/lab-template.js    scaffold to copy
labs/                        community labs + catalog.json (hash-verified)
labs-example/open-redirect.lab.js   annotated reference lab
scripts/strata.mjs           optional CLI: new · validate · hash · catalog
tests/                       engine, regression, sandbox, and lab-file tests
strata.html                  the app + 17 golden-reference labs
backups/                     frozen snapshots of earlier versions
```

### Optional developer tooling

```sh
node scripts/strata.mjs new my-lab        # scaffold labs/my-lab.lab.js
node scripts/strata.mjs validate labs/…   # run the real page validator
node scripts/strata.mjs catalog           # refresh catalog.json hashes
node tests/engine.test.mjs                # or just run the suite (CI does)
```

Nothing depends on these — the app itself has zero dependencies.

## Keyboard

`⌥↑/↓` or `j/k` move through layers · `⌥0–9` jump · `⌥space` cross-section · `Enter` fire · `Esc` back to catalog. Scrolling inside a layer's content scrolls the content; the wheel only changes layers when there's nothing left to scroll.

## Status & roadmap

Early and evolving. Next: more report-derived labs, a published community catalog, sandboxed backends for server-side labs, teacher/course mode, progress sync.

## License

MIT — see [LICENSE](LICENSE).
