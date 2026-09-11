# STRATA

**A multi-layered security lab where you learn *why* a vulnerability works — not just how to trigger it.**

STRATA renders a vulnerable web application as a cross-section: seven layers stacked in depth — the page, the browser code, the network, the edge, the server, the weak spot, the data — all showing the same request at once. Every byte you type is drawn in amber at every layer, so you watch your own input travel the stack until the moment it stops being *data* and becomes *syntax*, *markup*, or a *decision*.

Open source, single file, zero dependencies, zero network calls. Everything runs — and stays — in your browser.

## Run it

Open `strata.html`. That's it. (Or serve the folder if you want external lab-file links to work: `python3 -m http.server`.)

## What's inside

- **14 built-in labs** — Foundations (how a safe app is wired), the OWASP Top 10 (IDOR, crypto failures, injection ×4, insecure design, misconfiguration, outdated components, auth failures, unverified JWT, logging failures, SSRF).
- **Real labs, not click-throughs.** Every lab carries objectives you complete by *typing the payload yourself*. Hints reveal rung by rung; the answer-preset stays locked until you've solved it; progress persists locally.
- **An honest engine.** A real SQL lexer, a real XSS vector scanner (it knows `<script>` runs server-reflected but is inert via `innerHTML`), a real MD5 against a wordlist hashed at load, a real IP canonicalizer for SSRF. Nothing executes — effects are simulated once the engine proves they'd fire.
- **Virtual intercept.** Toggle Intercept and edit the lab's raw HTTP request Burp-style — URL-encoding and all — before sending it. Scoped entirely to the lab's simulated request; STRATA itself makes no network calls.
- **Infinite labs.** Labs are data. Drop any `…lab.js` calling `STRATA.registerLab({...})` onto the catalog — it's validated and smoke-run on load. Write them by hand or with an AI. See **[docs/AUTHORING.md](docs/AUTHORING.md)**.

## Authoring labs

Read [`docs/AUTHORING.md`](docs/AUTHORING.md) — the full lab contract, the helper library, the style guide, and an AI authoring recipe. Start from [`templates/lab-template.js`](templates/lab-template.js); a complete worked example lives in [`labs-example/open-redirect.lab.js`](labs-example/open-redirect.lab.js). Note the trust model: a lab file is local code with the page's full privileges — validation checks shape, not safety. Only load files you trust.

```
docs/AUTHORING.md            the lab format, style guide, AI recipe
templates/lab-template.js    scaffold to copy
labs-example/open-redirect.lab.js   complete reference lab
strata.html                  the app + 14 golden-reference labs
backups/                     frozen snapshots of earlier versions
```

## Keyboard

`⌥↑/↓` or `j/k` move through layers · `⌥0–9` jump · `⌥space` cross-section · `Enter` fire · `Esc` back to catalog. Scrolling inside a layer's content scrolls the content; the wheel only changes layers when there's nothing left to scroll.

## Status & roadmap

Early and evolving. Next: a community lab catalog on disk, sandboxed backends for server-side labs, defense-mode planes that light green when you patch the right layer, progress sync.

## License

MIT — see [LICENSE](LICENSE).
