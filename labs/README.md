# Community labs

Each file here is a self-contained STRATA lab that calls `STRATA.registerLab({...})`.
`catalog.json` is the published index: every entry carries the SHA-256 of its lab
file, and the in-app shelf refuses any file whose hash doesn't match.

To add a lab:
1. Write `your-lab.lab.js` (start from `../templates/lab-template.js`).
2. Validate it: `node scripts/strata.mjs validate labs/your-lab.lab.js`
3. Hash it: `shasum -a 256 labs/your-lab.lab.js`
4. Add the entry to `catalog.json` (id, file, sha256, title, difficulty, blurb).
5. Reload catalog.json hashes in one go: `node scripts/strata.mjs catalog`

Shelf-loaded labs run in a sandboxed worker: no DOM, no localStorage, sanitized
output — see the trust-model section in `../docs/AUTHORING.md`.
