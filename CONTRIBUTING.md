# Contributing to EmailScope

Thanks for helping. The bar for a change here is: **the data source has to be
real, public, and verifiable.**

## 🚀 Getting started

```bash
git clone <your-fork-url>
cd emailscope
make install
make check
```

Python 3.10 or newer.

## 📜 Ground rules

1. **Never fabricate an endpoint, response shape, or API behaviour.** If you
   have not run the request yourself, do not ship it.
2. **Public, unauthenticated sources only.** No password-reset probing, no
   credential lists, no scraping behind a login.
3. **One concern per PR.** A new probe site is not the moment to reformat the
   report renderer.
4. **Tests ship with the change.** Bug fix → a test that fails before and
   passes after. New module → happy path plus at least one failure case.
5. **README ships with the change.** If behaviour, flags, output, install
   steps or the version change, update `README.md` in the same PR — stale
   instructions are worse than none, and every claim must come from a run you
   actually did.

## 🔌 Adding a probe site

1. Pick a platform with a public profile endpoint.
2. Verify it both ways, from your machine:

   ```bash
   curl -i -A "Mozilla/5.0" https://example.com/api/users/torvalds   # real handle
   curl -i -A "Mozilla/5.0" https://example.com/api/users/zqxjwvunotfound991
   ```

   You need a clean discriminator: `200` + payload vs `404`/empty. If both
   return the same status *and* the same body, the endpoint cannot be used.
   Soft-404 pages need an explicit `missing_body` regex.

3. Add the entry to `src/emailscope/data/sites.json`.
4. Run `pytest tests/test_modules.py` and `make live`.
5. Open a PR describing the two responses you observed (redact nothing but
   personal data).

## ➕ Adding a module

- One file in `src/emailscope/modules/` exporting
  `async def collect(context: Context) -> Finding`.
- Register it in `PHASE_ONE` in `src/emailscope/engine.py` — the list order is
  the order the report renders in — and in `MODULES` in `src/emailscope/cli.py`
  so `--no-<module>` works. (The `social` and `accounts` panels are the two
  exceptions: they run in the second gather after `github` so they can reuse
  the names GitHub observed, and are inserted after that panel.)
- Read credentials with `context.options.key("SOME_API_KEY")` and return
  `status="skip"` when absent. Never hardcode a key, never log one.
- Degrade to `status="unknown"` when the network or the upstream refuses —
  do not report a negative you did not observe.

## 🎨 Style

- `ruff check .` and `ruff format .` must be clean (`make lint`).
- Comments explain *why*, not *what*.
- Public functions get a short doc comment covering purpose, parameters, and
  what they raise.

## 💬 Commits

Conventional Commits: `feat(probe): add Bluesky lookup`, `fix(report): clip
long hashes on narrow terminals`.

## 🐛 Reporting a bug

Open an issue with the exact command, the module that misbehaved, and what you
expected. Strip API keys from any pasted output — reports include environment
names, so check before you paste.
