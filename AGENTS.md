# AGENTS.md

## README sync — hard rule

When you upgrade the tool, upgrade the README in the same change. Any
user-visible difference (flags, module names, panels, output formats, help
text, install steps) updates the matching README sections in the same commit:

- Quick start, All flags, module table, Outputs, How to read it, Known
  limitations — whichever the change touches.
- Version bumps also update every version string shown in README examples
  (`emailspy 1.x.y` footers, JSON `"version"` fields), or re-capture the
  example output from a real run.
- Every claim must match observed behaviour — run the command before writing
  it down. Never document expected behaviour you have not seen.

## Commands

- `make check` — ruff check + format check + pytest; must pass before commit.
- `make live` — the network-backed tests (`EMAILSCOPE_LIVE=1`).
- Entry points: `emailspy` / `emailscope` (venv lives in `.venv/`).

## Release spots (all change together on a version bump)

- `pyproject.toml` → `version`
- `src/emailscope/__init__.py` → `__version__`
- `CHANGELOG.md` → new entry
- `README.md` → example outputs that embed the version
