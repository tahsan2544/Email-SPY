# Changelog

All notable changes to this project are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versions follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.7.0] - 2026-09-25

### Added

- `--html` export (and `.html` / `.htm` output files): one self-contained
  document — inline CSS, no scripts, no webfonts, no network — that keeps the
  terminal report's grammar: status stamps, right-aligned source provenance,
  left-rule panels, the summary strip and the ethics line. A batch becomes one
  file with a section per address. Honours `--theme`.
- Print styles and a light-mode palette for printing, WCAG AA contrast checks
  on every text colour (a theme colour is nudged lighter only if it would
  otherwise fail on the page background), visible focus rings and underlined
  links.

### Changed

- The header summary strip (provider / mailbox / handles / names) is now built
  by one shared `summary_fields()` used by both the terminal and HTML
  renderers, so the two exports cannot drift apart.

## [1.6.0] - 2026-09-25

### Added

- `mentions` module: where the **address itself** appears in public text —
  Sourcegraph code search (repository, file and the matching line), Hacker News
  stories and comments, and Stack Exchange questions. Five samples per source
  with dates, plus ready-made search links for all three. Unlike the domain
  modules it runs for free-mail addresses too, and reports `info` honestly when
  nothing public matches.
- Forum and Q&A bodies arrive as HTML; markup and entities are now stripped
  before rendering so hits read as sentences.

### Notes

- Sources tested live and rejected: grep.app (Vercel bot challenge, 429),
  Reddit (403 to non-browser clients), psbdmp (does not answer).

## [1.5.0] - 2026-09-25

### Added

- Batch runs: pass several addresses on the command line, or `--batch FILE`
  (one per line, `#` comments). Addresses are de-duplicated, validated before
  any request is made, and investigated sequentially with a `n/N` progress line
  on stderr so `--json`/`--csv` stdout stays parseable.
- Batch exports: `--json` becomes an array (a single address still returns the
  same object as before), `--markdown` concatenates one report per address.

### Changed

- CSV export now starts with an `email` column, so a batch triage sheet always
  says which address a row belongs to.

## [1.4.0] - 2026-09-25

### Added

- `--proxy URL` — route every request through an HTTP(S) or SOCKS proxy
  (`socks5h://127.0.0.1:9150` for Tor, `http://127.0.0.1:8080` for a local
  forwarder). `httpx[socks]` is now a declared dependency, and the chosen
  egress is printed in the report header as `EGRESS`.
- `--only M1,M2` — run just the named modules; an explicit `--no-<module>`
  still wins when both are given, and unknown names are a usage error.
- `urlscan` module: recent public browser scans of the address's own domain —
  scanned page URL, serving IP, country, HTTP status and scan date. Skipped
  for free-mail providers, like the other domain modules.
- `--csv` export (and `.csv` output files): one row per module for spreadsheet
  triage; nested detail stays in the JSON export.

### Notes

- Archive indexes were evaluated and deliberately left out: the Wayback CDX
  API answers in 3–60s and Common Crawl in 10s+, often with 503/504, which is
  not acceptable latency for a default module.

## [1.3.0] - 2026-09-25

### Added

- `ct` module: certificate-transparency subdomains of the address's own domain
  (certspotter), with issuance count and first/last certificate date.
- `hosts` module: hostnames and addresses observed for the domain (HackerTarget
  host search).
- `mailhost` module: resolves the domain's mail exchangers and reports the
  network that runs them — ASN holder and announced prefix from RIPEstat, open
  ports, known CVE count and co-hosted hostnames from Shodan's InternetDB.
- All three skip free-mail providers with the reason stated, matching `rdap`.
- `--no-ct`, `--no-hosts`, `--no-mailhost` switches.

## [1.2.0] - 2026-09-25

### Added

- `pgp` module: OpenPGP key published for the address on keys.openpgp.org —
  fingerprint, user IDs, and the other addresses the owner listed on the same
  key. Only serves verified addresses, so a hit is a strong association.
- `rdap` module: registration record for the address's own domain (registrar,
  registered / expires / last-changed, status flags, nameservers, DNSSEC).
  Skipped for free-mail providers, whose domain data describes the operator
  rather than the subject.
- `--no-pgp` and `--no-rdap` switches, wired like every other module flag.

## [1.1.0] - 2026-09-25

### Added

- `Email Spy` report identity: block-glyph `EMAIL SPY` wordmark (49 columns,
  plain-text fallback on narrow terminals), `CASE <ref>` reference derived from
  the SHA-256 of the address, and a `FINDINGS / SOURCES / SKIPPED` footer
  carrying the tool version.
- Themes (`--theme`, `--list-themes`): `spy` (default) and `classic`, defined
  in `src/emailscope/theme.py`. Colours now carry fixed meaning — stamp for a
  confirmed hit, remote for anything owned by someone else, warn for an
  inconclusive result.
- `emailspy` console entry point; `emailscope` remains as an alias.
- `tests/test_theme.py` covering wordmarks, status colours, stamp widths and
  the three-tier rendering.

### Changed

- Case summary strip under the subject: `PROVIDER`, `MAILBOX`, `HANDLES` and
  `NAMES`, read straight from the collected findings before any block opens.
  Observed names are de-duplicated ("Matt" + "Matt Mullenweg" → one entry).
- Pipeline numbering: every block and skipped line carries its `NN` position in
  the fixed probe order, and skipped titles line up with panel titles.
- Footer repeats `CASE <ref>` alongside the tool version.
- Every heading and skipped line now shows the source it came from, aligned
  right (`public DNS`, `gravatar.com`, `emailrep.io`).
- Only a hit renders as a filled stamp; other statuses are outlined text, so
  one element on screen carries a background.
- The subject line splits local part and domain, the domain in the colour that
  means "owned by someone else".
- Markdown export is titled `Email Spy report`.
- Report hierarchy: findings render at three weights — heavy box for a hit,
  left rule for informational blocks, a single dim line for skipped sources —
  instead of one box per module.
- `--no-<module>` flags now reach the engine (previously they were parsed but
  ignored); covered by a parametrised test.
- Help and error output follow the active theme.

## [1.0.0] - 2026-09-25

### Added

- First public release of the `emailscope` CLI.
- `identity` module: address validation, provider and disposable-domain
  detection, plus-tag extraction, candidate names and handles, Gravatar hashes.
- `dns` module: MX, NS, A, AAAA, SPF, DMARC, DKIM selector sweep, BIMI.
- `gravatar` module against the Gravatar v3 API, including verified accounts.
- `github` module: commit search by `author-email`, recovering the author's
  real name, linked login and repositories.
- `accounts` module: two-phase probe — handles derived from the address first,
  then re-probed with handles derived from the observed real name.
- Probe registry (`data/sites.json`) with nine verified public endpoints:
  GitHub, GitLab, Mastodon, Bluesky, Keybase, Docker Hub, Hacker News,
  SoundCloud, Linktree.
- `smtp` module: `RCPT TO` verification against the domain's real MX hosts,
  with explicit `exists` / `not_exists` / `unknown` verdicts.
- `reputation` (EmailRep) and `breaches` (HIBP) modules, key-gated and
  self-skipping.
- `dorks` module: 23 ready-to-run search queries across four engines and
  platform-specific `site:` dorks, with `--open` support.
- Rich terminal report plus `--json` and `--markdown` exporters.
- Offline test suite covering parsers, probe classifiers, report rendering and the CLI; Ruff configuration, CI workflow covering
  lint, tests on Python 3.10–3.13 and a wheel data-file check.

