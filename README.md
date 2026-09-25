# Email Spy

**A terminal OSINT tool that turns one email address into a readable investigation.**

Give it an address and it answers, in one screen: who is behind it, which
public accounts are tied to it, how the mail infrastructure is configured, and
where else on the open web that address appears.

```
emailspy jane.doe@example.com
```

Python package `emailscope`; `emailscope` is kept as an alias of `emailspy`.
Reports open with the **EMAIL SPY** wordmark under the default `spy` theme —
`--theme classic` brings back the earlier `EMAILSCOPE` look.

Everything it reports comes from **public sources only** — public DNS records,
public profile endpoints, open-source commit history, and public search indexes.
No accounts are created, no credentials are guessed, nothing is brute-forced.

---

## What it collects

| Module | Source | What you get |
| --- | --- | --- |
| `identity` | offline | address validity, provider, disposable-domain flag, plus-tag, **possible real names**, candidate usernames, Gravatar hashes |
| `dns` | public DNS | MX / NS / A / AAAA, SPF, DMARC, DKIM selectors, BIMI, misconfiguration warnings |
| `rdap` | RDAP (`rdap.org`) | registrar, registered / expires / last-changed dates, status flags, nameservers, DNSSEC — **only for the address's own domain**, skipped for free-mail providers |
| `ct` | certspotter | certificate-transparency **subdomains of the address's own domain**, issuance count, first/last certificate date |
| `hosts` | HackerTarget | hostnames and addresses observed for the address's own domain |
| `gravatar` | Gravatar v3 API | display name, location, job title, company, about text, avatar, **verified social accounts linked to the address** |
| `pgp` | keys.openpgp.org | **published OpenPGP key**: fingerprint, user IDs, and the *other* addresses the owner published on the same key (a hit means the address is verified there) |
| `github` | GitHub commit search | **real name from commit metadata**, linked GitHub login when the address is verified, repositories, first/last seen |
| `accounts` | 9 public profile endpoints | which candidate usernames are registered on GitHub, GitLab, Mastodon, Bluesky, Keybase, Docker Hub, Hacker News, SoundCloud, Linktree |
| `mailhost` | RIPEstat + Shodan InternetDB | for the address's own mail servers: **ASN holder**, announced prefix, open ports, **known CVE count**, and the hostnames those IPs also serve |
| `smtp` | the domain's real mail exchangers | `RCPT TO` verification — *mailbox exists / does not exist / unknown* |
| `reputation` | EmailRep *(API key)* | reputation score, first/last seen, deliverability, breach flags, **linked profile list** |
| `breaches` | Have I Been Pwned *(API key)* | breach names, dates, record counts, exposed data classes |
| `dorks` | none | 25 ready-to-run queries (plus two per observed name) across Google, Bing, DuckDuckGo, Yandex, GitHub, Reddit, X, VirusTotal, grep.app and platform-specific `site:` dorks |

`rdap`, `ct`, `hosts` and `mailhost` all describe the address's *own* domain
and mail servers, so they are skipped with a stated reason for free-mail
providers — Google's registration record and Google's open ports are not
evidence about the person behind `someone@gmail.com`.

The address → name → username feedback loop is the important part: the real
name recovered from public commit metadata is fed back into the account probe,
so `matt@mullenweg.com` goes from testing `matt` to also testing
`mattmullenweg`, `m.mullenweg` and `mullenweg`.

---

## Install

Requires Python 3.10+.

```bash
git clone <your-fork-url>
cd emailscope
python -m venv .venv && source .venv/bin/activate
pip install -e .
```

Or straight from PyPI once published:

```bash
pipx install emailscope   # provides `emailspy` and `emailscope`
```

## Quick start

```bash
# full investigation, rich terminal report
emailspy jane.doe@example.com

# machine-readable
emailspy jane.doe@example.com --json -o report.json
emailspy jane.doe@example.com --markdown -o report.md

# offline only — no packets leave your machine except DNS
emailspy jane.doe@example.com --no-accounts --no-smtp --no-gravatar --no-github

# open the generated search queries in your browser
emailspy jane.doe@example.com --open
```

### Example output

```
█████ █   █  ███  █████ █        ████ ████  █   █
█     ██ ██ █   █   █   █       █     █   █  █ █
████  █ █ █ █████   █   █        ███  ████    █
█     █   █ █   █   █   █           █ █       █
█████ █   █ █   █ █████ █████   ████  █       █
CASE 5A5F21                                                 2026-09-25 13:16 UTC
SUBJECT  matt@mullenweg.com
────────────────────────────────────────────────────────────────────
  PROVIDER   mullenweg.com          MAILBOX   unknown
   HANDLES   7 found                  NAMES   Matt Mullenweg
public records only — authorised investigations

│  01  [ INFO  ]  Mail infrastructure                          public DNS
│  no DMARC policy
│    Priority    Mail exchanger
│           0    mullenweg.com

┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
│  05  [ FOUND ]  Candidate accounts                   9 profile endpoints │
│  7 registered handle(s) across 7 platform(s).                        │
│                                                                      │
│    Service        Handle    Profile                                  │
│    Bluesky        @matt     https://bsky.app/profile/matt…           │
└──────────────────────────────────────────────────────────────────────┘
Bluesky @matt   https://bsky.app/profile/matt.bsky.social

 07  skipped     Reputation (EmailRep)  Set EMAILREP_API_KEY to enable…  emailrep.io

────────────────────────────────────────────────────────────────────

FINDINGS 3   SOURCES 9   SKIPPED 2                 CASE 5A5F21    emailspy 1.1.0
```

The header answers the first four questions before you open a block: who owns
the domain, whether a mailbox exists there, how many handles were found, and
what the address resolves to as a name. `MAILBOX` reads `exists` / `does not
exist` / `unknown` / `not checked`, in the colour that means that verdict.

Three tiers carry the hierarchy: a **hit** gets a heavy box in stamp colour,
**info** and **unknown** get a thin left rule, a **skipped** source is a single
dim line. The `[ FOUND ]` stamp is the only filled element on the screen —
every other status is outlined text, so the eye lands on what was actually
found.

The `01`, `02`, … in front of each block is **probe order**, the fixed pipeline
the tool runs (identity → dns → …), not a ranking. Two things on screen are
provenance: the **source** right-aligned on every heading (`public DNS`,
`gravatar.com`, `emailrep.io`), and the subject line split so the third-party
domain reads in a different colour from the part you supplied.

---

## Flags

```
usage: emailspy [-h] [-o FILE] [--json] [--markdown] [--timeout TIMEOUT]
                [--rate-limit SECONDS] [--open] [--no-links] [--link-limit N]
                [--quiet] [--no-color] [--list-modules]
                [--theme {classic,spy}] [--list-themes] [--version]
                [--no-identity] [--no-dns] [--no-rdap] [--no-ct] [--no-hosts]
                [--no-gravatar] [--no-pgp] [--no-github] [--no-accounts]
                [--no-mailhost] [--no-smtp] [--no-reputation] [--no-breaches]
                [--no-dorks]
                [email]
```

| Flag | Effect |
| --- | --- |
| `-o FILE` | write results to a file; `.json` / `.md` choose the format |
| `--json`, `--markdown` | print that format to stdout instead of the rich report |
| `--no-<module>` | skip one module (see `emailspy --list-modules`) |
| `--timeout N` | per-request timeout, seconds (default `12`) |
| `--rate-limit S` | minimum delay between requests to the same host |
| `--open` | open the top 8 generated search links in your default browser |
| `--no-links` / `--link-limit N` | control how many search links are printed (`0` = all) |
| `--quiet` | hide skipped modules |
| `--theme {spy,classic}` | colour scheme and wordmark (default `spy`) |
| `--list-themes` | show each theme's palette and default |
| `--no-color` | disable ANSI colour (also respects `NO_COLOR`) |

**Exit codes:** `0` success · `1` bad usage / invalid address · `2` runtime failure · `130` interrupted.

---

## Themes

Colour is doing work, not decoration:

| token | `spy` | meaning |
| --- | --- | --- |
| signal | `#5AD1C6` | our voice — wordmark, section titles, derived handles |
| stamp | `#FFB020` | a confirmed hit; the only filled background in the report |
| remote | `#79B8FF` | owned by someone else — URLs, hosts, accounts |
| alert | `#FF6B6B` | failure, and a rejected recipient |
| warn | `#FFD166` | we could not tell |
| graphite | `#72808E` | field labels, the neutral `[ INFO ]` status, machine meta |

```bash
emailspy jane.doe@example.com                 # spy (default)
emailspy jane.doe@example.com --theme classic # the earlier EMAILSCOPE palette
emailspy --list-themes
```

The `spy` wordmark is drawn as block glyphs, 49 columns wide; below 49 columns
the report falls back to plain text so nothing is ever truncated.

Themes live in `src/emailscope/theme.py` — one `Theme` dataclass per entry in
`THEMES`, plus `banner_rows()`, which decides whether a wordmark can be drawn
in block glyphs. A theme supplies colours and the wordmark only; layout is
shared, so both themes stay honest about what a colour means. Add a
`Theme(...)`, register it in `THEMES`, and `tests/test_theme.py` will pick it
up.

---

## Optional API keys

Two modules are richer with a key and skip cleanly without one:

```bash
export EMAILREP_API_KEY="..."   # reputation, deliverability, linked profiles
export HIBP_API_KEY="..."       # breach history
```

Get a free key from [EmailRep](https://emailrep.io/) and
[Have I Been Pwned](https://haveibeenpwned.com/API/Key). Keys are read from the
environment only — they are never written to reports or logs.

Unauthenticated quotas are deliberately left alone; EmailRep and HIBP both
reject anonymous traffic now, so EmailScope reports `SKIPPED` instead of
hammering them.

---

## How the account probe works

`src/emailscope/data/sites.json` drives it. Each entry is a public,
unauthenticated endpoint with an explicit exists/missing rule:

```json
{
  "id": "github",
  "name": "GitHub",
  "url": "https://api.github.com/users/{username}",
  "profile": "https://github.com/{username}",
  "exists_status": [200],
  "missing_status": [404]
}
```

Rules supported: `exists_status`/`missing_status` pairs, `missing_body`
(regex, for soft-404 pages), `json_list_nonempty`, `keybase_ok`, `hn_authored`.

Every endpoint in the shipped file was verified against a live account and a
deliberately non-existent handle before being added. To extend it:

1. confirm the endpoint returns **200 + data** for a real handle and
   **404 / empty** for `zqxjwvunotfound991`
2. add the entry, run `pytest tests/test_modules.py`
3. open a PR

Requests are capped (`MAX_JOBS`), throttled per host and run 8-wide. **A hit
means the username is registered — never that it belongs to the owner of the
address.** The report says so on every run.

---

## What this tool will not do

- No password-reset / "forgot password" enumeration — those endpoints exist to
  be rate-limited, and abusing them is account enumeration, not research.
- No credential stuffing, no brute force, no scraping behind logins.
- No search-engine scraping: queries are handed to you as links instead,
  because scraping Google/DDG violates their terms and breaks constantly.
- No guessing. Where the evidence stops, the report says `unknown`, not
  `likely`.

---

## Ethics and legal use

EmailScope aggregates **already public** information. That does not make every
use appropriate.

- Investigate addresses you own, or that you are authorised to look at
  (your own domain, an engagement with written scope, an abuse report you are
  compiling).
- Do not use it to stalk, harass, dox, profile or discriminate against anyone.
- Do not use the output as identity proof — a registered username or a commit
  author name is a lead, not a conclusion.
- Respect the sites you query. The built-in rate limits exist for a reason;
  raise them, don't lower them.

You are responsible for complying with the laws that apply to you (GDPR,
CFAA-equivalents, local privacy statutes) and with the terms of every service
the tool touches.

---

## Development

```bash
make install     # editable install + dev extras
make lint        # ruff check + format check
make test        # pytest
make check       # lint + test
```

Tests are offline by design: parsers, classifiers, report rendering and the
CLI are covered without touching the network. Add live coverage locally with:

```bash
EMAILSCOPE_LIVE=1 pytest -m live
```

### Project layout

```
src/emailscope/
├── cli.py               argparse, flags, output routing
├── engine.py            two-phase orchestrator (collect → name → re-probe)
├── context.py           Options + Context shared by modules
├── http.py              shared async client: retries, backoff, per-host throttle
├── report.py            rich renderer + JSON/Markdown exporters
├── theme.py             colour schemes (spy, classic)
├── models.py            Finding / Case
├── modules/             one file per data source
└── data/                sites.json (probe registry), providers.json
```

---

## Known limitations

- Unauthenticated GitHub search allows 10 requests/minute; a rate-limited run
  reports `SKIP` rather than failing.
- SMTP verification depends on the network allowing outbound port 25. Many
  ISPs and cloud providers block it — the module reports `unknown`, never a
  false negative.
- Provider and disposable-domain lists are curated, not exhaustive.
- Consumer platforms (Instagram, X, TikTok, Facebook) expose no usable
  unauthenticated API; use the generated `site:` dorks for those.

## License

MIT — see [LICENSE](LICENSE).
