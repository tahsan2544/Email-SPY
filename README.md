# 🕵️ Email Spy

[![CI](https://github.com/tahsan2544/Email-SPY/actions/workflows/ci.yml/badge.svg)](https://github.com/tahsan2544/Email-SPY/actions/workflows/ci.yml)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

**A terminal OSINT tool that turns one email address into a readable investigation.**

Give it an address and it answers, on one screen: **who is behind it**, **which
public accounts are tied to it**, **how the mail infrastructure is configured**,
and **where else on the open web that address appears**.

```bash
emailspy jane.doe@example.com
```

🐍 Python 3.10+ · 📦 package `emailscope` (`emailscope` is an alias of `emailspy`) ·
🗂️ **17 collection modules** · 📤 **5 output formats** · ⚖️ public sources only

Reports open with the **EMAIL SPY** wordmark under the default `spy` theme —
`--theme classic` brings back the earlier `EMAILSCOPE` look.

> Everything it reports comes from **public sources only** — public DNS records,
> public profile endpoints, open-source commit history, public code search and
> public search indexes. **No accounts are created, no credentials are guessed,
> nothing is brute-forced.**

---

## ✨ What you get

- 🧠 **Identity first** — validity, provider, disposable flag, plus-tags, and
  *candidate real names + usernames* derived offline from the address itself.
- 🔗 **A feedback loop** — the real name recovered from public commit metadata
  is fed back into the account probe, so `matt@mullenweg.com` goes from testing
  `matt` to also testing `mattmullenweg`, `m.mullenweg` and `mullenweg`.
- 📌 **Five mandatory accounts** — **Instagram, X, LinkedIn, GitHub and
  YouTube** are probed on every run and reported in their own panel first:
  `exists`, `missing` or an honest `unknown` when the platform blocks the
  check.
- 🏗️ **Infrastructure** — mail exchangers, SPF/DKIM/DMARC/BIMI, domain
  registration, certificate transparency, observed hosts, open ports and known
  CVEs on the mail servers.
- 📣 **Public footprint** — Gravatar profile with its **real avatar picture**,
  signed commits, registered
  handles on 8 more platforms, published PGP keys, and where the address itself
  turns up in public code and discussions (Sourcegraph, Hacker News, Stack
  Exchange).
- 📬 **A real mailbox verdict** — `RCPT TO` verification against the domain's
  actual mail exchangers: *exists / does not exist / unknown*.
- 🕸️ **23 ready-to-run dorks** (plus two per candidate name found) handed over
  as links — the tool never scrapes search engines for you.
- 📤 **Five ways to take the result with you** — terminal, JSON, CSV, Markdown,
  self-contained HTML (see [Outputs](#-outputs--everything-the-tool-can-give-you)).

---

## 📦 Install

Requires **Python 3.10+** — check with `python3 --version`. The commands below
use `python3` on purpose: plenty of systems ship no `python` alias at all.

```bash
git clone <your-fork-url>
cd emailscope
python3 -m venv .venv && source .venv/bin/activate
python3 -m pip install -e .
emailspy --version
```

> ❓ **`emailspy: command not found`?** The virtual environment is not active.
> Run `source .venv/bin/activate` first (`.venv\Scripts\activate` on Windows),
> then try again.

Or straight from PyPI once published:

```bash
pipx install emailscope   # provides `emailspy` and `emailscope`, no venv needed
```

---

## 🚀 Quick start

```bash
# 🖥️ full investigation, rich terminal report
#    ⌨️ on your own terminal it ends with a key menu:
#    j/m/h save JSON/Markdown/HTML · o opens links · q finishes
emailspy jane.doe@example.com

# 🖼️ the address's real Gravatar picture — HTML embeds it;
#    no avatar → the report says so, never a placeholder
emailspy jane.doe@example.com --only identity,gravatar -o avatar.html

# 🤖 machine-readable
emailspy jane.doe@example.com --json -o report.json
emailspy jane.doe@example.com --markdown -o report.md

# 🌐 a self-contained report you can send to someone
#    (no scripts, no fonts, no network — it opens and prints anywhere)
emailspy jane.doe@example.com -o report.html

# 🎯 only the modules you care about
emailspy jane.doe@example.com --only dns,rdap,smtp

# 📌 just the five mandatory accounts (Instagram, X, LinkedIn, GitHub, YouTube)
emailspy jane.doe@example.com --only social

# 🧅 route every request through Tor
emailspy jane.doe@example.com --proxy socks5h://127.0.0.1:9150

# 👥 several addresses at once (progress goes to stderr, output stays clean)
emailspy a@example.com b@example.org --only dns,smtp

# 📄 a whole roster from a file, triaged into a spreadsheet
emailspy --batch roster.txt --csv -o triage.csv

# 🔇 offline only — no packets leave your machine except DNS
emailspy jane.doe@example.com --no-accounts --no-smtp --no-gravatar --no-github

# 🌍 open the generated search queries in your browser
emailspy jane.doe@example.com --open
```

---

## 📤 Outputs — everything the tool can give you

The tool produces **five formats** from the same investigation. Pick one with a
flag, or just name the file extension and let `-o` infer it.

| 🎨 Format | Flag | File extension | Best for |
| --- | --- | --- | --- |
| 🖥️ Rich terminal report | *(default)* | — | Reading the result right now |
| 🤖 JSON | `--json` | `.json` | Scripts, pipelines, further processing |
| 📊 CSV | `--csv` | `.csv` | Spreadsheets — triaging many addresses |
| 📝 Markdown | `--markdown` | `.md`, `.markdown` | Pastebins, PRs, notes, wikis |
| 🌐 HTML | `--html` | `.html`, `.htm` | Sending to someone, printing, archiving |

```bash
emailspy jane.doe@example.com -o report.html   # extension picks the format
emailspy jane.doe@example.com --csv            # format to stdout
```

> 💡 Only **one** format flag at a time — combining two is a usage error.

### 🖥️ 1. Rich terminal report (default)

What you see on screen when you run the tool with no format flag:

- 🏷️ **ASCII wordmark** + `CASE` id + timestamp
- 📌 **`SUBJECT`** line — the part you supplied and the third-party domain in
  different colours
- 🔀 **`EGRESS`** line when `--proxy` is in use (you always know where the
  traffic went)
- 📈 **Summary strip** — `PROVIDER` · `MAILBOX` · `HANDLES` · `NAMES`, the four
  facts you want before opening anything
- 🧾 **One numbered panel per module** with a status stamp, a summary line,
  the detail (rows, tables, verdicts) and the **source right-aligned** on every
  heading so provenance is never ambiguous
- 🔗 **Generated search links** under the panels (limit `12` by default,
  `--link-limit N` or `--no-links` to change, `--open` to launch the top 8)
- 🧮 **Footer counts** — `FINDINGS · SOURCES · SKIPPED · CASE · version`

Statuses, and what they mean:

| Stamp | Meaning |
| --- | --- |
| 🟨 `[ FOUND ]` | Real data was found — the only filled element on screen |
| ⬜ `[ INFO ]` | The module ran and found nothing notable |
| 🟨 `[ UNKNOWN ]` | We could not tell (blocked, deferred, timed out) |
| ⬜ `skipped` | Disabled or missing API key — one dim line, stated reason |
| 🟥 `[ ERROR ]` | That source failed outright |

Add `--quiet` to hide skipped lines, `--no-color` (or `NO_COLOR=1`) for plain text.

### 🤖 2. JSON — the full picture

Everything the terminal shows, machine-readable: run metadata plus every
finding with its raw data and generated links.

```json
{
  "tool": "emailscope",
  "version": "1.11.0",
  "generated_at": "2026-09-25T16:33:36.107415+00:00",
  "email": "john.doe@example.com",
  "findings": [
    {
      "module": "identity",
      "title": "Address",
      "status": "info",
      "summary": "Custom domain (example.com).",
      "data": {
        "email": "john.doe@example.com",
        "valid": true,
        "local_part": "john.doe",
        "domain": "example.com",
        "name_candidates": ["John Doe", "Doe John", "J. Doe", "John D."],
        "handle_candidates": ["john.doe", "johndoe", "jdoe", "johnd", "john_doe"]
      },
      "links": []
    }
  ]
}
```

**One address → this object. Several addresses → a JSON array** of the same
objects. Safe to pipe: progress lines go to **stderr**, stdout carries only JSON.

### 📊 3. CSV — one row per module, per address

A spreadsheet-ready triage sheet. Header is always:

```csv
email,module,status,title,summary,source,links
john.doe@example.com,identity,info,Address,Custom domain (example.com).,offline analysis,
john.doe@example.com,smtp,skip,Deliverability,Disabled.,mail exchangers,
jane@example.org,identity,info,Address,Custom domain (example.org).,offline analysis,
```

The `email` column keeps every row attributable when you stack a whole roster
in one file. Nested detail stays in JSON — CSV is for scanning, JSON is for digging.

### 📝 4. Markdown — notes you can paste anywhere

```markdown
# Email Spy report — `john.doe@example.com`

Generated 2026-09-25 16:33 UTC by emailspy 1.11.0.

## [INFO] Address

Custom domain (example.com).

| Field | Value |
| --- | --- |
| Email | john.doe@example.com |
| Valid | yes |
| Possible names | John Doe, Doe John, J. Doe, John D. |
```

A batch becomes **one Markdown document with a section per address**.

### 🌐 5. HTML — one file you can send or print

`--html` (or a `.html` / `.htm` filename) renders the whole report into a
**single self-contained document**: inline CSS, **no scripts, no webfonts, no
network requests** — it opens from a USB stick, forwards as an email attachment
and prints as a light-mode dossier.

- ✅ Keeps the terminal grammar: status stamps, left-rule panels,
  right-aligned source provenance, the summary strip, the ethics line
- ✅ Embeds the address's **real Gravatar picture** when one exists — the
  bytes are fetched during the run, so the file still shows the face with no
  network; a missing avatar stays missing (no placeholder art)
- ✅ A batch becomes **one file with a section per address**
- ✅ Honours `--theme`
- ✅ WCAG AA contrast, visible focus rings, responsive down to phone width

### ⌨️ After the report — one-key shortcuts

When the rich report finishes on **your own terminal** (interactive, not
piped), a key menu appears under the report:

| Key | Does |
| --- | --- |
| `j` | save the JSON report as `<address>.json` |
| `m` | save the Markdown report as `<address>.md` |
| `h` | save the self-contained HTML report as `<address>.html` |
| `o` | open the top search links in your browser |
| `q` | finish |

Piped output, `--json` / `--csv` / `--markdown` / `--html` runs, and anything
non-interactive never show the menu — a scripted session must never block
waiting for a keypress.

### 📚 Single address vs. batch — what changes

| | 1 address | 2+ addresses (positional or `--batch FILE`) |
| --- | --- | --- |
| 🖥️ Rich report | one report | one report each, separated by a blank line |
| 🤖 JSON | **object** | **array of objects** |
| 📊 CSV | one block of rows | rows for every address, `email` column first |
| 📝 Markdown | one document | sections concatenated into one document |
| 🌐 HTML | one document | one document, `<section>` per address |
| 📣 Progress | none | `investigating addr (2/10)` on **stderr** |

`--batch FILE` reads one address per line; `#` starts a comment, blank lines
are ignored, duplicates are dropped, and **every address is validated before
the first request is sent**.

### 🚪 Exit codes

| Code | Meaning |
| --- | --- |
| `0` | ✅ success |
| `1` | ❌ bad usage, unknown flag/module, invalid address, unreadable batch file |
| `2` | 💥 runtime failure while investigating an address |
| `130` | ⏹️ interrupted (Ctrl-C) |

---

## 🗂️ What it collects

| Module | Source | What you get |
| --- | --- | --- |
| 🧬 `identity` | offline | address validity, provider, disposable-domain flag, plus-tag, **possible real names**, candidate usernames, Gravatar hashes |
| 🌐 `dns` | public DNS | MX / NS / A / AAAA, SPF, DMARC, DKIM selectors, BIMI, misconfiguration warnings |
| 🏛️ `rdap` | RDAP (`rdap.org`) | registrar, registered / expires / last-changed dates, status flags, nameservers, DNSSEC — **only for the address's own domain**, skipped for free-mail providers |
| 📜 `ct` | certspotter | certificate-transparency **subdomains of the address's own domain**, issuance count, first/last certificate date |
| 🔎 `hosts` | HackerTarget | hostnames and addresses observed for the address's own domain |
| 🌍 `urlscan` | urlscan.io | **recent public browser scans of the address's own domain**: scanned page URLs, serving IP, country, HTTP status and scan dates — skipped for free-mail providers |
| 🖼️ `gravatar` | Gravatar v3 API | display name, location, job title, company, about text, **the real avatar picture** (embedded in HTML), **verified social accounts linked to the address** |
| 🔏 `pgp` | keys.openpgp.org | **published OpenPGP key**: fingerprint, user IDs, and the *other* addresses the owner published on the same key (a hit means the address is verified there) |
| ⌨️ `github` | GitHub commit search | **real name from commit metadata**, linked GitHub login when the address is verified, repositories, first/last seen |
| 📌 `social` | instagram + x + linkedin + github + youtube | **the five mandatory accounts** — one `exists` / `missing` / `unknown` verdict per platform for the derived usernames, always its own panel (falls back to `site:` search links when no username can be derived) |
| 🪪 `accounts` | 8 public profile endpoints | which candidate usernames are registered on GitLab, Mastodon, Bluesky, Keybase, Docker Hub, Hacker News, SoundCloud, Linktree |
| 🗣️ `mentions` | Sourcegraph + Hacker News + Stack Exchange | **where the address itself turns up in public code and discussions**: matching repository files with the line that hit, forum posts with dates, and ready-made search links — runs for free-mail addresses too |
| 📡 `mailhost` | RIPEstat + Shodan InternetDB | for the address's own mail servers: **ASN holder**, announced prefix, open ports, **known CVE count**, and the hostnames those IPs also serve |
| 📬 `smtp` | the domain's real mail exchangers | `RCPT TO` verification — *mailbox exists / does not exist / unknown* |
| 📈 `reputation` | EmailRep *(API key)* | reputation score, first/last seen, deliverability, breach flags, **linked profile list** |
| 🚨 `breaches` | Have I Been Pwned *(API key)* | breach names, dates, record counts, exposed data classes |
| 🕸️ `dorks` | none | 23 ready-to-run queries, plus two per candidate name, across Google, Bing, DuckDuckGo, Yandex, GitHub, Reddit, X, VirusTotal, grep.app and platform-specific `site:` dorks |

> 🧠 `rdap`, `ct`, `hosts` and `mailhost` all describe the address's *own* domain
> and mail servers, so they are skipped **with a stated reason** for free-mail
> providers — Google's registration record and Google's open ports are not
> evidence about the person behind `someone@gmail.com`.

---

## 🖥️ Example output

```
█████ █   █  ███  █████ █        ████ ████  █   █
█     ██ ██ █   █   █   █       █     █   █  █ █
████  █ █ █ █████   █   █        ███  ████    █
█     █   █ █   █   █   █           █ █       █
█████ █   █ █   █ █████ █████   ████  █       █
CASE 33252C                                                 2026-09-26 02:01 UTC
SUBJECT  m@mullenweg.com
────────────────────────────────────────────────────────────────────────────────
    PROVIDER   mullenweg.com           MAILBOX   not checked
     HANDLES   none found                NAMES   —
public records only — authorised investigations

│  01  [ INFO  ]  Address                                    offline analysis
│  Custom domain (mullenweg.com).
│  Email            m@mullenweg.com
│  Valid            yes
│  Domain           mullenweg.com
│  Gravatar MD5     767fc9c115a1b989744c755d…

│  02  [ INFO  ]  Mail infrastructure                              public DNS
│  no DMARC policy
│    Priority    Mail exchanger
│           0    mullenweg.com
│  SPF             v=spf1 ip4:96.127.182.10 a mx ?all
│  DKIM selectors  default._domainkey

│  10  [UNKNOWN]  Mandatory accounts      instagram+x+linkedin+github+youtube
│  No candidate usernames to probe — search links provided instead.
│    Platform     Verdict    Username    Profile
│    Instagram    unknown    —           —
│    X            unknown    —           —
│    LinkedIn     unknown    —           —
│    GitHub       unknown    —           —
│    YouTube      unknown    —           —
│  Note  Username registered — association with this address is not proven.

Instagram search   https://www.google.com/search?q=site%3Ainstagram.com+m%40mull
                   enweg.com
X search           https://www.google.com/search?q=site%3Ax.com+OR+site%3Atwitte
                   r.com+m%40mullenweg.com

│  11  [ INFO  ]  Candidate accounts                      8 profile endpoints
│  Local part yields no usable username.

┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
│  12  [ FOUND ]  Public mentions            sourcegraph + hn + stackexchange  │
│  2 code match(es) · 2 post(s)                                               │
│    Repository                           File                                 │
│    github.com/woocommerce/woocommer…    libs/fluxc/src/testFixtures/reso…    │
│    Source         When          Post                                        │
│    hacker news    2010-07-09    I believe I won this one. Drop me an         │
│                                 email at m@mullenweg.com. :)                 │
│  Code hits  2                                                                │
│  Posts      2                                                                │
└──────────────────────────────────────────────────────────────────────────────┘
Sourcegraph search      https://sourcegraph.com/search?q=context%3Aglobal+m%40m…

FINDINGS 1   SOURCES 17   SKIPPED 12              CASE 33252C    emailspy 1.11.0
```

### 📖 How to read it

- **The header answers the first four questions** before you open a block: who
  owns the domain, whether a mailbox exists there, how many handles were found,
  and what the address resolves to as a name. `MAILBOX` reads `exists` /
  `does not exist` / `unknown` / `not checked`, coloured by verdict.
- **Three tiers carry the hierarchy**: a **hit** gets a heavy box in stamp
  colour, **info** and **unknown** get a thin left rule, a **skipped** source is
  a single dim line. The `[ FOUND ]` stamp is the only filled element on the
  screen — your eye lands on what was actually found.
- **`01`, `02`, … is probe order**, the fixed pipeline the tool runs
  (identity → dns → …), **not** a ranking.
- **The mandatory panel never disappears** — Instagram, X, LinkedIn, GitHub
  and YouTube always get a verdict row: `exists` means the username is
  registered, `missing` means the platform confirmed it is not, and `unknown`
  means the platform blocked the check (a bot wall or rate limit), never that
  the account is absent.

An address whose local part is a registered username shows the panel at full
strength (`nasa@example.com` — the username `nasa` exists on four platforms;
LinkedIn's bot wall stays an honest `unknown`):

```
│  10  [ FOUND ]  Mandatory accounts      instagram+x+linkedin+github+youtube  │
│  4 of 5 platforms confirmed: Instagram, X, GitHub, YouTube.                  │
│                                                                              │
│    Platform     Verdict    Username    Profile                               │
│    Instagram    exists     @nasa       https://www.instagram.com/nasa/       │
│    X            exists     @nasa       https://x.com/nasa                    │
│    LinkedIn     unknown    —           —                                     │
│    GitHub       exists     @nasa       https://github.com/nasa               │
│    YouTube      exists     @nasa       https://www.youtube.com/@nasa         │
│                                                                              │
│  Handles Tested  nasa                                                        │
│  Note            Username registered — association with this address is not  │
│                  proven.                                                     │
```
- **Provenance is always on screen**: the source right-aligned on every heading
  (`public DNS`, `gravatar.com`, `emailrep.io`), and the subject line split so
  the third-party domain reads in a different colour from the part you supplied.

---

## 🎨 Themes

Colour is doing work, not decoration:

| token | `spy` | meaning |
| --- | --- | --- |
| signal | `#5AD1C6` | 🗣️ our voice — wordmark, section titles, derived handles |
| stamp | `#FFB020` | 🟨 a confirmed hit; the only filled background in the report |
| remote | `#79B8FF` | 🌐 owned by someone else — URLs, hosts, accounts |
| alert | `#FF6B6B` | ❌ failure, and a rejected recipient |
| warn | `#FFD166` | 🤷 we could not tell |
| graphite | `#72808E` | 🏷️ field labels, the neutral `[ INFO ]` status, machine meta |

```bash
emailspy jane.doe@example.com                 # spy (default)
emailspy jane.doe@example.com --theme classic # the earlier EMAILSCOPE palette
emailspy --list-themes
```

The `spy` wordmark is drawn as block glyphs, 49 columns wide; below 49 columns
the report falls back to plain text so nothing is ever truncated. `classic`
prints its `EMAILSCOPE` wordmark as plain text.

Themes live in `src/emailscope/theme.py` — one `Theme` dataclass per entry in
`THEMES`, plus `banner_rows()`, which decides whether a wordmark can be drawn
in block glyphs. A theme supplies colours and the wordmark only; layout is
shared, so both themes stay honest about what a colour means. Add a
`Theme(...)`, register it in `THEMES`, and `tests/test_theme.py` will pick it
up.

---

## 🧰 All flags

```
usage: emailspy [-h] [--batch FILE] [-o FILE] [--json] [--csv] [--markdown]
                [--html] [--timeout TIMEOUT] [--rate-limit SECONDS] [--open]
                [--no-links] [--link-limit N] [--quiet] [--no-color]
                [--list-modules] [--theme {classic,spy}] [--only MODULES]
                [--proxy URL] [--list-themes] [--version] [--no-identity]
                [--no-dns] [--no-rdap] [--no-ct] [--no-hosts] [--no-urlscan]
                [--no-gravatar] [--no-pgp] [--no-github] [--no-mentions]
                [--no-social] [--no-accounts] [--no-mailhost] [--no-smtp] [--no-reputation]
                [--no-breaches] [--no-dorks]
                [email ...]

Investigate an email address: owner identity, linked accounts, mail infrastructure and public footprint.
```

The real `--help` also ends with copy-paste examples and the ethics line.

| 🚩 Flag | Effect |
| --- | --- |
| `-o FILE` | write results to a file; `.json` / `.md` / `.csv` / `.html` choose the format |
| `--json`, `--markdown`, `--csv`, `--html` | print that format to stdout instead of the rich report; several addresses give a JSON array, concatenated Markdown, one CSV block per address, or a single HTML file with a section per address |
| `--batch FILE` | read more addresses from FILE, one per line (`#` comments) |
| `--only M1,M2` | run only the listed modules (see `emailspy --list-modules`) |
| `--proxy URL` | route every request through a proxy — `socks5h://127.0.0.1:9150` for Tor, `http://127.0.0.1:8080` for a local forwarder |
| `--no-<module>` | skip one module (see `emailspy --list-modules`) |
| `--timeout N` | per-request timeout, seconds (default `12`) |
| `--rate-limit S` | minimum delay between requests to the same host |
| `--open` | open the top 8 generated search links in your default browser |
| `--no-links` / `--link-limit N` | control how many search links are printed (`0` = all) |
| `--quiet` | hide skipped modules |
| `--theme {spy,classic}` | colour scheme and wordmark (default `spy`) |
| `--list-modules` | list the 17 modules (with icons) and exit |
| `--list-themes` | show each theme's palette and default |
| `--no-color` | disable ANSI colour (also respects `NO_COLOR`) |
| `--version` | print the version and exit |

---

## 🔑 Optional API keys

Two modules are richer with a key and skip cleanly without one:

```bash
export EMAILREP_API_KEY="..."   # 📈 reputation, deliverability, linked profiles
export HIBP_API_KEY="..."       # 🚨 breach history
```

Get a free key from [EmailRep](https://emailrep.io/) and
[Have I Been Pwned](https://haveibeenpwned.com/API/Key). Keys are read from the
environment only — they are **never written to reports or logs**.

Unauthenticated quotas are deliberately left alone; EmailRep and HIBP both
reject anonymous traffic now, so EmailScope reports `SKIPPED` instead of
hammering them.

---

## 🔍 How the account probe works

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

## 🚫 What this tool will not do

- ❌ No password-reset / "forgot password" enumeration — those endpoints exist
  to be rate-limited, and abusing them is account enumeration, not research.
- ❌ No credential stuffing, no brute force, no scraping behind logins.
- ❌ No search-engine scraping: queries are handed to you as links instead,
  because scraping Google/DDG violates their terms and breaks constantly.
- ❌ No guessing. Where the evidence stops, the report says `unknown`, not
  `likely`.

---

## ⚖️ Ethics and legal use

EmailScope aggregates **already public** information. That does not make every
use appropriate.

- ✅ Investigate addresses you own, or that you are authorised to look at
  (your own domain, an engagement with written scope, an abuse report you are
  compiling).
- ❌ Do not use it to stalk, harass, dox, profile or discriminate against anyone.
- ⚠️ Do not use the output as identity proof — a registered username or a commit
  author name is a lead, not a conclusion.
- 🤝 Respect the sites you query. The built-in rate limits exist for a reason;
  raise them, don't lower them.

You are responsible for complying with the laws that apply to you (GDPR,
CFAA-equivalents, local privacy statutes) and with the terms of every service
the tool touches.

---

## ❓ FAQ

**Does it work on Gmail / Outlook / Yahoo addresses?**
Yes — `identity`, `dns` (of the MX host), `gravatar`, `pgp`, `github`,
`accounts`, `mentions`, `smtp` and `dorks` all run. The *domain-scoped* modules
(`rdap`, `ct`, `hosts`, `urlscan`, `mailhost`) skip with a reason: Google's
registration record is not evidence about you.

**Does it send mail, log in, or touch the mailbox?**
No. The only mailbox interaction is an `RCPT TO` question to the domain's own
mail server — the same check any mail server does before accepting a message.

**Will it tell me who an address belongs to?**
It gives you **evidence, not verdicts**: names recovered from commit metadata,
registered handles, linked profiles, published keys. What you conclude from
that is yours to defend — the report deliberately says `unknown` where the
evidence stops.

**Why is something `skipped` or `unknown`?**
Because the tool states its limits instead of guessing: no API key (reputation,
breaches), provider policy (free-mail domain modules), or the network
refused the request (rate limits, blocked port 25). Each skip line carries the
reason.

**Can I run it offline?**
Mostly: `--only identity,dorks` needs no network at all, and `--no-*` flags
let you cut everything else. DNS lookups still go out unless you skip `dns`.

**Is it fast?**
Modules run concurrently with retries, backoff and a per-host throttle; a full
17-module run of one address takes around 20 seconds against a cooperative
domain, and a `--batch` run reports `n/N` progress on stderr as it goes.

---

## 🛠️ Development

```bash
make install     # editable install + dev extras
make lint        # ruff check + format check
make test        # pytest
make check       # lint + test
make build       # sdist + wheel into dist/
```

Tests are offline by design: parsers, classifiers, report rendering and the
CLI are covered without touching the network. Add live coverage locally with:

```bash
EMAILSCOPE_LIVE=1 pytest -m live
```

### 📂 Project layout

```
src/emailscope/
├── cli.py               argparse, flags, output routing
├── engine.py            two-phase orchestrator (collect → name → re-probe)
├── context.py           Options + Context shared by modules
├── http.py              shared async client: retries, backoff, per-host throttle
├── report.py            rich renderer + JSON/Markdown/CSV exporters
├── htmlreport.py        self-contained HTML export (same grammar, prints cleanly)
├── theme.py             colour schemes (spy, classic)
├── models.py            Finding / Case
├── modules/             one file per data source
└── data/                sites.json (probe registry), providers.json
```

---

## ⚠️ Known limitations

- Unauthenticated GitHub search allows 10 requests/minute; a rate-limited run
  reports `SKIP` rather than failing.
- SMTP verification depends on the network allowing outbound port 25. Many
  ISPs and cloud providers block it — the module reports `unknown`, never a
  false negative.
- Provider and disposable-domain lists are curated, not exhaustive.
- Consumer platforms defend hard, so the mandatory panel stays honest about
  what it can prove: X and YouTube answer a clean 200/404, Instagram serves
  soft-404 pages (detected via the profile's `og:title` marker), and LinkedIn
  frequently answers `999` or resets the connection — those cases report
  `unknown`, never a false "not found". TikTok and Facebook still have no
  usable unauthenticated endpoint; use the generated `site:` dorks for them.
- Archive indexes were tested and left out: the Wayback CDX API answers in
  3–60s (sometimes 503) and Common Crawl in 10s+, which is not acceptable
  latency for a module that also has to stay polite about rate limits.
- Text-search sources were tested live and rejected for the same reason:
  grep.app sits behind a Vercel bot challenge (429), Reddit returns 403 to
  non-browser clients, and psbdmp does not answer at all.
- Terminals cannot draw pictures portably, so the **terminal report links the
  avatar** instead of inlining it — the HTML report embeds the actual image.
  When the address has no avatar the report says
  `No Gravatar account for this address.` A blocked or non-image response is
  never counted as a picture. No placeholder faces, ever.

---

## 📄 License

MIT — see [LICENSE](LICENSE).
