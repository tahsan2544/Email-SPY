# 🔒 Security Policy

## Reporting a vulnerability

Please use **GitHub private vulnerability reporting** on this repository, or
open a private contact with the maintainers. Do not file a public issue for
something that could expose user data.

We aim to acknowledge within 72 hours and to ship a fix or a mitigation for
confirmed issues within 14 days.

## What counts

- Any path where EmailScope writes an API key, environment value or address
  list into a report, log or exception message.
- Any path where a probe response is rendered unescaped into a terminal in a
  way that permits ANSI injection from remote content.
- Any module that widens collection beyond what the README documents.
- Supply-chain issues in the dependency set.

## What does not

- "This tool found information about me that is public." Aggregating public
  records is the documented purpose; see the ethics section of the README.
- A third-party service changing its response shape — report those as bugs.

## Handling of credentials

- API keys are read from the environment (`EMAILREP_API_KEY`, `HIBP_API_KEY`).
- Keys are never written to stdout, files, or exception text.
- Do not commit `.env` files. `.env` is gitignored; ship `.env.example` only.

## Supported versions

| Version | Supported |
| --- | --- |
| 1.x | yes |
| < 1.0 | no |
