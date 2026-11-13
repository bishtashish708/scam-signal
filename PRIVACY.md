# Privacy

scam-signal collects nothing. There is no telemetry, analytics, account, or server.

## Where analysis happens
- **Claude Code / CLI:** helper scripts run on your machine (Python standard library).
- **Claude.ai / Cowork:** inside your own Claude session and its code-execution sandbox, under your account's existing data terms.

## Network access (all optional, all off by default)
| Flag | What is sent | To whom |
|---|---|---|
| `--rdap` | the bare registrable domain (e.g. `example-login.top`) | rdap.org (public RDAP bootstrap → the registry) |
| `--expand` | the short URL, via an HTTP HEAD request; stops before contacting the final destination | the URL-shortener service |
| `--phish-feeds` | nothing about your URL; the feeds are downloaded and matched locally (cached for 6 hours in `~/.cache/scam-signal`) | openphish.com, urlhaus.abuse.ch |

The skill instructs Claude to ask before using any of these and never to open, fetch or screenshot a suspicious link itself.

## Email connectors
Inbox triage uses whatever Gmail/Outlook connector *you* have enabled in Claude. The skill is read-only (search + read), bounded (default 7 days / 50 messages; it asks before widening), and never replies, deletes, archives, labels or unsubscribes unless you explicitly ask.

## Saved reports
`analyze.py --save` and `redact.py` remove SSNs, card/account/routing/IBAN numbers, phone numbers, one-time codes, dates of birth, street addresses, email local parts and URL query strings. Domains and URL paths are kept as scam indicators.

## macOS Messages
Not read by the skill. See `docs/imessage-decision.md` for the opt-in experimental script and its trade-offs.
