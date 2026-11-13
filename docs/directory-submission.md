# Anthropic plugin directory: submission prep

Status: **prepared, not submitted.** The maintainer submits from the developer portal.

Official process: [Submit your plugin](https://claude.com/docs/plugins/submit) and the [pre-submission checklist](https://claude.com/docs/plugins/pre-submission-checklist). Plugins are submitted from a GitHub repo through the developer portal at **claude.ai/directory/manage** → **Submit new** → **Plugin bundle**. The older Claude Console form is retired.

## Source step

| Field | Value |
|---|---|
| Repository | `bishtashish708/scam-signal` |
| Plugin path | *(empty: `.claude-plugin/plugin.json` is at the repo root)* |
| Branch or tag | *(empty: follows `main`)*, or a release tag (e.g. `v0.2.0`) to pin it |

Then select **Validate**. Fix anything marked **Blocking**, push, and select **Re-validate**.

## Self-check against the checklist

| Check | Status |
|---|---|
| `claude plugin validate .` | ✔ passes, no warnings |
| Name: lowercase/digits/hyphens, distinctive, not a reserved word or brand | `scam-signal` ✔ |
| `description`, `author`, `version` set | ✔ |
| README ≥ 40 words, LICENSE present, `license` in plugin.json | ✔ MIT |
| No `.DS_Store` / `__MACOSX`; no symlinks, submodules or LFS | ✔ (caches and `dist/` are gitignored) |
| Non-image files < 256 KiB; ≤ 512 files; only text + PNG/GIF | ✔ (`docs/demo.gif` is an image) |
| Skills-only: no hooks, MCP servers, launchers (`npx`/`uvx`/`uv run`), lockfiles or package installs | ✔ |
| Valid SKILL.md front matter; `description` is a single string | ✔ |
| No credentials anywhere | ✔ (synthetic data only; a CI guard rejects non-555 phone numbers in eval data) |
| Readable source, nothing minified or compiled | ✔ |
| README discloses everything the plugin runs, sends or fetches | ✔ see "Privacy" in the README and [`PRIVACY.md`](../PRIVACY.md) |

**Possible reviewer questions.** None of these block submission.
- `experimental/imessage_scan.py` ships in the plugin folder, because the plugin folder is the repo root. It isn't referenced by `SKILL.md`, it requires an explicit `--i-understand-this-reads-my-messages` flag, it opens `chat.db` read-only, and it makes no network calls. If a reviewer prefers, the skill can move to a subfolder plugin path so that `experimental/`, `tests/` and `evals/` aren't installed.
- Three optional, off-by-default network lookups exist in `url_check.py`, each sending at most a domain or short URL:
  - RDAP to rdap.org;
  - a HEAD request to known URL shorteners;
  - feed downloads from OpenPhish and URLhaus.
  They're disclosed in the README, PRIVACY.md and SKILL.md, and Claude asks before using them.

## Listing details

These are read from `plugin.json` and the README:
- **Name:** scam-signal
- **Short description:** the `description` from plugin.json
- **Category (marketplace.json):** security
- **Docs / support / privacy:** README · GitHub Issues · PRIVACY.md

## Data handling answers (draft for the maintainer to confirm)

| Question | Draft answer |
|---|---|
| Reads or stores personal data? | **Reads** what the user chooses to share: a message, screenshot or file, or a bounded read-only window of mail through the user's own connector. **Stores nothing**, unless the user asks to save a report, which is written PII-redacted to a path they choose. |
| Sends data to services other than declared connectors? | **Not by default.** Optional, user-approved lookups send only a bare domain (rdap.org) or a short URL (to the shortener itself). Phishing feeds are downloaded and matched locally. No telemetry. |
| Retention | None. There are no servers. The optional feed cache (`~/.cache/scam-signal`, 6h TTL) contains only public feed data. |
| Intended for under-18s? | No. It's a general consumer-protection tool and not directed at minors. |

## Compliance step

- **Contact email:** the maintainer confirms it in the portal. It isn't stored in this repo.
- **Acknowledgements:** the maintainer must select all four acknowledgements personally.

## Evidence for reviewers

- Rule-engine evals, plus a 15-prompt live LLM check covering trigger, no-trigger, refusal and stress cases: [`evals/RESULTS.md`](../evals/RESULTS.md)
- Ethics / refusal policy: README → Ethics, SKILL.md → Hard rules
