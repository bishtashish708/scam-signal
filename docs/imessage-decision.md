# Decision: macOS Messages (chat.db) is NOT part of the skill in v0.1

**Status:** decided for MVP; open for the maintainer to revisit.

## Option evaluated
Read `~/Library/Messages/chat.db` (SQLite) to pull recent SMS/iMessage from unknown senders automatically.

## Why not in the skill
1. **Full Disk Access is all-or-nothing per app.** Granting it to Terminal/iTerm/VS Code so a script can read chat.db also lets *every* process launched from that terminal read Mail, Safari history, Photos metadata, etc.
2. **Over-collection.** chat.db holds the user's whole message history, including other people's messages and 2FA codes. A screenshot shares exactly one conversation the user chose.
3. **Portability.** The skill must work in Claude.ai/Cowork, which can't reach a local Mac database. A Mac-only path would make behaviour inconsistent.
4. **Directory eligibility / trust.** A skill that asks users to grant Full Disk Access is a much harder trust ask than "attach a screenshot".
5. **Diminishing returns.** iOS already filters unknown senders and offers "Report Junk"; screenshots cover the same content with one tap.

## What ships instead
`experimental/imessage_scan.py`, outside the skill folder:
- refuses to run without `--i-understand-this-reads-my-messages`;
- opens the DB with SQLite `mode=ro` (read-only), with no copies and no writes;
- reads only **incoming** messages in conversations where the user has **never replied** (unknown senders), within ≤30 days, ≤1000 messages;
- prints JSON lines to stdout only; no network, no files;
- decodes `attributedBody` (macOS 13+) for messages whose `text` column is empty;
- tested only against a **synthetic** database (`tests/test_imessage_experimental.py`). It has never been run against a real chat.db during development.

## Decision needed from the maintainer
- (a) keep as experimental (current), (b) promote to a documented opt-in feature with a dedicated Claude Code command, or (c) remove it entirely.
