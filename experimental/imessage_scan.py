#!/usr/bin/env python3
"""EXPERIMENTAL, OPT-IN: scan recent macOS Messages (iMessage/SMS) from unknown senders.

This is deliberately NOT part of the scam-signal skill. Read docs/imessage-decision.md first.

What it does
  * Opens ~/Library/Messages/chat.db READ-ONLY (sqlite URI mode=ro). Never writes to it.
  * Looks only at incoming messages from the last N days (default 7, max 30)
    in conversations where you have NEVER sent a message, i.e. unknown senders.
  * Prints them as JSON lines to stdout so you can pipe them to analyze.py.
  * Writes nothing to disk and makes no network requests.

What it needs
  * macOS Full Disk Access for the terminal app you run it from
    (System Settings > Privacy & Security > Full Disk Access). That permission
    applies to EVERYTHING launched from that terminal, so consider granting it
    only temporarily and revoking it afterwards.

Usage
    python3 experimental/imessage_scan.py --i-understand-this-reads-my-messages --days 7 \
      | python3 experimental/imessage_scan.py --analyze
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import sqlite3
import sys
from pathlib import Path

APPLE_EPOCH = dt.datetime(2001, 1, 1, tzinfo=dt.timezone.utc)
DEFAULT_DB = Path.home() / "Library" / "Messages" / "chat.db"


def decode_attributed_body(blob: bytes | None) -> str | None:
    """Extract the plain string from an NSAttributedString typedstream blob (macOS 13+)."""
    if not blob or b"NSString" not in blob:
        return None
    try:
        rest = blob.split(b"NSString", 1)[1][5:]
        if rest[0] == 0x81:
            n = int.from_bytes(rest[1:3], "little")
            raw = rest[3:3 + n]
        else:
            n = rest[0]
            raw = rest[1:1 + n]
        return raw.decode("utf-8", "replace")
    except Exception:
        return None


def apple_ts(value: int) -> dt.datetime:
    # Modern macOS stores nanoseconds since 2001-01-01; old versions stored seconds.
    secs = value / 1e9 if value > 10**11 else value
    return APPLE_EPOCH + dt.timedelta(seconds=secs)


def scan(db_path: Path, days: int, limit: int) -> list[dict]:
    uri = f"file:{db_path}?mode=ro"
    con = sqlite3.connect(uri, uri=True)
    con.row_factory = sqlite3.Row
    since = dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=days)
    since_ns = int((since - APPLE_EPOCH).total_seconds() * 1e9)
    rows = con.execute(
        """
        SELECT m.ROWID AS id, m.text, m.attributedBody, m.date, m.service, h.id AS sender, cmj.chat_id
        FROM message m
        JOIN chat_message_join cmj ON cmj.message_id = m.ROWID
        LEFT JOIN handle h ON h.ROWID = m.handle_id
        WHERE m.is_from_me = 0
          AND m.date >= ?
          AND cmj.chat_id NOT IN (
              SELECT cmj2.chat_id FROM chat_message_join cmj2
              JOIN message m2 ON m2.ROWID = cmj2.message_id
              WHERE m2.is_from_me = 1)
        ORDER BY m.date DESC
        LIMIT ?
        """,
        (since_ns, limit),
    ).fetchall()
    con.close()
    out = []
    for r in rows:
        text = r["text"] or decode_attributed_body(r["attributedBody"])
        if not text:
            continue
        out.append({"id": r["id"], "sender": r["sender"], "service": r["service"],
                    "date": apple_ts(r["date"]).isoformat(timespec="minutes"), "text": text})
    return out


def analyze_stdin() -> int:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "skills" / "scam-signal" / "scripts"))
    import analyze  # noqa: E402
    print("| date | sender | verdict | type | top flag |\n|---|---|---|---|---|")
    for line in sys.stdin:
        if not line.strip():
            continue
        m = json.loads(line)
        res = analyze.analyze(m["text"], channel="sms")
        top = res["red_flags"][0]["label"] if res["red_flags"] else "-"
        print(f"| {m['date']} | {m['sender']} | {res['verdict']} | {res['typology'].get('id')} | {top} |")
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--i-understand-this-reads-my-messages", dest="ack", action="store_true")
    ap.add_argument("--days", type=int, default=7)
    ap.add_argument("--limit", type=int, default=200)
    ap.add_argument("--db", default=os.environ.get("SCAM_SIGNAL_CHAT_DB", str(DEFAULT_DB)))
    ap.add_argument("--analyze", action="store_true", help="read JSON lines from stdin and print a verdict table")
    a = ap.parse_args(argv)
    if a.analyze:
        return analyze_stdin()
    if not a.ack:
        print("Refusing to run without --i-understand-this-reads-my-messages. See docs/imessage-decision.md.", file=sys.stderr)
        return 2
    days = max(1, min(a.days, 30))
    try:
        msgs = scan(Path(a.db), days, max(1, min(a.limit, 1000)))
    except sqlite3.OperationalError as e:
        print(f"Could not open Messages database read-only ({e}). On macOS this usually means the terminal "
              "lacks Full Disk Access.", file=sys.stderr)
        return 1
    for m in msgs:
        print(json.dumps(m, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
