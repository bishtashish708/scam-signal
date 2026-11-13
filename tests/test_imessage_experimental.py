import io
import sqlite3
import tempfile
import time
import unittest
from contextlib import redirect_stderr
from pathlib import Path

import _paths  # noqa: F401
import imessage_scan as im

APPLE_EPOCH_UNIX = 978307200


def _ns_now(offset_days=0):
    return int((time.time() - APPLE_EPOCH_UNIX - offset_days * 86400) * 1e9)


def make_db(path: Path):
    con = sqlite3.connect(path)
    con.executescript("""
    CREATE TABLE handle (ROWID INTEGER PRIMARY KEY, id TEXT);
    CREATE TABLE message (ROWID INTEGER PRIMARY KEY, text TEXT, attributedBody BLOB, handle_id INTEGER,
                          date INTEGER, is_from_me INTEGER, service TEXT);
    CREATE TABLE chat_message_join (chat_id INTEGER, message_id INTEGER);
    """)
    con.execute("INSERT INTO handle VALUES (1, '+15550100001'), (2, '+15550100002')")
    blob = b"\x04\x0bstreamtyped\x81\xe8\x03\x84\x01@\x84\x84\x84\x12NSAttributedString\x00\x84\x84\x08NSObject\x00\x85\x92\x84\x84\x84\x08NSString\x01\x94\x84\x01+" \
        + bytes([len("Toll notice: unpaid balance $3.95, pay at tollpay-center.top".encode())]) \
        + "Toll notice: unpaid balance $3.95, pay at tollpay-center.top".encode() + b"\x86"
    rows = [
        (1, "USPS: package on hold, update at usps-help.top", None, 1, _ns_now(1), 0, "SMS"),  # unknown sender
        (2, None, blob, 1, _ns_now(2), 0, "SMS"),                                              # attributedBody only
        (3, "dinner at 7?", None, 2, _ns_now(1), 0, "iMessage"),                               # known (replied) chat
        (4, "sure!", None, 2, _ns_now(1), 1, "iMessage"),
        (5, "old message", None, 1, _ns_now(40), 0, "SMS"),                                    # outside window
    ]
    con.executemany("INSERT INTO message VALUES (?,?,?,?,?,?,?)", rows)
    con.executemany("INSERT INTO chat_message_join VALUES (?,?)", [(10, 1), (10, 2), (20, 3), (20, 4), (10, 5)])
    con.commit()
    con.close()


class IMessageTests(unittest.TestCase):
    def test_refuses_without_ack(self):
        with redirect_stderr(io.StringIO()):
            self.assertEqual(im.main(["--db", "/nonexistent"]), 2)

    def test_scan_unknown_senders_only_readonly(self):
        with tempfile.TemporaryDirectory() as d:
            db = Path(d) / "chat.db"
            make_db(db)
            before = db.read_bytes()
            msgs = im.scan(db, days=7, limit=50)
            texts = [m["text"] for m in msgs]
            self.assertEqual(len(msgs), 2)
            self.assertTrue(any("usps-help.top" in t for t in texts))
            self.assertTrue(any("tollpay-center.top" in t for t in texts))
            self.assertFalse(any("dinner" in t for t in texts))
            self.assertEqual(before, db.read_bytes())


if __name__ == "__main__":
    unittest.main()
