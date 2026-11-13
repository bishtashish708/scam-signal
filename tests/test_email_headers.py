import unittest
from pathlib import Path

import _paths  # noqa: F401
import email_headers as eh
from cfb_writer import utf16, write_cfb

FIX = Path(__file__).parent / "fixtures"


def flags(rep):
    return {f.flag for f in rep.findings}


class EmlTests(unittest.TestCase):
    def test_phish(self):
        rep = eh.analyze_message(eh.load(str(FIX / "phish_paypal.eml")))
        f = flags(rep)
        # topmost Authentication-Results wins over the forged one below it
        self.assertEqual(rep.auth["dmarc"], "fail")
        for expected in ("dmarc_fail", "spf_fail", "reply_to_mismatch", "display_name_impersonation",
                         "sender_lookalike_domain", "link_text_mismatch", "risky_attachment"):
            self.assertIn(expected, f)
        self.assertNotIn("authenticated_sender", f)
        self.assertIn("Secure_Message.html", rep.attachments)

    def test_legit(self):
        rep = eh.analyze_message(eh.load(str(FIX / "legit_amazon.eml")))
        self.assertIn("authenticated_sender", flags(rep))
        self.assertFalse([x for x in rep.findings if x.severity == "high"])
        self.assertTrue(rep.urls[0].startswith("https://www.amazon.com"))

    def test_raw_headers_only(self):
        raw = b"From: IRS Refund Dept <refunds.irs@gmail.com>\nSubject: Tax refund pending\n\nClaim your refund."
        rep = eh.analyze_message(eh.email.message_from_bytes(raw, policy=eh.email.policy.default))
        self.assertIn("display_name_impersonation", flags(rep))


class MsgTests(unittest.TestCase):
    def _msg(self, big_body=False):
        headers = ("From: \"Chase Security\" <alerts@chase-secure-verify.top>\r\n"
                   "Reply-To: help@verify-desk.example\r\nSubject: Account locked\r\n"
                   "Authentication-Results: mx.example; dmarc=fail header.from=chase-secure-verify.top\r\n")
        body = "Your account has been locked. Verify your identity at https://chase-secure-verify.top/login"
        if big_body:
            body += " " + "padding " * 900  # > 4096 bytes in UTF-16 -> regular FAT path
        return write_cfb({
            "__substg1.0_007D001F": utf16(headers),
            "__substg1.0_1000001F": utf16(body),
            "__substg1.0_0037001F": utf16("Account locked"),
            "__attach_version1.0_#00000000": {"__substg1.0_3707001F": utf16("unlock_form.html"),
                                              "__substg1.0_37010102": b"<html>x</html>"},
        })

    def test_cfb_roundtrip(self):
        st = eh.read_cfb(self._msg())
        self.assertIn("__substg1.0_007D001F", st)
        self.assertIn("__attach_version1.0_#00000000/__substg1.0_3707001F", st)

    def test_msg_analysis_mini_and_big(self):
        for big in (False, True):
            rep = eh.analyze_message(eh.msg_to_message(self._msg(big)))
            f = flags(rep)
            self.assertEqual(rep.from_domain, "chase-secure-verify.top")
            self.assertIn("dmarc_fail", f)
            self.assertIn("reply_to_mismatch", f)
            self.assertIn("risky_attachment", f)
            self.assertIn("locked", rep.body_text)

    def test_not_cfb(self):
        with self.assertRaises(ValueError):
            eh.read_cfb(b"not an ole file at all")


if __name__ == "__main__":
    unittest.main()
