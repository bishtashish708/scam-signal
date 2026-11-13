import contextlib
import io
import socket
import tempfile
import unittest
from pathlib import Path

import _paths  # noqa: F401
import analyze

FIX = Path(__file__).parent / "fixtures"


class AnalyzeTests(unittest.TestCase):
    def setUp(self):
        # The default path must never touch the network.
        self._orig = socket.socket.connect

        def boom(*a, **k):
            raise AssertionError("network access attempted in offline mode")
        socket.socket.connect = boom

    def tearDown(self):
        socket.socket.connect = self._orig

    def test_bank_impersonation_call(self):
        r = analyze.analyze("He said he was from the Chase fraud department. To protect your money, move your savings "
                            "to a secure account using Zelle. Read me the code we just sent. Don't tell the teller.",
                            channel="call")
        self.assertEqual(r["label"], "scam")
        self.assertEqual(r["typology"]["id"], "bank_impersonation")
        self.assertIn(r["risk_level"], ("high", "very_high"))
        ids = [f["id"] for f in r["red_flags"]]
        self.assertIn("safe_account", ids)
        self.assertIn("otp_request", ids)
        self.assertTrue(all(f["evidence"] for f in r["red_flags"] if not f["id"].startswith(("url:", "email:"))))
        names = " ".join(x["name"] for x in r["report_to"])
        self.assertIn("FTC", names)

    def test_smishing_gets_7726(self):
        r = analyze.analyze("USPS: package on hold, incomplete address. Update within 24 hours: usps-redelivery-help.top/x",
                            channel="sms")
        self.assertEqual(r["typology"]["id"], "delivery_toll_smishing")
        self.assertIn("7726", r["report_to"][0]["name"])

    def test_legit_otp(self):
        r = analyze.analyze("Your Venmo verification code is 482913. Don't share this code with anyone.", channel="sms")
        self.assertEqual(r["label"], "legit")
        self.assertEqual(r["report_to"], [])

    def test_unauthorized_is_fraud_not_scam(self):
        r = analyze.analyze("I saw three Zelle transfers I did not make or authorize. Someone hacked my account.",
                            channel="complaint")
        self.assertEqual(r["label"], "fraud")
        self.assertEqual(r["typology"]["stage1"], "non_consensual_fraud")

    def test_eml_file_and_markdown(self):
        r = analyze.analyze(email_path=str(FIX / "phish_paypal.eml"))
        self.assertEqual(r["label"], "scam")
        md = analyze.to_markdown(r)
        for section in ("**Verdict:**", "## Red flags", "## What to do now", "## Where to report", "FBI IC3"):
            self.assertIn(section, md)

    def test_save_is_redacted(self):
        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / "r.md"
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                analyze.main(["--text", "IRS: you owe taxes, pay with gift cards now or be arrested. My SSN 123-45-6789, "
                              "call me at 555-010-4477", "--save", str(out)])
            saved = out.read_text()
            self.assertNotIn("123-45-6789", saved)
            self.assertNotIn("010-4477", saved)


if __name__ == "__main__":
    unittest.main()
