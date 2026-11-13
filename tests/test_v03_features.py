"""Tests for v0.3.0 (independent review P1 items)."""
import json
import unittest

import chat_export

import _paths  # noqa: F401
import analyze
import redact
import taxonomy
import url_check

PIG_IOS = """[1/3/26, 9:02:11 PM] Amy: Hi, is this Kevin? We were supposed to meet for golf on Saturday
[1/3/26, 9:15:40 PM] You: Sorry, wrong number
[1/3/26, 9:16:02 PM] Amy: Oh so sorry! Nice to meet you anyway. I'm from Seattle, what do you do?
[1/9/26, 7:30:12 PM] Amy: My uncle taught me crypto contract trading, I made 30% this week
[1/12/26, 6:10:00 PM] Amy: Download the app and register, customer service will guide you to deposit USDT
[1/20/26, 9:05:00 PM] Amy: You must pay 20% personal income tax before withdrawal, your account is frozen until then"""

TASK_ANDROID = """2/1/26, 10:02 - Rachel HR: Hello! I'm Rachel from a staffing agency, we have a flexible remote position with daily salary
2/1/26, 10:05 - Me: what is the job?
2/1/26, 10:07 - Rachel HR: You rate products in our app and earn commission on each task, very simple
2/3/26, 18:40 - Rachel HR: You got a lucky combo order! Please recharge 300 USDT to complete it and withdraw your earnings"""

TG_TEXT = """Maria, [05.02.26 20:11]
my love I miss you so much, you are my soulmate
Maria, [06.02.26 09:30]
I am stuck at customs in Lagos, they are holding my package
Maria, [06.02.26 09:31]
please send me $1,500 by gift cards so I can pay the clearance fee"""

LEGIT_ANDROID = """1/14/26, 21:02 - Sam: hey are we still on for dinner friday?
1/14/26, 21:05 - Jo: yes! 7pm
1/15/26, 08:00 - Sam: can you zelle me $40 for your half of the tickets
1/15/26, 08:10 - Jo: done"""


class ChatExports(unittest.TestCase):
    def test_formats_parse(self):
        self.assertEqual(len(chat_export.parse(PIG_IOS)), 6)
        self.assertEqual(len(chat_export.parse(TASK_ANDROID)), 4)
        self.assertEqual(len(chat_export.parse(TG_TEXT)), 3)
        tg_json = json.dumps({"messages": [{"type": "message", "date": "2026-02-05T20:11:00", "from": "Maria", "text": t}
                                           for t in ("hi", "my love", ["send ", {"type": "bold", "text": "money"}])]})
        msgs = chat_export.parse(tg_json)
        self.assertEqual(msgs[-1].text, "send money")

    def test_not_a_chat(self):
        self.assertEqual(chat_export.parse("USPS: your package is on hold. Pay $1.99 now."), [])

    def test_stage_progressions(self):
        for text, typ in [(PIG_IOS, "investment_crypto"), (TASK_ANDROID, "employment_task"), (TG_TEXT, "romance")]:
            r = analyze.analyze(text)
            self.assertEqual(r["label"], "scam", typ)
            self.assertEqual(r["typology"]["id"], typ)
            self.assertIn("chat_progression", [f["id"] for f in r["red_flags"]], typ)
            self.assertEqual(r["channel"], "chat")

    def test_legit_chat(self):
        r = analyze.analyze(LEGIT_ANDROID)
        self.assertEqual(r["label"], "legit")
        self.assertNotIn("chat_progression", [f["id"] for f in r["red_flags"]])


class NewTypologies(unittest.TestCase):
    def test_bec_not_delivery(self):
        r = analyze.analyze("Hi, please note our bank details have changed. Kindly remit the outstanding invoice #4471 "
                            "to the new account below and do not use the old account.", channel="email")
        self.assertEqual(r["typology"]["id"], "bec_payment_redirect")

    def test_qr_and_invoice(self):
        self.assertEqual(analyze.analyze("Parking enforcement: unpaid parking fine. Scan the QR code to pay now and avoid towing.")["typology"]["id"], "qr_phishing")
        r = analyze.analyze("PayPal invoice #INV-2291: you were billed $499.00 for a crypto purchase. If you did not authorize this, call 555-0161 to cancel.")
        self.assertEqual(r["typology"]["id"], "fake_invoice")

    def test_safe_account_stays_bank_impersonation(self):
        r = analyze.analyze("This is your bank's fraud department. Your account is compromised, move your savings to a new secure account today.")
        self.assertEqual(r["typology"]["id"], "bank_impersonation")

    def test_all_types_have_mappings(self):
        for k, v in taxonomy.TYPOLOGY.items():
            for f in ("name", "stage1", "ftc", "ic3", "cfpb", "summary"):
                self.assertIn(f, v, k)


class UrlAdditions(unittest.TestCase):
    def test_obfuscated_ips(self):
        for u, ip in [("http://0x7f000001/login", "127.0.0.1"), ("http://3232235777/x", "192.168.1.1"),
                      ("http://0300.0250.0.1/", "192.168.0.1")]:
            r = url_check.analyze_url(u)
            self.assertIn("obfuscated_ip_host", [f.flag for f in r.findings], u)
            self.assertIn(ip, " ".join(f.evidence for f in r.findings))

    def test_messaging_handoff(self):
        for u in ("https://t.me/crypto_mentor_amy", "https://wa.me/15550100", "https://chat.whatsapp.com/AbC"):
            r = url_check.analyze_url(u)
            self.assertEqual([f.flag for f in r.findings], ["messaging_handoff"], u)
        self.assertEqual(url_check.analyze_url("https://www.whatsapp.com/download").official_brand, "whatsapp")

    def test_uk_brand_lookalike(self):
        self.assertIn("brand_in_unofficial_domain", [f.flag for f in url_check.analyze_url("https://hmrc-refund-claim.top").findings])


class Countries(unittest.TestCase):
    def test_guess(self):
        self.assertEqual(taxonomy.guess_country("HMRC: you are owed a tax refund of £312"), "uk")
        self.assertEqual(taxonomy.guess_country("Your SBI KYC is pending, share OTP, else UPI blocked"), "in")
        self.assertIsNone(taxonomy.guess_country("Your package is on hold"))

    def test_report_links_follow_country(self):
        r = analyze.analyze("HMRC: you are owed a tax refund of £312. Claim now at hmrc-refund-claim.top before it expires today")
        self.assertEqual(r["country"]["code"], "uk")
        self.assertTrue(any("7726" in x["name"] for x in r["report_to"]))
        r = analyze.analyze("Your account is blocked. Share the OTP with our officer to keep it active.", country="in")
        self.assertTrue(any("1930" in x["name"] for x in r["report_to"]))

    def test_unclear_country_says_so(self):
        r = analyze.analyze("Your package is on hold. Pay the $1.99 redelivery fee at parcel-redeliver.top within 12 hours")
        self.assertEqual(r["country"]["source"], "assumed")
        self.assertIn("Tell me your country", r["country"]["note"])


def _aadhaar_like() -> str:
    for d in range(10):
        if redact._verhoeff_ok("23456789012" + str(d)):
            return "23456789012" + str(d)
    raise AssertionError


class RedactionAdditions(unittest.TestCase):
    def test_international_and_ids(self):
        a = _aadhaar_like()
        t = (f"+44 20 7946 0958, 07700 900123, +91 98765 43210, 98765 43210, +61 4 1234 5678. "
             f"Aadhaar {a[:4]} {a[4:8]} {a[8:]}. PAN ABCPE1234F. SW1A 1AA. "
             "seed phrase: abandon ability able about above absent absorb abstract absurd abuse access accident. "
             "key 0x" + "ab" * 32)
        out = redact.redact(t)
        for leak in ("7946", "900123", "43210", "1234 5678", a[8:], "ABCPE1234F", "SW1A", "abandon", "abab"):
            self.assertNotIn(leak, out, leak)
        self.assertIn("[REDACTED-SEED-PHRASE]", out)
        self.assertIn("[REDACTED-AADHAAR]", out)

    def test_keeps_indicators(self):
        out = redact.redact("Flight UA1432 departs 4:35pm. Visit hmrc-refund-claim.top. Amount $1,250.00.")
        for keep in ("UA1432", "hmrc-refund-claim.top", "$1,250.00"):
            self.assertIn(keep, out)


if __name__ == "__main__":
    unittest.main()
