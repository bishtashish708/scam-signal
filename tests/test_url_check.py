import unittest

import _paths  # noqa: F401
import url_check as uc


def flags(u):
    return {f.flag for f in uc.analyze_url(u).findings}


class UrlTests(unittest.TestCase):
    def test_lookalikes(self):
        self.assertIn("lookalike_domain", flags("https://paypa1-secure.com/login"))
        self.assertIn("lookalike_domain", flags("https://www.c0stco.com"))
        self.assertIn("lookalike_domain", flags("https://amaz0n-refunds.com"))

    def test_punycode(self):
        f = flags("https://xn--pypal-4ve.com")
        self.assertIn("internationalized_domain", f)
        self.assertIn("lookalike_domain", f)

    def test_brand_in_wrong_domain(self):
        self.assertIn("brand_in_unofficial_domain", flags("paypal.com.account-verify.info/x"))
        self.assertIn("brand_in_unofficial_domain", flags("https://tracking.ups-help.com"))
        self.assertTrue({"brand_in_unofficial_domain", "lookalike_domain"} & flags("https://wellsfargo.com.co"))

    def test_tricks(self):
        self.assertIn("userinfo_trick", flags("https://secure.chase.com@evil.example.net/"))
        self.assertIn("ip_address_host", flags("http://192.168.4.4/x"))
        self.assertIn("url_shortener", flags("https://bit.ly/3abc"))
        self.assertIn("generic_form_host", flags("https://sites.google.com/view/wellsfargo-unlock"))
        self.assertIn("direct_file_download", flags("https://files.example.net/invoice.zip"))

    def test_official_not_flagged(self):
        for u in ("https://www.chase.com/alerts", "https://tools.usps.com/go/Track", "https://www.ups.com/track",
                  "https://www.amazon.com/gp/your-account", "https://www.irs.gov/payments"):
            r = uc.analyze_url(u)
            self.assertIsNotNone(r.official_brand, u)
            self.assertFalse([f for f in r.findings if f.severity == "high"], u)

    def test_no_short_brand_substring_false_positive(self):
        self.assertFalse(flags("https://matter.com/groups") - {"no_https"})

    def test_extract_and_refang(self):
        urls = uc.extract_urls("go to hxxps://evil[.]top/x now, or email me at bob@chase.com")
        self.assertEqual(urls, ["https://evil.top/x"])
        self.assertIn("usps-redelivery-help.top/track", uc.extract_urls("visit usps-redelivery-help.top/track."))

    def test_registrable(self):
        self.assertEqual(uc.registrable("a.b.example.co.uk"), "example.co.uk")
        self.assertEqual(uc.registrable("secure.chase.com"), "chase.com")


if __name__ == "__main__":
    unittest.main()
