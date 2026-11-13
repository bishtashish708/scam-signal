import unittest

import _paths  # noqa: F401
from redact import redact


class RedactTests(unittest.TestCase):
    def test_ssn_card_routing_phone(self):
        t = ("My SSN is 123-45-6789, card 4111 1111 1111 1111, routing 021000021, "
             "call me at (555) 010-4477 or email jane.doe@example.com")
        r = redact(t)
        for secret in ("123-45-6789", "4111 1111 1111 1111", "021000021", "010-4477", "jane.doe@"):
            self.assertNotIn(secret, r)
        self.assertIn("[REDACTED-SSN]", r)
        self.assertIn("[REDACTED-CARD]", r)
        self.assertIn("[REDACTED-ROUTING]", redact("wire to 021000021 today"))
        self.assertIn("[REDACTED-PHONE]", r)
        self.assertIn("j***@example.com", r)

    def test_codes_accounts_dob(self):
        r = redact("Your code is 482913. Account number: 0012345678. DOB: 04/12/1961")
        self.assertNotIn("482913", r)
        self.assertNotIn("0012345678", r)
        self.assertNotIn("04/12/1961", r)

    def test_keeps_indicators(self):
        r = redact("Forward to 7726. Link: https://usps-redelivery.top/track?u=jane@example.com&id=99")
        self.assertIn("7726", r)
        self.assertIn("https://usps-redelivery.top/track?[REDACTED-QUERY]", r)
        self.assertNotIn("jane@example.com", r)

    def test_non_luhn_number_kept(self):
        self.assertIn("1234 5678 9012 3456", redact("order 1234 5678 9012 3456"))


if __name__ == "__main__":
    unittest.main()
