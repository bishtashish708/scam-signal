#!/usr/bin/env python3
"""PII redaction for scam-signal reports (stdlib only).

Used before anything is written to disk. It masks the *victim's* personal data
(SSNs, card numbers, bank account/routing numbers, phone numbers, email local
parts, one-time codes, dates of birth, street addresses) and keeps the *scam
indicators* that make the report useful (sender domains, URLs with their query
strings stripped, 5-6 digit SMS short codes).

Usage:
    python3 redact.py < report.md > report.redacted.md
    python3 redact.py --file report.md
"""
from __future__ import annotations

import argparse
import re
import sys

# --- validators -------------------------------------------------------------


def _luhn_ok(digits: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def _aba_ok(digits: str) -> bool:
    """ABA routing-number checksum (3-7-1 weighting)."""
    if len(digits) != 9:
        return False
    w = [3, 7, 1] * 3
    return sum(int(c) * k for c, k in zip(digits, w)) % 10 == 0


# --- patterns ---------------------------------------------------------------

SSN = re.compile(r"\b(?!000|666|9\d\d)\d{3}[- ](?!00)\d{2}[- ](?!0000)\d{4}\b")
SSN_LABELED = re.compile(r"(?i)\b(ssn|social security(?: number| no\.?)?)\s*[:#]?\s*\d{9}\b")
CARD = re.compile(r"\b(?:\d[ -]?){13,19}\b")
IBAN = re.compile(r"\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,4})?\b")
ACCOUNT_LABELED = re.compile(
    r"(?i)\b((?:acct|account|routing|aba|member)\s*(?:no\.?|number|num|#)?\s*[:#]?\s*)(\d[\d -]{4,20}\d)"
)
OTP_LABELED = re.compile(
    r"(?i)\b((?:code|passcode|otp|pin|verification code|security code)\s*(?:is|:|=)?\s*)(\d{4,8})\b"
)
DOB = re.compile(
    r"(?i)\b((?:dob|date of birth|born)\s*[:#]?\s*)(\d{1,2}[/-]\d{1,2}[/-]\d{2,4})"
)
PHONE = re.compile(
    r"(?<![\w/])(?:\+?1[ .-]?)?\(?\d{3}\)?[ .-]?\d{3}[ .-]?\d{4}(?![\w/])"
)
EMAIL = re.compile(r"\b([A-Za-z0-9._%+-])([A-Za-z0-9._%+-]*)@([A-Za-z0-9.-]+\.[A-Za-z]{2,})\b")
STREET = re.compile(
    r"\b\d{1,6}\s+(?:[A-Z][a-z]+\s){1,3}(?:St|Street|Ave|Avenue|Rd|Road|Blvd|Ln|Lane|Dr|Drive|Ct|Court|Way|Pl|Place)\b\.?"
)
URL_QUERY = re.compile(r"(https?://[^\s?#<>\"']+)\?[^\s<>\"']*")


def redact(text: str) -> str:
    out = text
    # Strip URL query strings first: they often carry tracking IDs, emails or
    # tokens tied to the recipient. Host + path are kept as indicators.
    out = URL_QUERY.sub(lambda m: m.group(1) + "?[REDACTED-QUERY]", out)
    out = SSN_LABELED.sub(lambda m: f"{m.group(1)} [REDACTED-SSN]", out)
    out = SSN.sub("[REDACTED-SSN]", out)
    out = OTP_LABELED.sub(lambda m: m.group(1) + "[REDACTED-CODE]", out)
    out = DOB.sub(lambda m: m.group(1) + "[REDACTED-DOB]", out)
    out = ACCOUNT_LABELED.sub(lambda m: m.group(1) + "[REDACTED-ACCOUNT]", out)

    def _card(m: re.Match) -> str:
        digits = re.sub(r"\D", "", m.group(0))
        if 13 <= len(digits) <= 19 and _luhn_ok(digits):
            return "[REDACTED-CARD]"
        return m.group(0)

    out = CARD.sub(_card, out)
    out = IBAN.sub("[REDACTED-IBAN]", out)

    def _nine(m: re.Match) -> str:
        return "[REDACTED-ROUTING]" if _aba_ok(m.group(0)) else m.group(0)

    out = re.sub(r"\b\d{9}\b", _nine, out)
    out = PHONE.sub("[REDACTED-PHONE]", out)
    out = EMAIL.sub(lambda m: f"{m.group(1)}***@{m.group(3)}", out)
    out = STREET.sub("[REDACTED-ADDRESS]", out)
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--file", help="file to redact (default: stdin)")
    args = ap.parse_args(argv)
    text = open(args.file, encoding="utf-8").read() if args.file else sys.stdin.read()
    sys.stdout.write(redact(text))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
