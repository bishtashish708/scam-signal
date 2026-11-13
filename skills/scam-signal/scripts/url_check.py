#!/usr/bin/env python3
"""Safe URL / lookalike-domain analysis for scam-signal (stdlib only).

OFFLINE BY DEFAULT. This never loads the page, never submits anything, never
downloads files. The offline checks look only at the URL string itself.

Optional network lookups (each one is opt-in and sends only what is listed):
  --rdap         sends the bare registrable DOMAIN to rdap.org (public RDAP
                 bootstrap) to read its registration date.
  --expand       for known URL shorteners only: sends a HEAD request to the
                 shortener and reads the Location header, hop by hop. It stops
                 at the first non-shortener host and does NOT contact it.
  --phish-feeds  downloads public phishing feeds (OpenPhish community feed,
                 abuse.ch URLhaus) and matches LOCALLY. Your URL is never sent.
  --online       all three.

Usage:
    python3 url_check.py "hxxps://paypa1-secure[.]com/login" --json
"""
from __future__ import annotations

import argparse
import datetime as _dt
import http.client
import json
import os
import re
import sys
import time
import unicodedata
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass, field

# --------------------------------------------------------------------------
# Reference data
# --------------------------------------------------------------------------

# brand key -> official registrable domains. Keep this conservative: a domain
# listed here is treated as "official" and will not be flagged as a lookalike.
BRANDS: dict[str, list[str]] = {
    "paypal": ["paypal.com", "paypal.me"],
    "venmo": ["venmo.com"],
    "cashapp": ["cash.app", "square.com", "squareup.com", "block.xyz"],
    "zelle": ["zellepay.com", "zelle.com"],
    "chase": ["chase.com", "jpmorganchase.com", "jpmorgan.com"],
    "bankofamerica": ["bankofamerica.com", "bofa.com"],
    "wellsfargo": ["wellsfargo.com", "wf.com"],
    "citi": ["citi.com", "citibank.com"],
    "capitalone": ["capitalone.com"],
    "usbank": ["usbank.com"],
    "pnc": ["pnc.com"],
    "truist": ["truist.com"],
    "americanexpress": ["americanexpress.com", "aexp.com"],
    "discover": ["discover.com"],
    "navyfederal": ["navyfederal.org"],
    "usaa": ["usaa.com"],
    "chime": ["chime.com"],
    "amazon": ["amazon.com", "amazon.co.uk", "amazon.ca", "amazon.de", "amazon.in", "amazon.com.au", "amazon.co.jp", "amazon.fr", "amazon.es", "amazon.it"],
    "apple": ["apple.com", "icloud.com"],
    "microsoft": ["microsoft.com", "live.com", "outlook.com", "office.com", "microsoftonline.com", "office365.com"],
    "google": ["google.com", "gmail.com", "youtube.com"],
    "netflix": ["netflix.com"],
    "facebook": ["facebook.com", "fb.com", "meta.com"],
    "instagram": ["instagram.com"],
    "whatsapp": ["whatsapp.com"],
    "usps": ["usps.com"],
    "ups": ["ups.com"],
    "fedex": ["fedex.com"],
    "dhl": ["dhl.com"],
    "irs": ["irs.gov"],
    "ssa": ["ssa.gov"],
    "coinbase": ["coinbase.com"],
    "binance": ["binance.com", "binance.us"],
    "kraken": ["kraken.com"],
    "geeksquad": ["bestbuy.com", "geeksquad.com"],
    "norton": ["norton.com"],
    "mcafee": ["mcafee.com"],
    "docusign": ["docusign.com", "docusign.net"],
    "dropbox": ["dropbox.com"],
    "att": ["att.com"],
    "verizon": ["verizon.com"],
    "tmobile": ["t-mobile.com"],
    "walmart": ["walmart.com"],
    "costco": ["costco.com"],
    "ebay": ["ebay.com"],
    "linkedin": ["linkedin.com"],
    "ezpass": ["e-zpassny.com", "e-zpassiag.com", "ezpassnj.com", "ezpassva.com", "ezpassmd.com", "ezpassde.com"],
    "sunpass": ["sunpass.com"],
    "fastrak": ["bayareafastrak.org", "thetollroads.com"],
    "txtag": ["txtag.org"],
    # UK / Australia / Canada. (Indian banks are moving to *.bank.in domains; not listed until that settles.)
    "hmrc": ["www.gov.uk", "service.gov.uk"],
    "dvla": ["www.gov.uk", "service.gov.uk"],
    "royalmail": ["royalmail.com"],
    "evri": ["evri.com"],
    "auspost": ["auspost.com.au"],
    "canadapost": ["canadapost-postescanada.ca", "canadapost.ca"],
}
# Short brand tokens are too collision-prone for substring matching ("att" in
# "matter", "ups" in "groups"), so they only match as whole hyphen/dot tokens.
SHORT_TOKEN_BRANDS = {"att", "ups", "dhl", "irs", "ssa", "pnc", "citi", "usps", "usaa", "chase", "apple", "hmrc", "dvla", "evri"}

BRAND_ALIASES = {
    "boa": "bankofamerica", "bofa": "bankofamerica", "wells": "wellsfargo", "cash-app": "cashapp",
    "amex": "americanexpress", "nfcu": "navyfederal", "t-mobile": "tmobile", "e-zpass": "ezpass",
    "appleid": "apple", "icloud": "apple", "office365": "microsoft", "outlook": "microsoft",
    "royal-mail": "royalmail", "australiapost": "auspost", "canada-post": "canadapost",
}

OFFICIAL = {d: b for b, ds in BRANDS.items() for d in ds}

MULTI_PART_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au", "co.jp", "co.in",
    "co.nz", "com.co", "com.ar", "com.pe", "com.ph", "com.my", "com.ng", "com.pk", "co.id", "com.br", "com.mx", "co.za", "com.sg", "com.hk", "co.kr", "com.cn", "com.tr",
}

SHORTENERS = {
    "bit.ly", "bitly.com", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "shorturl.at", "rb.gy", "t.ly", "s.id", "tiny.cc", "lnkd.in",
    "qrco.de", "v.gd", "shorte.st", "bl.ink", "short.io", "tr.ee",
}

FREE_HOSTING = (
    "weebly.com", "wixsite.com", "firebaseapp.com", "web.app", "pages.dev", "netlify.app",
    "vercel.app", "github.io", "glitch.me", "ngrok.io", "ngrok-free.app", "herokuapp.com",
    "blogspot.com", "000webhostapp.com", "duckdns.org", "r2.dev", "workers.dev",
    "square.site", "godaddysites.com", "webflow.io", "framer.app", "carrd.co",
)
FORM_HOSTS = ("forms.gle", "docs.google.com/forms", "sites.google.com", "forms.office.com")

RISKY_TLDS = {
    "top", "xyz", "icu", "click", "buzz", "cyou", "rest", "sbs", "cfd", "live", "shop",
    "online", "site", "vip", "win", "bond", "monster", "lol", "info", "support", "help",
    "cc", "tk", "ml", "ga", "cf", "gq", "zip", "mov", "lat", "today", "life",
}

CRED_WORDS = (
    "login", "log-in", "signin", "sign-in", "verify", "verification", "secure", "security",
    "account", "update", "unlock", "suspend", "confirm", "wallet", "billing", "refund",
    "redeliver", "redelivery", "toll", "invoice", "unpaid", "claim", "reward", "support",
)

# Common confusables collapsed to an ASCII "skeleton".
CONFUSABLES = {
    "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b", "9": "g", "@": "a",
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x",
    "у": "y", "і": "i", "ј": "j", "һ": "h", "ԁ": "d", "ο": "o",
    "α": "a", "ν": "v", "ρ": "p", "ı": "i", "ɡ": "g",
}

# --------------------------------------------------------------------------
# Extraction
# --------------------------------------------------------------------------

_URL_RE = re.compile(
    r"""(?ix)
    \b(
      (?:h(?:tt|xx)ps?://[^\s<>"'`)\]]+)          # scheme URLs (incl. defanged hxxp)
      |
      (?:www\.[^\s<>"'`)\]]+)
      |
      (?:(?:[a-z0-9-]+\.)+(?:com|net|org|info|top|xyz|icu|click|buzz|live|shop|online|site|vip|co|io|app|me|us|cc|tk|gov|ly|gl|at|id|de|uk|ca|cyou|sbs|cfd|bond|lol|support|help|win|rest|monster|today|life|lat|zip|mov)
         (?:/[^\s<>"'`)\]]*)?)                    # bare domains with known TLDs
    )""",
)


def refang(text: str) -> str:
    t = re.sub(r"(?i)hxxp", "http", text)
    t = re.sub(r"\[\s*\.\s*\]|\(\s*\.\s*\)|\{\s*\.\s*\}|\s\[dot\]\s|\[dot\]|\(dot\)", ".", t)
    t = t.replace("[:]", ":").replace("[://]", "://")
    return t


def extract_urls(text: str) -> list[str]:
    seen: list[str] = []
    for m in _URL_RE.finditer(refang(text)):
        u = m.group(1).rstrip(".,;:!?'\"")
        # skip email addresses picked up as bare domains
        start = m.start(1)
        if start > 0 and refang(text)[start - 1] == "@":
            continue
        if u.lower() not in (s.lower() for s in seen):
            seen.append(u)
    return seen


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------


def normalize(url: str) -> urllib.parse.SplitResult:
    u = refang(url.strip())
    if not re.match(r"(?i)^[a-z][a-z0-9+.-]*://", u):
        u = "http://" + u
    return urllib.parse.urlsplit(u)


def decode_host(host: str) -> str:
    try:
        return ".".join(
            lbl.encode("ascii").decode("idna") if lbl.startswith("xn--") else lbl
            for lbl in host.split(".")
        )
    except Exception:
        return host


def registrable(host: str) -> str:
    labels = [x for x in host.lower().strip(".").split(".") if x]
    if len(labels) <= 2:
        return ".".join(labels)
    if ".".join(labels[-2:]) in MULTI_PART_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def skeleton(s: str) -> str:
    s = unicodedata.normalize("NFKC", s.lower())
    s = "".join(CONFUSABLES.get(c, c) for c in s)
    s = s.replace("rn", "m").replace("vv", "w").replace("cl", "d")
    s = unicodedata.normalize("NFKD", s)
    return "".join(c for c in s if not unicodedata.combining(c))


def levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def is_official(host: str) -> str | None:
    reg = registrable(host)
    if reg in OFFICIAL:
        return OFFICIAL[reg]
    if host.endswith(".gov") or host.endswith(".mil"):
        return "us-government"
    return None


def _tokens(s: str) -> list[str]:
    return [t for t in re.split(r"[^a-z0-9]+", s.lower()) if t]


def brand_mentions(s: str) -> set[str]:
    """Brands named inside a host or path string."""
    low = s.lower()
    toks = set(_tokens(low)) | set(_tokens(skeleton(low)))
    joined = low.replace("-", "").replace(".", "") + " " + skeleton(low).replace("-", "").replace(".", "")
    found = set()
    for b in BRANDS:
        if b in SHORT_TOKEN_BRANDS:
            if b in toks:
                found.add(b)
        elif len(b) >= 5 and b in joined:
            found.add(b)
        elif b in toks:
            found.add(b)
    for alias, b in BRAND_ALIASES.items():
        if alias in toks or (len(alias) >= 6 and alias.replace("-", "") in joined):
            found.add(b)
    return found


# --------------------------------------------------------------------------
# Analysis
# --------------------------------------------------------------------------


@dataclass
class Finding:
    flag: str
    severity: str  # high | medium | low | info
    weight: int
    evidence: str


@dataclass
class UrlReport:
    url: str
    host: str
    host_decoded: str
    registrable_domain: str
    official_brand: str | None
    findings: list[Finding] = field(default_factory=list)
    online: dict = field(default_factory=dict)

    @property
    def score(self) -> int:
        return sum(f.weight for f in self.findings)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["score"] = self.score
        return d



# --------------------------------------------------------------------------
# Redirect / link-wrapper unwrapping (offline: parsed from the URL string)
# --------------------------------------------------------------------------

# (host suffix, path prefix, query keys, kind). "open_redirect" wrappers can point anywhere,
# so they must never lend their own reputation to the destination. "security_rewrite"
# wrappers (SafeLinks, urldefense) are added by the recipient's mail gateway.
WRAPPERS = [
    ("google.com", "/url", ("q", "url"), "open_redirect"),
    ("google.com", "/amp/s/", (), "open_redirect"),
    ("l.facebook.com", "/l.php", ("u",), "open_redirect"),
    ("lm.facebook.com", "/l.php", ("u",), "open_redirect"),
    ("l.instagram.com", "/", ("u",), "open_redirect"),
    ("l.messenger.com", "/l.php", ("u",), "open_redirect"),
    ("t.umblr.com", "/redirect", ("z",), "open_redirect"),
    ("youtube.com", "/redirect", ("q",), "open_redirect"),
    ("linkedin.com", "/redir/redirect", ("url",), "open_redirect"),
    ("safelinks.protection.outlook.com", "/", ("url",), "security_rewrite"),
    ("urldefense.proofpoint.com", "/v2/url", ("u",), "security_rewrite"),
    ("urldefense.com", "/v3/", (), "security_rewrite"),
]


def _proofpoint_v2(u: str) -> str:
    return urllib.parse.unquote(u.replace("-", "%").replace("_", "/"))


def unwrap(url: str, depth: int = 0) -> tuple[str, list[tuple[str, str]]]:
    """Return (final_url, [(wrapper_host, kind), ...]) without any network access."""
    if depth > 4:
        return url, []
    parts = normalize(url)
    host = (parts.hostname or "").lower()
    q = urllib.parse.parse_qs(parts.query)
    for suffix, prefix, keys, kind in WRAPPERS:
        if not (host == suffix or host.endswith("." + suffix)) or not parts.path.startswith(prefix):
            continue
        inner = None
        if suffix == "urldefense.com":
            m = re.match(r"/v3/__(.+?)__;", parts.path + ("?" + parts.query if parts.query else ""))
            inner = m.group(1) if m else None
        elif suffix == "google.com" and prefix == "/amp/s/":
            inner = "https://" + parts.path[len(prefix):]
        else:
            for k in keys:
                if q.get(k):
                    inner = q[k][0]
                    break
            if inner and suffix == "urldefense.proofpoint.com":
                inner = _proofpoint_v2(inner)
        if inner and re.match(r"(?i)^(?:https?:)?//|^www\.", inner.strip()):
            inner = inner.strip()
            if inner.startswith("//"):
                inner = "https:" + inner
            final, chain = unwrap(inner, depth + 1)
            return final, [(host, kind)] + chain
    return url, []


MESSAGING_HANDOFF = {
    "t.me": "Telegram", "telegram.me": "Telegram", "telegram.dog": "Telegram",
    "wa.me": "WhatsApp", "chat.whatsapp.com": "WhatsApp", "api.whatsapp.com": "WhatsApp",
    "line.me": "LINE", "signal.me": "Signal", "m.me": "Messenger", "qm.qq.com": "QQ",
}


def _obfuscated_ip(host: str) -> str | None:
    """Decode IPs written as one decimal/hex number or with hex/octal octets (e.g. 0x7f.1, 3232235777, 0300.0250.1.1)."""
    if not host or re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host) and not re.search(r"(?:^|\.)0\d", host):
        return None
    parts = host.split(".")
    if not 1 <= len(parts) <= 4 or not all(re.fullmatch(r"0x[0-9a-f]+|\d+", x) for x in parts):
        return None
    try:
        nums = [int(x, 16) if x.startswith("0x") else (int(x, 8) if len(x) > 1 and x.startswith("0") else int(x)) for x in parts]
    except ValueError:
        return None
    # inet_aton semantics: the last part fills the remaining bytes
    tail_bytes = 4 - (len(nums) - 1)
    if any(n > 255 for n in nums[:-1]) or nums[-1] >= 256 ** tail_bytes:
        return None
    if len(nums) == 1 and nums[0] < 256 ** 3:  # a bare small number is not a host
        return None
    val = 0
    for n in nums[:-1]:
        val = val * 256 + n
    val = val * (256 ** tail_bytes) + nums[-1]
    return ".".join(str((val >> s) & 255) for s in (24, 16, 8, 0))


def analyze_url(url: str) -> UrlReport:
    final, chain = unwrap(url)
    if chain:
        rep = analyze_url(final)
        rep.url = url
        opens = [h for h, k in chain if k == "open_redirect"]
        if opens:
            rep.findings.insert(0, Finding("redirect_wrapper", "medium", 2 if not rep.official_brand else 0,
                                           f"Link is wrapped in a redirect through {opens[0]}; it really goes to {rep.registrable_domain}. "
                                           "The wrapper's reputation says nothing about the destination."))
        else:
            rep.findings.insert(0, Finding("security_rewrite", "info", 0,
                                           f"Link was rewritten by your mail security gateway ({chain[0][0]}); analyzed the original destination {rep.registrable_domain}."))
        return rep
    parts = normalize(url)
    netloc = parts.netloc
    userinfo = ""
    if "@" in netloc:
        userinfo, _, netloc = netloc.rpartition("@")
    host = netloc.split(":")[0].lower().strip(".")
    host_dec = decode_host(host)
    alt_ip = _obfuscated_ip(host)
    is_ip = bool(re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host)) or host.startswith("[") or bool(alt_ip)
    reg = host if is_ip else registrable(host)
    had_scheme = bool(re.match(r"(?i)^\s*h(?:tt|xx)ps?://", url))
    generic_host = any(f in (host + parts.path).lower() for f in FORM_HOSTS) or any(
        host == h or host.endswith("." + h) for h in FREE_HOSTING)
    rep = UrlReport(url=url, host=host, host_decoded=host_dec, registrable_domain=reg,
                    official_brand=None if (is_ip or generic_host) else is_official(host))
    add = rep.findings.append
    path = urllib.parse.unquote(parts.path + ("?" + parts.query if parts.query else ""))

    if rep.official_brand:
        add(Finding("official_domain", "info", -2,
                    f"{reg} is an official domain for {rep.official_brand}. Still prefer typing the address or using the app."))

    if alt_ip:
        add(Finding("obfuscated_ip_host", "high", 5,
                    f"Host {host} is an IP address written in hex/decimal/octal to disguise it (it means {alt_ip})."))
    elif is_ip:
        add(Finding("ip_address_host", "high", 4, f"Link points to a raw IP address ({host}), not a named site."))
    handoff = next((name for h, name in MESSAGING_HANDOFF.items()
                    if (host == h or host.endswith("." + h)) and (h != "api.whatsapp.com" or parts.path.startswith("/send"))), None)
    if handoff:
        rep.official_brand = None
        rep.findings[:] = [f for f in rep.findings if f.flag != "official_domain"]
        add(Finding("messaging_handoff", "medium", 2,
                    f"Link opens a {handoff} chat. Moving you to {handoff} is a common step in job, investment and romance scams."))
    if userinfo:
        add(Finding("userinfo_trick", "high", 4,
                    f"Text before '@' ({userinfo}) is ignored by browsers; the real destination is {host}."))
    if "xn--" in host or any(ord(c) > 127 for c in host):
        add(Finding("internationalized_domain", "high", 3,
                    f"Domain uses non-ASCII / punycode characters: {host} displays as {host_dec}."))

    if not rep.official_brand and reg not in SHORTENERS and not is_ip and not generic_host and not handoff:
        sld = decode_host(reg.split(".")[0])
        cands = [sld] + [t for t in sld.split("-") if t and t != sld]
        lookalike = None
        for dom in OFFICIAL:
            osld = dom.split(".")[0]
            if len(osld) < 4:
                continue
            for tok in cands:
                sk = skeleton(tok)
                if tok != osld and sk == skeleton(osld):
                    lookalike = (dom, "character substitution")
                elif tok != osld and len(osld) >= 5 and len(tok) >= 4 and levenshtein(sk, osld) <= (1 if len(osld) < 8 else 2):
                    lookalike = (dom, "one or two characters off")
                elif tok == sld == osld and reg != dom:
                    lookalike = (dom, "same name on a different extension")
                if lookalike:
                    break
            if lookalike:
                break
        if lookalike:
            add(Finding("lookalike_domain", "high", 5,
                        f"{reg} imitates {lookalike[0]} ({lookalike[1]})."))
        brands_in_host = brand_mentions(host_dec)
        if brands_in_host and not lookalike:
            b = sorted(brands_in_host)[0]
            add(Finding("brand_in_unofficial_domain", "high", 4,
                        f"Host '{host_dec}' uses the name '{b}' but the real site is {BRANDS[b][0]}; the actual owner is {reg}."))
        elif not brands_in_host:
            brands_in_path = brand_mentions(path)
            if brands_in_path:
                b = sorted(brands_in_path)[0]
                add(Finding("brand_in_path", "medium", 2,
                            f"'{b}' appears in the path of a page hosted on {reg}, not on {BRANDS[b][0]}."))

    if reg in SHORTENERS:
        add(Finding("url_shortener", "medium", 2,
                    f"{reg} is a link shortener that hides the real destination."))
    full = (host + parts.path).lower()
    if any(host == h or host.endswith("." + h) for h in FREE_HOSTING):
        add(Finding("free_site_builder", "medium", 2,
                    f"Hosted on a free site builder/platform ({reg}); banks and agencies don't use these for account pages."))
    if any(f in full for f in FORM_HOSTS):
        add(Finding("generic_form_host", "medium", 2,
                    "Link goes to a generic form/site host, a common way to collect credentials or payment info."))
    tld = host.rsplit(".", 1)[-1] if "." in host else ""
    if tld in RISKY_TLDS and not rep.official_brand:
        add(Finding("high_abuse_tld", "low", 1, f".{tld} is a low-cost domain extension heavily used in phishing."))
    cw = sorted({w for w in CRED_WORDS if w in full})
    if cw and not rep.official_brand:
        add(Finding("credential_bait_words", "low", 1, f"URL contains bait words: {', '.join(cw[:5])}."))
    if host.count(".") >= 4:
        add(Finding("deep_subdomains", "low", 1, f"Unusually many subdomain levels ({host})."))
    if host_dec.count("-") >= 3:
        add(Finding("hyphen_stuffing", "low", 1, f"Many hyphens in the host ({host_dec})."))
    if had_scheme and parts.scheme == "http" and not rep.official_brand and reg not in SHORTENERS:
        add(Finding("no_https", "low", 1, "Link is plain http (no encryption)."))
    if re.search(r"\.(apk|exe|scr|msi|dmg|pkg|iso|img|js|vbs|bat|cmd|lnk|zip|rar|7z|html?)$", parts.path.lower()):
        add(Finding("direct_file_download", "high", 3, f"Link points straight at a file ({parts.path.rsplit('/', 1)[-1]}). Don't open it."))
    return rep


# --------------------------------------------------------------------------
# Optional online lookups (explicit opt-in only)
# --------------------------------------------------------------------------

UA = "scam-signal/0.2 (+https://github.com/bishtashish708/scam-signal)"


def rdap_lookup(domain: str, timeout: float = 8.0) -> dict:
    """Return {'registered': 'YYYY-MM-DD', 'age_days': N} or {'error': ...}. Sends DOMAIN only."""
    url = "https://rdap.org/domain/" + urllib.parse.quote(domain)
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "application/rdap+json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310 (fixed https host)
            data = json.loads(r.read(2_000_000).decode("utf-8", "replace"))
    except Exception as e:  # network blocked, 404 for unregistered, rate limit...
        return {"error": f"{type(e).__name__}: {e}"}
    for ev in data.get("events", []):
        if ev.get("eventAction") == "registration" and ev.get("eventDate"):
            d = _dt.datetime.fromisoformat(ev["eventDate"].replace("Z", "+00:00"))
            age = (_dt.datetime.now(_dt.timezone.utc) - d).days
            return {"registered": d.date().isoformat(), "age_days": age}
    return {"error": "no registration date in RDAP response"}


def expand_short_url(url: str, max_hops: int = 5, timeout: float = 6.0) -> dict:
    """Follow redirects ONLY while the host is a known shortener. Never fetches the final page."""
    hops = []
    cur = url
    for _ in range(max_hops):
        p = normalize(cur)
        if registrable(p.hostname or "") not in SHORTENERS:
            break
        conn_cls = http.client.HTTPSConnection if p.scheme == "https" else http.client.HTTPConnection
        try:
            conn = conn_cls(p.hostname, p.port, timeout=timeout)
            conn.request("HEAD", (p.path or "/") + ("?" + p.query if p.query else ""), headers={"User-Agent": UA})
            resp = conn.getresponse()
            loc = resp.getheader("Location")
            conn.close()
        except Exception as e:
            return {"hops": hops, "error": f"{type(e).__name__}: {e}"}
        if not loc:
            break
        cur = urllib.parse.urljoin(cur, loc)
        hops.append(cur)
    return {"hops": hops, "final": cur, "final_contacted": False}


FEEDS = {
    "openphish": "https://openphish.com/feed.txt",
    "urlhaus": "https://urlhaus.abuse.ch/downloads/text_online/",
}


def _cache_dir() -> str:
    d = os.environ.get("SCAM_SIGNAL_CACHE") or os.path.join(os.path.expanduser("~"), ".cache", "scam-signal")
    os.makedirs(d, exist_ok=True)
    return d


def load_feeds(ttl: int = 6 * 3600, timeout: float = 15.0) -> tuple[set[str], set[str], list[str]]:
    """Download public feeds (cached) and return (urls, hosts, errors). Nothing about the user's URL is sent."""
    urls: set[str] = set()
    errors: list[str] = []
    for name, src in FEEDS.items():
        path = os.path.join(_cache_dir(), f"{name}.txt")
        fresh = os.path.exists(path) and time.time() - os.path.getmtime(path) < ttl
        if not fresh:
            try:
                req = urllib.request.Request(src, headers={"User-Agent": UA})
                with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310
                    body = r.read(20_000_000)
                with open(path, "wb") as f:
                    f.write(body)
            except Exception as e:
                errors.append(f"{name}: {type(e).__name__}: {e}")
        if os.path.exists(path):
            with open(path, encoding="utf-8", errors="replace") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        urls.add(line.rstrip("/").lower())
    hosts = {(urllib.parse.urlsplit(u).hostname or "") for u in urls}
    return urls, hosts, errors


def apply_online(rep: UrlReport, rdap: bool, expand: bool, feeds: tuple | None) -> None:
    if expand and rep.registrable_domain in SHORTENERS:
        res = expand_short_url(rep.url)
        rep.online["expand"] = res
        if res.get("final") and res["final"] != rep.url:
            inner = analyze_url(res["final"])
            rep.online["expanded_analysis"] = inner.to_dict()
            for f in inner.findings:
                rep.findings.append(Finding("expanded:" + f.flag, f.severity, f.weight, f"After expansion -> {f.evidence}"))
    if rdap and not rep.official_brand and rep.registrable_domain not in SHORTENERS:
        res = rdap_lookup(rep.registrable_domain)
        rep.online["rdap"] = res
        age = res.get("age_days")
        if isinstance(age, int):
            if age < 30:
                rep.findings.append(Finding("new_domain", "high", 4, f"{rep.registrable_domain} was registered {age} days ago ({res['registered']})."))
            elif age < 180:
                rep.findings.append(Finding("young_domain", "medium", 2, f"{rep.registrable_domain} is only {age} days old."))
    if feeds is not None:
        urls, hosts, errors = feeds
        hit_url = normalize(rep.url).geturl().rstrip("/").lower() in urls
        hit_host = rep.host in hosts and not rep.official_brand and rep.registrable_domain not in SHORTENERS
        rep.online["phish_feeds"] = {"url_listed": hit_url, "host_listed": hit_host, "errors": errors}
        if hit_url or hit_host:
            rep.findings.append(Finding("listed_in_phishing_feed", "high", 6,
                                        f"{'URL' if hit_url else 'Host ' + rep.host} appears in a public phishing/malware feed."))


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Offline-first URL / lookalike-domain check.")
    ap.add_argument("urls", nargs="*", help="URLs, or text containing URLs (defanged is fine)")
    ap.add_argument("--text-file", help="extract URLs from this text file")
    ap.add_argument("--rdap", action="store_true", help="look up domain age via rdap.org (sends domain only)")
    ap.add_argument("--expand", action="store_true", help="expand known shorteners via HEAD (never visits final page)")
    ap.add_argument("--phish-feeds", action="store_true", help="download public feeds and match locally")
    ap.add_argument("--online", action="store_true", help="enable all three lookups")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)
    src = " ".join(a.urls)
    if a.text_file:
        src += "\n" + open(a.text_file, encoding="utf-8", errors="replace").read()
    urls = extract_urls(src)
    if not urls:
        print("No URLs found.", file=sys.stderr)
        return 1
    feeds = load_feeds() if (a.phish_feeds or a.online) else None
    reps = []
    for u in urls:
        r = analyze_url(u)
        if a.rdap or a.expand or feeds is not None or a.online:
            apply_online(r, a.rdap or a.online, a.expand or a.online, feeds)
        reps.append(r)
    if a.json:
        print(json.dumps([r.to_dict() for r in reps], indent=2))
    else:
        for r in reps:
            print(f"{r.url}\n  domain: {r.registrable_domain}  score: {r.score}")
            for f in sorted(r.findings, key=lambda f: -f.weight):
                print(f"  [{f.severity}] {f.flag}: {f.evidence}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
