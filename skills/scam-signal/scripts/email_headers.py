#!/usr/bin/env python3
"""Email header + structure analysis for scam-signal (stdlib only).

Reads a raw .eml (RFC 5322), an Outlook .msg (OLE/CFB, parsed with a small
built-in reader), or raw header text pasted from "Show original" / "View
source". Fully offline. Nothing is fetched, no links are opened, attachments
are never written to disk or executed; only their names and types are looked at.

Checks:
  * SPF / DKIM / DMARC results from the TOPMOST Authentication-Results header
    (the one your own mail provider added; lower ones can be forged by the sender)
  * From vs Reply-To vs Return-Path domain mismatches
  * brand in the display name sent from a free mailbox or an unrelated domain
  * lookalike sender domains (reuses url_check)
  * links whose visible text shows one domain while the href goes elsewhere
  * risky attachment types (.html, .iso, .zip, .exe, macro docs, ...)

Usage:
    python3 email_headers.py message.eml [--json]
    python3 email_headers.py message.msg
    pbpaste | python3 email_headers.py -        # raw source from clipboard
"""
from __future__ import annotations

import argparse
import email
import email.policy
import email.utils
import json
import re
import struct
import sys
from dataclasses import asdict, dataclass, field
from html.parser import HTMLParser
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import url_check  # noqa: E402

FREE_MAILBOXES = {
    "gmail.com", "googlemail.com", "yahoo.com", "ymail.com", "outlook.com", "hotmail.com",
    "live.com", "msn.com", "aol.com", "icloud.com", "me.com", "mac.com", "proton.me",
    "protonmail.com", "gmx.com", "gmx.net", "mail.com", "zoho.com", "yandex.com", "yandex.ru",
    "tutanota.com", "fastmail.com",
}
# Bulk-mail platforms whose bounce domains legitimately differ from From:
ESP_BOUNCE = (
    "amazonses.com", "sendgrid.net", "mailgun.org", "mcsv.net", "mcdlv.net", "rsgsv.net",
    "sparkpostmail.com", "mandrillapp.com", "postmarkapp.com", "salesforce.com", "exacttarget.com",
    "bounces.google.com", "returnpath.net", "sendinblue.com", "brevo.com", "constantcontact.com",
    "hubspotemail.net", "klaviyomail.com", "marketo.org", "mktomail.com", "emarsys.net",
)
RISKY_ATTACH = re.compile(
    r"\.(html?|shtml|svg|iso|img|vhd|zip|rar|7z|gz|exe|scr|msi|bat|cmd|com|js|jse|vbs|vbe|wsf|hta|lnk|one|"
    r"docm|xlsm|pptm|xlam|jar|apk|dmg|pkg)$",
    re.I,
)


@dataclass
class Finding:
    flag: str
    severity: str
    weight: int
    evidence: str


@dataclass
class EmailReport:
    from_display: str = ""
    from_address: str = ""
    from_domain: str = ""
    reply_to: str = ""
    return_path: str = ""
    subject: str = ""
    auth: dict = field(default_factory=dict)
    urls: list = field(default_factory=list)
    attachments: list = field(default_factory=list)
    findings: list = field(default_factory=list)
    body_text: str = ""
    hidden_text: str = ""
    alt_text: str = ""

    @property
    def score(self) -> int:
        return sum(f.weight for f in self.findings)

    def to_dict(self, include_body: bool = False) -> dict:
        d = asdict(self)
        d["score"] = self.score
        if not include_body:
            d.pop("body_text")
        return d


# --------------------------------------------------------------------------
# Minimal OLE / Compound File Binary reader (enough for Outlook .msg)
# --------------------------------------------------------------------------

CFB_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
ENDOFCHAIN = 0xFFFFFFFE
MAXREGSECT = 0xFFFFFFFA


def read_cfb(data: bytes) -> dict[str, bytes]:
    """Return {"path/to/stream": bytes} for every stream in a CFB file."""
    if data[:8] != CFB_MAGIC:
        raise ValueError("not an OLE/CFB file")
    sector_shift, mini_shift = struct.unpack_from("<HH", data, 0x1E)
    ss, mss = 1 << sector_shift, 1 << mini_shift
    (num_fat, dir_start, _, mini_cutoff, minifat_start, num_minifat,
     difat_start, num_difat) = struct.unpack_from("<IIIIIIII", data, 0x2C)
    nsect = max(0, (len(data) - ss) // ss)

    def sector(i: int) -> bytes:
        off = (i + 1) * ss
        return data[off: off + ss]

    difat = list(struct.unpack_from("<109I", data, 0x4C))
    nxt, guard = difat_start, 0
    while nxt < MAXREGSECT and guard < num_difat + 1 and nxt < nsect:
        ents = struct.unpack(f"<{ss // 4}I", sector(nxt))
        difat.extend(ents[:-1])
        nxt, guard = ents[-1], guard + 1
    fat: list[int] = []
    for s in difat[:num_fat]:
        if s < MAXREGSECT and s < nsect:
            fat.extend(struct.unpack(f"<{ss // 4}I", sector(s)))

    def chain(start: int, table: list[int]) -> list[int]:
        out, seen = [], set()
        while start < MAXREGSECT and start < len(table) and start not in seen:
            seen.add(start)
            out.append(start)
            start = table[start]
        return out

    dir_bytes = b"".join(sector(s) for s in chain(dir_start, fat))
    entries = []
    for off in range(0, len(dir_bytes) - 127, 128):
        e = dir_bytes[off: off + 128]
        nlen = struct.unpack_from("<H", e, 0x40)[0]
        name = e[: max(0, nlen - 2)].decode("utf-16-le", "replace")
        etype = e[0x42]
        left, right, child = struct.unpack_from("<III", e, 0x44)
        start, size = struct.unpack_from("<IQ", e, 0x74)
        entries.append(dict(name=name, type=etype, left=left, right=right, child=child, start=start, size=size))
    if not entries:
        return {}
    root = entries[0]
    ministream = b"".join(sector(s) for s in chain(root["start"], fat))
    minifat_bytes = b"".join(sector(s) for s in chain(minifat_start, fat))
    minifat = list(struct.unpack(f"<{len(minifat_bytes) // 4}I", minifat_bytes))

    def stream(e: dict) -> bytes:
        size = e["size"] & 0xFFFFFFFF if ss == 512 else e["size"]
        if size < mini_cutoff:
            buf = b"".join(ministream[s * mss:(s + 1) * mss] for s in chain(e["start"], minifat))
        else:
            buf = b"".join(sector(s) for s in chain(e["start"], fat))
        return buf[:size]

    out: dict[str, bytes] = {}
    visited: set[int] = set()

    def walk(idx: int, prefix: str) -> None:
        stack = [idx]
        while stack:
            i = stack.pop()
            if i >= len(entries) or i in visited or i == 0xFFFFFFFF:
                continue
            visited.add(i)
            e = entries[i]
            stack.extend([e["left"], e["right"]])
            path = prefix + e["name"]
            if e["type"] == 2:
                out[path] = stream(e)
            elif e["type"] == 1:
                walk(e["child"], path + "/")

    walk(root["child"], "")
    return out


def _prop(streams: dict[str, bytes], tag: str, prefix: str = "") -> str | None:
    for kind, enc in (("001F", "utf-16-le"), ("001E", "latin-1")):
        b = streams.get(f"{prefix}__substg1.0_{tag}{kind}")
        if b is not None:
            return b.decode(enc, "replace").rstrip("\x00")
    return None


def msg_to_message(data: bytes) -> email.message.EmailMessage:
    """Convert an Outlook .msg into an EmailMessage (headers + text/html body)."""
    st = read_cfb(data)
    headers = _prop(st, "007D") or ""
    if headers.strip():
        msg = email.message_from_string(headers.strip() + "\n\n", policy=email.policy.default)
    else:
        msg = email.message.EmailMessage()
        name, addr = _prop(st, "0C1A") or "", _prop(st, "5D01") or _prop(st, "0C1F") or ""
        msg["From"] = email.utils.formataddr((name, addr)) if addr else name
        if _prop(st, "0037"):
            msg["Subject"] = _prop(st, "0037")
    # drop transport MIME headers; we rebuild the body ourselves
    for h in ("Content-Type", "Content-Transfer-Encoding", "MIME-Version"):
        del msg[h]
    text = _prop(st, "1000") or ""
    html = st.get("__substg1.0_10130102")
    if html:
        msg.set_content(text or "(no plain-text body)")
        msg.add_alternative(html.decode("utf-8", "replace"), subtype="html")
    else:
        msg.set_content(text)
    names = []
    for path in st:
        m = re.match(r"(__attach_version1\.0_#[0-9A-Fa-f]+/)", path)
        if m and m.group(1) not in names:
            names.append(m.group(1))
    for pre in names:
        fn = _prop(st, "3707", pre) or _prop(st, "3704", pre) or "attachment"
        # record the name only; the payload is intentionally NOT copied
        msg.add_attachment(b"", maintype="application", subtype="octet-stream", filename=fn)
    return msg


# --------------------------------------------------------------------------
# Body / link extraction
# --------------------------------------------------------------------------


_VOID = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "source", "track", "wbr"}
_HIDDEN_STYLE = re.compile(
    r"display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0(?:\.0+)?(?:px|pt|em|rem|%)?\s*(?:;|$)|"
    r"opacity\s*:\s*0(?:\.0+)?\s*(?:;|$)|max-height\s*:\s*0|(?<![-\w])color\s*:\s*(?:#fff(?:fff)?|white|transparent)\b|"
    r"mso-hide\s*:\s*all|width\s*:\s*0(?:px)?\s*;\s*height\s*:\s*0", re.I)


class _LinkParser(HTMLParser):
    """Collects visible text, <a href> links with their visible label, image alt text,
    and text a human reader would NOT see (display:none, zero-size, white-on-white...).
    Hidden text is where prompt-injection payloads aimed at AI mail assistants usually live."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[tuple[str, str]] = []
        self.text: list[str] = []
        self.hidden: list[str] = []
        self.alts: list[str] = []
        self._href: str | None = None
        self._buf: list[str] = []
        self._skip = 0
        self._stack: list[tuple[str, bool]] = []

    @property
    def _is_hidden(self) -> bool:
        return any(h for _, h in self._stack)

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag in ("script", "style", "head", "title"):
            self._skip += 1
        hidden = "hidden" in a or (a.get("aria-hidden") == "true" and tag != "img") or bool(_HIDDEN_STYLE.search(a.get("style") or ""))
        if tag not in _VOID:
            self._stack.append((tag, hidden))
        if tag == "img":
            alt = (a.get("alt") or a.get("title") or "").strip()
            if alt:
                self.alts.append(alt)
        if tag == "a":
            self._href = a.get("href")
            self._buf = []
        if tag in ("br", "p", "div", "tr", "li"):
            self.text.append("\n")

    def handle_endtag(self, tag):
        if tag in ("script", "style", "head", "title") and self._skip:
            self._skip -= 1
        for i in range(len(self._stack) - 1, -1, -1):
            if self._stack[i][0] == tag:
                del self._stack[i:]
                break
        if tag == "a" and self._href is not None:
            self.links.append((self._href, "".join(self._buf).strip()))
            self._href = None

    def handle_comment(self, data):
        if data.strip() and not data.strip().startswith("[if"):
            self.hidden.append(data.strip())

    def handle_data(self, data):
        if self._skip:
            return
        if self._is_hidden:
            if data.strip():
                self.hidden.append(data.strip())
            return
        self.text.append(data)
        if self._href is not None:
            self._buf.append(data)


def _domain(addr: str) -> str:
    return addr.rsplit("@", 1)[-1].lower().strip(">. ") if "@" in addr else ""


def _related(a: str, b: str) -> bool:
    if not a or not b:
        return True
    ra, rb = url_check.registrable(a), url_check.registrable(b)
    if ra == rb:
        return True
    ba, bb = url_check.OFFICIAL.get(ra), url_check.OFFICIAL.get(rb)
    return bool(ba and ba == bb)


def parse_auth_results(value: str) -> dict:
    res = {}
    for mech in ("spf", "dkim", "dmarc", "arc"):
        m = re.search(rf"\b{mech}\s*=\s*([a-z]+)", value, re.I)
        if m:
            res[mech] = m.group(1).lower()
    m = re.search(r"header\.d\s*=\s*([\w.-]+)", value, re.I)
    if m:
        res["dkim_domain"] = m.group(1).lower()
    m = re.search(r"header\.from\s*=\s*([\w.-]+)", value, re.I)
    if m:
        res["header_from"] = m.group(1).lower()
    return res


def load(path: str) -> email.message.EmailMessage:
    if path == "-":
        data = sys.stdin.buffer.read()
    else:
        data = Path(path).read_bytes()
    if data[:8] == CFB_MAGIC:
        return msg_to_message(data)
    return email.message_from_bytes(data, policy=email.policy.default)


def analyze_message(msg: email.message.EmailMessage) -> EmailReport:
    r = EmailReport()
    add = r.findings.append
    disp, addr = email.utils.parseaddr(str(msg.get("From", "")))
    r.from_display, r.from_address, r.from_domain = disp, addr, _domain(addr)
    r.subject = str(msg.get("Subject", ""))
    r.reply_to = email.utils.parseaddr(str(msg.get("Reply-To", "")))[1]
    r.return_path = email.utils.parseaddr(str(msg.get("Return-Path", "")))[1]

    # --- authentication (topmost header only) ---
    ar = msg.get_all("Authentication-Results") or []
    if ar:
        r.auth = parse_auth_results(str(ar[0]))
    else:
        rs = msg.get_all("Received-SPF") or []
        if rs:
            m = re.match(r"\s*(\w+)", str(rs[0]))
            if m:
                r.auth = {"spf": m.group(1).lower()}
    dmarc, spf, dkim = r.auth.get("dmarc"), r.auth.get("spf"), r.auth.get("dkim")
    if dmarc == "fail":
        add(Finding("dmarc_fail", "high", 4, f"DMARC failed: the message is not verified as coming from {r.from_domain}."))
    if spf in ("fail", "softfail"):
        add(Finding("spf_fail", "medium", 2, f"SPF={spf}: the sending server isn't authorized to send for this domain."))
    if dkim in ("fail", "neutral", "permerror"):
        add(Finding("dkim_fail", "medium", 2, f"DKIM={dkim}: the message signature doesn't verify."))
    if r.auth and not dmarc and spf in (None, "none") and dkim in (None, "none"):
        add(Finding("no_authentication", "low", 1, "No SPF/DKIM/DMARC pass recorded for this message."))
    if dmarc == "pass" or (dkim == "pass" and _related(r.auth.get("dkim_domain", ""), r.from_domain)):
        add(Finding("authenticated_sender", "info", -1,
                    f"Mail provider verified it really came from {r.auth.get('header_from') or r.from_domain}. "
                    "That only proves who sent it, not that the sender is honest."))
    if not ar and not msg.get_all("Received-SPF"):
        add(Finding("no_auth_headers", "info", 0,
                    "No authentication headers present (forwarded or pasted copy?). Ask for the original/raw source for a stronger check."))

    # --- address mismatches ---
    if r.reply_to and not _related(_domain(r.reply_to), r.from_domain):
        add(Finding("reply_to_mismatch", "high", 3,
                    f"Replies go to {r.reply_to}, not the sender's domain {r.from_domain}."))
    rp_dom = _domain(r.return_path)
    if rp_dom and not _related(rp_dom, r.from_domain) and not any(rp_dom.endswith(e) for e in ESP_BOUNCE):
        add(Finding("return_path_mismatch", "low", 1, f"Bounce address domain {rp_dom} differs from {r.from_domain}."))

    # --- display-name impersonation ---
    brands = url_check.brand_mentions(disp) if disp else set()
    if re.search(r"(?i)\b(security|support|billing|fraud|account|service|team|helpdesk|admin|it department)\b", disp) and not brands:
        brands = url_check.brand_mentions(r.subject)
    official = url_check.is_official(r.from_domain) if r.from_domain else None
    if brands and r.from_domain and not any(official == b for b in brands):
        b = sorted(brands)[0]
        sev = "high"
        why = "a free personal mailbox" if r.from_domain in FREE_MAILBOXES else f"an unrelated domain ({r.from_domain})"
        add(Finding("display_name_impersonation", sev, 4,
                    f"Display name '{disp}' suggests {b}, but it was sent from {why}."))
    elif r.from_domain in FREE_MAILBOXES and re.search(
            r"(?i)\b(bank|security|fraud|billing|support|department|irs|police|court|government)\b", disp + " " + r.subject):
        add(Finding("institution_from_free_mailbox", "medium", 2,
                    f"Claims to be an institution but uses a free mailbox ({r.from_domain})."))
    if re.search(r"[\w.+-]+@[\w-]+\.[\w.-]+", disp):
        inner = _domain(re.search(r"[\w.+-]+@[\w-]+\.[\w.-]+", disp).group(0))
        if not _related(inner, r.from_domain):
            add(Finding("address_in_display_name", "high", 3,
                        f"Display name shows the address @{inner} but the real sender is @{r.from_domain}."))
    if r.from_domain:
        dr = url_check.analyze_url("https://" + r.from_domain)
        for f in dr.findings:
            if f.flag in ("lookalike_domain", "brand_in_unofficial_domain", "internationalized_domain"):
                add(Finding("sender_" + f.flag, "high", 4, "Sender domain: " + f.evidence))

    mid = str(msg.get("Message-ID", ""))
    mdom = mid.rsplit("@", 1)[-1].strip("<> ").lower() if "@" in mid else ""
    if mdom and not _related(mdom, r.from_domain) and not any(mdom.endswith(e) for e in ESP_BOUNCE + ("mail.gmail.com", "outlook.com", "prod.outlook.com")):
        add(Finding("message_id_mismatch", "low", 0, f"Message-ID was generated by {mdom}, not {r.from_domain}."))

    # --- body, links, attachments ---
    texts, links, hidden, alts = [], [], [], []
    for part in msg.walk():
        if part.is_multipart():
            continue
        fn = part.get_filename()
        disp_hdr = str(part.get("Content-Disposition", ""))
        if fn or "attachment" in disp_hdr:
            r.attachments.append(fn or "(unnamed)")
            if fn and RISKY_ATTACH.search(fn):
                add(Finding("risky_attachment", "high", 4,
                            f"Attachment '{fn}' is a type commonly used to deliver phishing pages or malware. Don't open it."))
            continue
        ctype = part.get_content_type()
        try:
            content = part.get_content()
        except Exception:
            payload = part.get_payload(decode=True) or b""
            content = payload.decode("utf-8", "replace")
        if not isinstance(content, str):
            continue
        if ctype == "text/html":
            p = _LinkParser()
            try:
                p.feed(content)
            except Exception:
                pass
            links.extend(p.links)
            hidden.extend(p.hidden)
            alts.extend(p.alts)
            if not any(t for t in texts):
                texts.append(re.sub(r"\n\s*\n+", "\n", "".join(p.text)))
        elif ctype == "text/plain":
            texts.insert(0, content)
    r.body_text = (texts[0] if texts else "").strip()

    r.hidden_text = "\n".join(dict.fromkeys(hidden))[:4000]
    r.alt_text = "\n".join(dict.fromkeys(alts))[:2000]
    if len(r.hidden_text) >= 15:
        add(Finding("hidden_text", "medium", 2,
                    f"Contains text hidden from the reader ({len(r.hidden_text)} chars), e.g. \"{r.hidden_text[:120]}\". "
                    "Hidden text is a filter-evasion and AI prompt-injection technique."))

    seen_hosts = set()
    shown_hosts = set()
    for href, label in links:
        if not href or not re.match(r"(?i)^(https?:|www\.)", href.strip()):
            continue
        hu = url_check.normalize(href)
        target = (hu.hostname or "").lower()
        shown = url_check.extract_urls(label)
        if shown:
            sh = (url_check.normalize(shown[0]).hostname or "").lower()
            shown_hosts.add(sh)
            if sh and target and not _related(sh, target):
                add(Finding("link_text_mismatch", "high", 4,
                            f"Link text shows {sh} but actually goes to {target}."))
        if target not in seen_hosts:
            seen_hosts.add(target)
            r.urls.append(href)
    # Plain-text URLs count, but NOT the visible label of an HTML link: "www.paypal.com" shown as
    # anchor text says nothing about where the link goes, and must not earn "official domain" credit.
    for u in url_check.extract_urls(r.body_text):
        h = (url_check.normalize(u).hostname or "").lower()
        if h and h not in seen_hosts and h not in shown_hosts:
            seen_hosts.add(h)
            r.urls.append(u)
    return r


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Analyze an .eml/.msg/raw-source email offline.")
    ap.add_argument("path", help=".eml, .msg, raw header text, or '-' for stdin")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--body", action="store_true", help="include extracted body text in JSON")
    a = ap.parse_args(argv)
    rep = analyze_message(load(a.path))
    if a.json:
        print(json.dumps(rep.to_dict(include_body=a.body), indent=2, default=str))
    else:
        print(f"From: {rep.from_display} <{rep.from_address}>  Reply-To: {rep.reply_to or '-'}")
        print(f"Subject: {rep.subject}\nAuth: {rep.auth or 'none found'}\nScore: {rep.score}")
        for f in sorted(rep.findings, key=lambda f: -f.weight):
            print(f"  [{f.severity}] {f.flag}: {f.evidence}")
        if rep.urls:
            print("Links:", *rep.urls, sep="\n  ")
        if rep.attachments:
            print("Attachments:", ", ".join(rep.attachments))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
