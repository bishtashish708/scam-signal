#!/usr/bin/env python3
"""scam-signal: one-shot analyzer (stdlib only, offline by default).

Accepts message text (SMS/DM/screenshot transcription), a call transcript or
notes file, an email (.eml / .msg / raw source), a complaint narrative, or
a bare URL. Outputs a report: likely typology mapped to FTC / IC3 / CFPB
categories, ranked red flags with evidence quotes, risk + confidence,
what-to-do-now steps and official reporting links.

Examples:
    python3 analyze.py --text "USPS: your package is on hold, pay \\$1.99 at usps-redelivery.top"
    python3 analyze.py --file suspicious.eml
    python3 analyze.py --file voicemail_transcript.txt --channel call
    python3 analyze.py --url "hxxps://paypa1-secure[.]com/login" --online
    python3 analyze.py --file msg.txt --json
    python3 analyze.py --file msg.txt --save report.md      # saved copy is PII-redacted

Privacy: no network access unless you pass --rdap / --expand / --phish-feeds /
--online, and even then only the domain (RDAP) or the shortener URL (expand)
leaves your machine. Phishing feeds are downloaded and matched locally.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import chat_export  # noqa: E402

import email_headers  # noqa: E402
import redact  # noqa: E402
import signals  # noqa: E402
import taxonomy  # noqa: E402
import url_check  # noqa: E402

VERSION = "0.2.0"

DECEPTION_FLAGS = {
    "safe_account", "otp_request", "remote_access", "gift_card_payment", "overpayment", "too_good",
    "romance_pretext", "family_pretext", "job_too_easy", "advance_fee", "sextortion", "tech_scare",
    "link_activation_trick", "delivery_fee", "secrecy", "stay_on_line", "crypto_payment",
    "seed_phrase", "wallet_drainer", "recovery_offer", "ai_directed_text", "changed_bank_details", "fake_invoice",
    "qr_code_lure",
}
# A request for money, codes or credentials. When one is present, reassuring boilerplate
# ("we'll never ask for your code", "call the number on your card") must not cancel it out:
# scammers paste that boilerplate precisely because it lowers suspicion.
ASK_FLAGS = {
    "safe_account", "otp_request", "credential_request", "gift_card_payment", "crypto_payment", "unusual_payment",
    "remote_access", "advance_fee", "overpayment", "delivery_fee", "seed_phrase", "wallet_drainer", "recovery_offer",
    "changed_bank_details", "qr_code_lure",
}
FIRST_PERSON_UNAUTH = re.compile(
    r"\b(?:i|we) (?:did not|didn'?t|never) (?:make|authorize|send|approve|initiate|recogni[sz]e)\b"
    r"|\b(?:i|we)\b[^.]{0,60}\b(?:did not|didn'?t|never) (?:make|authorize|send|approve|initiate)\b"
    r"|\bsomeone (?:else )?(?:hacked|accessed|logged into|got into|broke into|took over) (?:my|our)\b"
    r"|\bwithout my (?:knowledge|permission|authori[sz]ation|consent)\b"
    r"|\bsim[- ]swap|\bported my (?:number|phone)\b",
    re.I,
)

LEVELS = [
    (9, "very_high", "Very likely a scam"),
    (5, "high", "Likely a scam"),
    (3, "medium", "Suspicious: treat as a scam until verified"),
    (1, "low", "Some caution signs, but no strong scam pattern matched"),
    (-99, "minimal", "The rules found no scam pattern. This is not a clearance"),
]
NOT_CLEARANCE = ("The rule engine only matches known patterns; a clean result does NOT mean the message is safe. "
                 "Verify through the official app or a number you look up yourself before acting on any request.")
SCAM_THRESHOLD = 3


def looks_like_email(text: str) -> bool:
    head = text.lstrip()[:2000]
    return bool(re.match(r"(?im)^(?:received|return-path|delivered-to|from|authentication-results|message-id|x-[\w-]+):", head)) and \
        bool(re.search(r"(?im)^(?:from|subject):", head))


def analyze(text: str = "", *, email_path: str | None = None, raw_email: bytes | None = None,
            urls: list[str] | None = None, channel: str = "unknown",
            online: dict | None = None, country: str | None = None) -> dict:
    online = online or {}
    em = None
    if email_path or raw_email is not None:
        msg = email_headers.load(email_path) if email_path else email_headers.email.message_from_bytes(
            raw_email, policy=email_headers.email.policy.default)
        em = email_headers.analyze_message(msg)
        # hidden HTML and image alt text are included so injection payloads and lures hidden there are matched
        text = "\n".join(x for x in (em.subject, em.body_text, em.hidden_text, em.alt_text) if x)
        channel = "email"
    body = text or ""
    chat = None
    if not em:
        msgs = chat_export.parse(body)
        if msgs:
            chat = chat_export.summarize(msgs)
            body = "\n".join(m.text for m in msgs)
            channel = "chat" if channel == "unknown" else channel

    norm = signals.normalize_text(body)
    hits = signals.find_flags(norm.text)
    reassure = signals.find_flags(norm.text, signals.REASSURING)
    if norm.obfuscated:
        ev = [f"{norm.zero_width} invisible zero-width characters"] if norm.zero_width else []
        ev += [f"spaced-out letters: '{x}'" for x in norm.spaced[:2]] + [f"look-alike spelling: '{x}'" for x in norm.leet[:3]]
        if norm.confusables:
            ev.append(f"{norm.confusables} word(s) mixing Latin with Cyrillic/Greek look-alike letters")
        hits.append(signals.Hit("obfuscated_text", "Text is disguised to slip past filters (hidden characters, l33t or s p a c e d letters)", 3, ev))
    top_scheme = None
    if chat and chat["schemes"]:
        top_scheme = chat["schemes"][0]
        if top_scheme["strength"] >= 2:
            ev = [f"{h['label']} (msg {h['index'] + 1}, {h['date']}): \"{h['quote'][:110]}\"" for h in top_scheme["hits"]]
            hits.append(signals.Hit("chat_progression",
                                    f"Conversation follows the {top_scheme['name']} playbook "
                                    f"({top_scheme['stages_reached']}/{top_scheme['total_stages']} stages)",
                                    6 if top_scheme["strength"] == 3 else 3, ev))
    flag_ids = {h.id for h in hits}
    coverage = signals.language_coverage(body)

    # URLs: explicit + found in body (non-email) + real hrefs/plain-text links from the email parser.
    # For emails, the visible text of an <a> tag is NOT a link and must not earn official-domain credit.
    all_urls: list[str] = []
    for u in (urls or []) + ([] if em else url_check.extract_urls(body)) + (em.urls if em else []):
        if u not in all_urls:
            all_urls.append(u)
    feeds = url_check.load_feeds() if online.get("phish_feeds") else None
    url_reports = []
    for u in all_urls[:15]:
        r = url_check.analyze_url(u)
        if online:
            url_check.apply_online(r, online.get("rdap", False), online.get("expand", False), feeds)
        url_reports.append(r)

    # ---- scoring ----
    text_score = sum(h.weight for h in hits)
    combos = []
    if {"gift_card_payment", "crypto_payment", "unusual_payment"} & flag_ids and {"urgency", "threat", "secrecy"} & flag_ids:
        combos.append(("pressure_plus_payment", 2))
    if "authority_claim" in flag_ids and {"otp_request", "credential_request", "safe_account", "remote_access", "gift_card_payment"} & flag_ids:
        combos.append(("authority_plus_ask", 2))
    if "wrong_number_opener" in flag_ids and {"channel_switch", "crypto_payment", "too_good"} & flag_ids:
        combos.append(("pig_butchering_pattern", 2))
    text_score += sum(w for _, w in combos)
    url_score = max([max(0, r.score) for r in url_reports] or [0])
    url_score = min(url_score, 7)
    # A risky link needs *some* lure; but a lookalike link alone is still a medium risk.
    url_high = any(f.severity == "high" for r in url_reports for f in r.findings)
    if url_high:
        url_score = max(url_score, 4)
    email_score = min(max(0, em.score), 8) if em else 0
    reassure_score = sum(h.weight for h in reassure)
    if url_high or email_score >= 4:
        reassure_score = max(reassure_score, -1)
    has_ask = bool(ASK_FLAGS & flag_ids)
    email_bad = bool(em and any(f.weight >= 3 for f in em.findings))
    official_links = [r for r in url_reports if r.official_brand]
    if official_links and not url_high and not has_ask and not email_bad and "ai_directed_text" not in flag_ids:
        reassure_score -= 1
    if has_ask or "ai_directed_text" in flag_ids:
        reassure_score = max(reassure_score, 0)  # boilerplate can't cancel a money/code ask
    total = text_score + url_score + email_score + reassure_score
    if has_ask:
        total = max(total, 0)

    # ---- classification ----
    typ_scores = signals.score_typology(norm.text + " " + " ".join(r.host_decoded for r in url_reports), flag_ids)
    if top_scheme and top_scheme["strength"] >= 2:
        typ_scores = [(top_scheme["typology"], 99)] + [t for t in typ_scores if t[0] != top_scheme["typology"]]
    fraud_narrative = bool(FIRST_PERSON_UNAUTH.search(body)) and not (DECEPTION_FLAGS & flag_ids) and total < 12
    if fraud_narrative:
        label, typ = "fraud", "account_takeover"
    else:
        label = "scam" if total >= SCAM_THRESHOLD else "legit"
        typ = next((t for t, _ in typ_scores if t != "account_takeover"), "unclear") if label == "scam" else "none"
        if label == "scam" and typ == "unclear" and (url_high or email_score >= 4):
            typ = "credential_phishing"
    level = next((lv for lv in LEVELS if total >= lv[0]))
    if fraud_narrative:
        level = (0, "account_alert", "Unauthorized activity on your account (fraud, not a scam)")
    if label == "legit" and not coverage["covered"]:
        label, typ = "unsupported", "none"
        level = (0, "not_assessed", "Not assessed: the rules only cover English (%s). This is not a clearance" % coverage["reason"])
    distinct = len(flag_ids) + (1 if url_high else 0) + (1 if email_score >= 4 else 0)
    if label == "unsupported":
        confidence = "none"
    elif label == "legit":
        confidence = "medium" if total <= 0 and len(body) > 40 else "low"
    elif total >= 9 or (total >= 6 and distinct >= 3):
        confidence = "high"
    elif total >= 5:
        confidence = "medium"
    else:
        confidence = "low"

    # ---- ranked flags ----
    ranked = [{"id": h.id, "label": h.label, "weight": h.weight, "evidence": h.evidence} for h in hits]
    for r in url_reports:
        for f in r.findings:
            if f.weight > 0:
                ranked.append({"id": "url:" + f.flag, "label": f"Link {r.registrable_domain}: {f.flag.replace('_', ' ')}",
                               "weight": f.weight, "evidence": [f.evidence]})
    if em:
        for f in em.findings:
            if f.weight > 0:
                ranked.append({"id": "email:" + f.flag, "label": "Email: " + f.flag.replace("_", " "),
                               "weight": f.weight, "evidence": [f.evidence]})
    ranked.sort(key=lambda d: -d["weight"])
    reassuring = [{"id": h.id, "label": h.label, "evidence": h.evidence} for h in reassure]
    for r in (official_links if not has_ask and not email_bad else []):
        reassuring.append({"id": "url:official_domain", "label": f"Link goes to official domain {r.registrable_domain}", "evidence": []})
    if em:
        for f in em.findings:
            if f.weight < 0:
                reassuring.append({"id": "email:" + f.flag, "label": f.evidence, "evidence": []})

    info = taxonomy.TYPOLOGY.get(typ, {})
    do_now = list(taxonomy.DO_NOW_BY_TYPE.get(typ, []))
    if label != "fraud":
        do_now = (taxonomy.DO_NOW_GENERAL if label == "scam" else [NOT_CLEARANCE]) + do_now
    if "ai_directed_text" in flag_ids:
        do_now.insert(0, "This message contains instructions aimed at AI assistants or spam filters. Legitimate senders don't do that: "
                         "treat it as hostile, and don't let any AI tool act on it (reply, forward, click, or mark safe).")
    report_keys = list(taxonomy.REPORT_BY_TYPE.get(typ, ["ftc"])) if label in ("scam", "fraud") else []
    if label == "scam" and channel == "sms" and "sms7726" not in report_keys:
        report_keys.insert(0, "sms7726")
    if label == "scam" and channel == "email" and "apwg" not in report_keys:
        report_keys.insert(0, "apwg")
    if label == "scam" and channel == "call" and "fcc" not in report_keys:
        report_keys.append("fcc")
    reporting = [{"name": taxonomy.LINKS[k][0], "url": taxonomy.LINKS[k][1]} for k in report_keys]
    cc, cc_source = (country.lower(), "given") if country else (taxonomy.guess_country(body), "guessed")
    if cc not in taxonomy.COUNTRY_REPORTING:
        cc, cc_source = "us", "assumed"
    country_note = None
    if cc != "us" and label in ("scam", "fraud"):
        info_c = taxonomy.COUNTRY_REPORTING[cc]
        reporting = [{"name": n, "url": u} for n, u in info_c["report"]]
        if "platform" in report_keys:
            reporting.append({"name": taxonomy.LINKS["platform"][0], "url": None})
        country_note = info_c.get("note")
    if cc_source == "assumed" and label in ("scam", "fraud"):
        country_note = ("Reporting links are for the U.S. Tell me your country for local ones "
                        "(UK, India, Australia, Canada, Ireland/EU, New Zealand are built in).")

    return {
        "tool": "scam-signal", "version": VERSION, "channel": channel,
        "label": label, "risk_level": level[1], "verdict": level[2], "confidence": confidence,
        "language_covered": coverage["covered"], "prompt_injection_detected": "ai_directed_text" in flag_ids,
        "obfuscation": {"zero_width": norm.zero_width, "spaced": norm.spaced, "leet": norm.leet, "confusables": norm.confusables}
        if norm.obfuscated else None,
        "score": {"total": total, "text": text_score, "links": url_score, "email": email_score,
                  "reassuring": reassure_score, "combos": [c for c, _ in combos]},
        "typology": {"id": typ, **info} if typ != "none" else {"id": "none"},
        "typology_candidates": typ_scores[:3],
        "red_flags": ranked,
        "reassuring_signals": reassuring,
        "do_now": do_now,
        "if_already_acted": taxonomy.IF_ALREADY_ACTED if label in ("scam", "fraud") else [],
        "report_to": reporting if label != "unsupported" else [],
        "country": {"code": cc, "source": cc_source, "note": country_note},
        "urls": [r.to_dict() for r in url_reports],
        "email": em.to_dict() if em else None,
        "chat": chat,
        "network_used": {k: v for k, v in online.items() if v},
    }


def to_markdown(res: dict) -> str:
    L = []
    L.append("# scam-signal report\n")
    L.append(f"**Verdict:** {res['verdict']}  \n**Risk:** {res['risk_level'].replace('_', ' ').upper()} · "
             f"**Confidence:** {res['confidence']} · **Channel:** {res['channel']}\n")
    t = res["typology"]
    if t.get("id") not in (None, "none"):
        L.append(f"## Likely type: {t['name']}\n")
        L.append(f"{t['summary']}\n")
        L.append(f"- FTC Consumer Sentinel: {t['ftc']}\n- FBI IC3: {t['ic3']}\n- CFPB: {t['cfpb']}")
        stage = {"scam": "scam (you would be authorizing a payment or action under deception)",
                 "non_consensual_fraud": "non-consensual fraud (activity you did not authorize)",
                 "ambiguous": "ambiguous"}[t["stage1"]]
        L.append(f"- Authorized-vs-unauthorized: {stage}\n")
    if res["red_flags"]:
        L.append("## Red flags (strongest first)\n")
        for i, f in enumerate(res["red_flags"][:10], 1):
            ev = f" \"{f['evidence'][0]}\"" if f["evidence"] else ""
            L.append(f"{i}. **{f['label']}**:{ev}")
        L.append("")
    if res.get("chat") and res["chat"]["schemes"]:
        c = res["chat"]
        L.append(f"## Conversation stages ({c['messages']} messages, {c['first']} to {c['last']})\n")
        for sc in c["schemes"][:2]:
            L.append(f"**{sc['name']}**: {sc['stages_reached']}/{sc['total_stages']} stages" + ("" if sc["in_order"] else " (out of order)"))
            for h in sc["hits"]:
                L.append(f"- {h['label']}: msg {h['index'] + 1} ({h['date']}): \"{h['quote'][:140]}\"")
            L.append("")
    if res["reassuring_signals"]:
        L.append("## Reassuring signs (scammers can fake these too)\n")
        for f in res["reassuring_signals"]:
            L.append(f"- {f['label']}")
        L.append("")
    L.append("## What to do now\n")
    for s in res["do_now"]:
        L.append(f"- {s}")
    if res["if_already_acted"]:
        L.append("\n## If you already responded, paid or shared info\n")
        for s in res["if_already_acted"]:
            L.append(f"- {s}")
    if res["report_to"]:
        cn = res.get("country") or {}
        where = taxonomy.COUNTRY_REPORTING.get(cn.get("code", "us"), {}).get("name", "")
        L.append(f"\n## Where to report ({where})\n" if where else "\n## Where to report\n")
        for r in res["report_to"]:
            L.append(f"- {r['name']}" + (f": {r['url']}" if r["url"] else ""))
        if cn.get("note"):
            L.append(f"\n_{cn['note']}_")
    L.append("\n---\n*scam-signal v%s: local rule-based signals (score %s). This is guidance, not a guarantee and not legal advice. "
             "When in doubt, contact the organization through a channel you look up yourself.*" % (res["version"], res["score"]["total"]))
    return "\n".join(L) + "\n"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Analyze a suspicious message, email, call note or link.")
    src = ap.add_mutually_exclusive_group()
    src.add_argument("--text", help="message text")
    src.add_argument("--file", help=".txt / .eml / .msg / transcript file ('-' for stdin)")
    ap.add_argument("--url", action="append", default=[], help="URL to analyze (repeatable)")
    ap.add_argument("--channel", default="unknown", choices=["sms", "email", "call", "dm", "chat", "complaint", "web", "unknown"])
    ap.add_argument("--country", help="reporting country: us, uk, in, au, ca, ie, eu, nz (default: guess from the message, else us)")
    ap.add_argument("--rdap", action="store_true", help="domain age via rdap.org (sends domain only)")
    ap.add_argument("--expand", action="store_true", help="expand known URL shorteners (HEAD only)")
    ap.add_argument("--phish-feeds", action="store_true", help="download public phishing feeds, match locally")
    ap.add_argument("--online", action="store_true", help="enable all optional lookups")
    ap.add_argument("--json", action="store_true", help="print JSON instead of markdown")
    ap.add_argument("--save", help="write a PII-redacted markdown report to this path")
    a = ap.parse_args(argv)
    online = {"rdap": a.rdap or a.online, "expand": a.expand or a.online, "phish_feeds": a.phish_feeds or a.online}
    if not any(online.values()):
        online = {}

    text, raw = "", None
    if a.text is not None:
        text = a.text
    elif a.file:
        if a.file == "-":
            data = sys.stdin.buffer.read()
        else:
            data = Path(a.file).read_bytes()
        if data[:8] == email_headers.CFB_MAGIC or (a.file.lower().endswith((".eml", ".msg"))):
            raw = data
        else:
            text = data.decode("utf-8", "replace")
            if looks_like_email(text):
                raw = data
    elif not a.url and not sys.stdin.isatty():
        text = sys.stdin.read()
    if raw is not None and raw[:8] == email_headers.CFB_MAGIC:
        raw = email_headers.msg_to_message(raw).as_bytes()
    res = analyze(text, raw_email=raw, urls=a.url, channel=a.channel, online=online, country=a.country)
    out = json.dumps(res, indent=2, default=str) if a.json else to_markdown(res)
    print(out)
    if a.save:
        Path(a.save).write_text(redact.redact(to_markdown(res)), encoding="utf-8")
        print(f"(redacted report saved to {a.save})", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
