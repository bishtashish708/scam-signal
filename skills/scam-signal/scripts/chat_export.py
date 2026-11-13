#!/usr/bin/env python3
"""Parse WhatsApp / Telegram chat exports and detect multi-message scam progressions (stdlib only).

Long-con scams (pig-butchering, job/task, romance) look harmless message by message;
the signal is the *progression*: friendly opener -> trust -> money. This module
splits an export into messages and reports which stages of each scheme appear,
in what order, with the first quote and timestamp for each stage.

Supported inputs:
  * WhatsApp iOS export      [1/14/26, 9:02:11 PM] Name: message
  * WhatsApp Android export  1/14/26, 21:02 - Name: message
  * Telegram text export     Name, [14.01.26 21:02]   (message on following lines)
  * Telegram JSON export     result.json  {"messages": [{"date", "from", "text"}]}

Usage:
    python3 chat_export.py "WhatsApp Chat with Amy.txt"
    python3 chat_export.py result.json --json
How to export: WhatsApp > chat > contact name > Export Chat > Without Media.
Telegram Desktop > chat > ... > Export chat history (JSON or HTML/text).
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path

_DT = r"\d{1,4}[/.\-]\d{1,2}[/.\-]\d{2,4}"
_TM = r"\d{1,2}[:.]\d{2}(?:[:.]\d{2})?(?:[\s  ]?[AaPp]\.?[Mm]\.?)?"
WA_IOS = re.compile(rf"^[‎‏]?\[({_DT}),?\s+({_TM})\]\s+([^:]{{1,60}}?):\s?(.*)$")
WA_ANDROID = re.compile(rf"^[‎‏]?({_DT}),?\s+({_TM})\s+[-–]\s+([^:]{{1,60}}?):\s?(.*)$")
TG_TEXT = re.compile(rf"^(.{{1,60}}?),\s+\[({_DT})\s+({_TM})\]\s*$")
SYSTEM = re.compile(r"(?i)messages and calls are end-to-end encrypted|<media omitted>|this message was deleted|"
                    r"created group|added you|changed the subject|security code changed")


@dataclass
class Msg:
    date: str
    time: str
    sender: str
    text: str


def _from_json(data: dict) -> list[Msg]:
    out = []
    for m in data.get("messages", []):
        if m.get("type", "message") != "message":
            continue
        t = m.get("text", "")
        if isinstance(t, list):
            t = "".join(x if isinstance(x, str) else x.get("text", "") for x in t)
        d = str(m.get("date", ""))
        out.append(Msg(d[:10], d[11:16], str(m.get("from") or m.get("actor") or "?"), t))
    return out


def parse(text: str) -> list[Msg]:
    """Return messages, or [] if this doesn't look like a chat export."""
    s = text.lstrip("﻿")
    if s.lstrip().startswith("{"):
        try:
            return _from_json(json.loads(s))
        except (ValueError, AttributeError):
            return []
    msgs: list[Msg] = []
    for raw in s.splitlines():
        line = raw.rstrip()
        m = WA_IOS.match(line) or WA_ANDROID.match(line)
        if m:
            d, t, who, body = m.groups()
            msgs.append(Msg(d, t.replace(" ", " "), who.strip(), body))
            continue
        m = TG_TEXT.match(line)
        if m:
            who, d, t = m.groups()
            msgs.append(Msg(d, t, who.strip(), ""))
            continue
        if msgs and line.strip():
            msgs[-1].text = (msgs[-1].text + "\n" + line).strip() if msgs[-1].text else line.strip()
    msgs = [m for m in msgs if m.text and not SYSTEM.search(m.text)]
    return msgs if len(msgs) >= 3 else []


# --------------------------------------------------------------------------
# Stage models. Each stage: (id, label, patterns). Order matters.
# --------------------------------------------------------------------------

SCHEMES: dict[str, dict] = {
    "pig_butchering": {
        "typology": "investment_crypto",
        "name": "Pig-butchering (relationship investment scam)",
        "stages": [
            ("opener", "Unsolicited or 'wrong number' opener", [
                r"\b(?:wrong (?:number|person)|is this (?:mr\.?|mrs\.?|ms\.?)? ?[a-z]+\b|sorry to bother|did i (?:text|message) the wrong|we met at|got your number from)\b",
                r"^(?:hi|hello|hey)[!,. ]+(?:is this|are you) [a-z]+\b",
            ]),
            ("rapport", "Builds friendship / trust", [
                r"\b(?:where are you from|what do you do|nice to (?:meet|chat)|my name is|good (?:morning|night) (?:dear|friend|my friend)|how was your day|let'?s be friends|what a coincidence|fate|i live in|i'?m from)\b",
            ]),
            ("investment_hook", "Brings up their trading/crypto success", [
                r"\b(?:crypto\w*|bitcoin|btc|usdt|eth|forex|gold (?:trading|futures)|trading|invest\w*|my (?:uncle|aunt|mentor|teacher)|insider|signals?|contract trading|liquidity mining|arbitrage|profits?|returns?)\b",
            ]),
            ("platform", "Steers you to a specific platform/app and a first deposit", [
                r"\b(?:download|register|sign up|open an account)\b.{0,60}\b(?:app|platform|exchange|site|link)\b",
                r"\b(?:deposit|top up|transfer|send)\b.{0,40}\b(?:usdt|usdc|btc|eth|crypto|\$?\d[\d,]*)\b",
                r"\b(?:wallet address|trc-?20|erc-?20|customer service will (?:help|guide))\b",
            ]),
            ("extraction", "Blocks withdrawal until you pay more (tax/fee/'frozen')", [
                r"\b(?:withdraw\w*)\b.{0,80}\b(?:tax|fee|deposit|margin|frozen|locked|verification|insurance|unlock|vip|credit score)\b",
                r"\b(?:account (?:is )?(?:frozen|locked|suspended)|pay (?:the )?(?:tax|fee) (?:first|to withdraw)|personal income tax|risk (?:control|deposit))\b",
            ]),
        ],
    },
    "job_task": {
        "typology": "employment_task",
        "name": "Job / task scam",
        "stages": [
            ("recruit", "Unsolicited recruiter / easy remote job", [
                r"\b(?:recruit\w*|hiring|part[- ]time|remote (?:job|work|position)|flexible (?:hours|job|position)|hr (?:department|manager)|staffing agency|daily (?:salary|pay|income))\b",
            ]),
            ("tasks", "Simple 'tasks' with commission (rate, like, boost)", [
                r"\b(?:tasks?|orders?|ratings?|reviews?|likes?|optimi[sz]\w*|boost\w*|data)\b.{0,60}\b(?:commission|earn\w*|reward|income|profit)\b",
                r"\bcommission\b",
            ]),
            ("prepay", "You must deposit your own money to continue / withdraw", [
                r"\b(?:recharge|top[- ]?up|prepaid (?:task|order)|combo (?:task|order)|merge order|negative balance|lucky order|deposit)\b",
                r"\b(?:pay|send|transfer)\b.{0,40}\b(?:to (?:continue|unlock|complete|withdraw)|usdt|crypto)\b",
            ]),
        ],
    },
    "romance": {
        "typology": "romance",
        "name": "Romance scam",
        "stages": [
            ("affection", "Fast affection / love-bombing", [
                r"\b(?:my love|darling|sweetheart|honey|babe|soulmate|miss you|love you|my heart|dear one|god brought you|my queen|my king)\b",
            ]),
            ("distance", "Can't meet or video call; abroad/deployed", [
                r"\b(?:can'?t (?:video|facetime|call|meet)|camera (?:is )?broken|deployed|oil rig|offshore|peacekeeping|overseas|abroad|ship|military)\b",
            ]),
            ("crisis", "Sudden crisis", [
                r"\b(?:hospital|surgery|customs|stuck|stranded|accident|arrested|frozen (?:account|funds)|visa|ticket|lawyer|clearance|inheritance|package (?:held|stuck))\b",
            ]),
            ("money", "Asks you for money", [
                r"\b(?:send|wire|lend|loan|borrow|pay|transfer|zelle|western union|gift ?cards?|bitcoin|crypto|cash ?app)\b.{0,60}\b(?:money|\$?\d[\d,]*|dollars|funds|fee|cards?|it|me)\b",
            ]),
        ],
    },
}


@dataclass
class StageHit:
    stage: str
    label: str
    index: int
    date: str
    sender: str
    quote: str


@dataclass
class SchemeResult:
    scheme: str
    name: str
    typology: str
    stages_reached: int
    total_stages: int
    in_order: bool
    reached_money_stage: bool
    hits: list[StageHit] = field(default_factory=list)

    @property
    def strength(self) -> int:
        """0 = nothing, 1 = weak, 2 = suspicious progression, 3 = strong full pattern."""
        if self.stages_reached >= 3 and self.reached_money_stage:
            return 3 if self.in_order else 2
        if self.stages_reached >= 2 and self.reached_money_stage:
            return 2
        return 1 if self.stages_reached >= 2 else 0


def detect_stages(msgs: list[Msg]) -> list[SchemeResult]:
    results = []
    for key, sch in SCHEMES.items():
        hits: list[StageHit] = []
        for sid, label, pats in sch["stages"]:
            for i, m in enumerate(msgs):
                hit = next((re.search(p, m.text, re.I | re.M) for p in pats if re.search(p, m.text, re.I | re.M)), None)
                if hit:
                    q = m.text if len(m.text) <= 160 else m.text[max(0, hit.start() - 60):hit.start() + 100] + "…"
                    hits.append(StageHit(sid, label, i, f"{m.date} {m.time}".strip(), m.sender, q.replace("\n", " ")))
                    break
        order = [h.index for h in hits]
        last_sid = sch["stages"][-1][0]
        results.append(SchemeResult(key, sch["name"], sch["typology"], len(hits), len(sch["stages"]),
                                    order == sorted(order), any(h.stage == last_sid for h in hits), hits))
    return sorted(results, key=lambda r: (-r.strength, -r.stages_reached))


def summarize(msgs: list[Msg]) -> dict:
    res = detect_stages(msgs)
    senders: dict[str, int] = {}
    for m in msgs:
        senders[m.sender] = senders.get(m.sender, 0) + 1
    return {
        "messages": len(msgs),
        "participants": senders,
        "first": f"{msgs[0].date} {msgs[0].time}" if msgs else "",
        "last": f"{msgs[-1].date} {msgs[-1].time}" if msgs else "",
        "schemes": [dict(asdict(r), strength=r.strength) for r in res if r.strength >= 1],
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("file", help="WhatsApp .txt export, Telegram result.json or text export ('-' for stdin)")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)
    raw = sys.stdin.read() if a.file == "-" else Path(a.file).read_text(encoding="utf-8", errors="replace")
    msgs = parse(raw)
    if not msgs:
        print("Not recognized as a WhatsApp/Telegram export (need at least 3 messages).", file=sys.stderr)
        return 2
    s = summarize(msgs)
    if a.json:
        print(json.dumps(s, indent=2, ensure_ascii=False))
        return 0
    print(f"{s['messages']} messages from {', '.join(s['participants'])} ({s['first']} to {s['last']})")
    for sc in s["schemes"]:
        tag = {3: "STRONG", 2: "suspicious", 1: "weak"}[sc["strength"]]
        print(f"\n[{tag}] {sc['name']}: {sc['stages_reached']}/{sc['total_stages']} stages"
              + ("" if sc["in_order"] else " (out of order)"))
        for h in sc["hits"]:
            print(f"  - {h['label']} @ msg {h['index'] + 1} ({h['date']}, {h['sender']}): \"{h['quote']}\"")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
