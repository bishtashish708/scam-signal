"""Rule-based red-flag and typology engine for scam-signal (stdlib only).

This is a transparent, deterministic BASELINE. In the skill, Claude reads its
output alongside the message itself and makes the final call. The engine is
deliberately explainable: every flag carries the sentence that triggered it.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

# --------------------------------------------------------------------------
# Red flags: (id, label, weight, [patterns])
# Patterns are matched case-insensitively against the message text.
# --------------------------------------------------------------------------

_NEG = r"(?:never|don'?t|do not|won'?t|will not|no one|nobody|not)"

FLAGS: list[tuple[str, str, int, list[str]]] = [
    ("safe_account", "Asks you to move money to a 'safe'/'secure'/new account", 5, [
        r"\b(?:safe|secure|protected|new) (?:bank )?account\b.{0,60}\b(?:move|transfer|send|protect|deposit)",
        r"\b(?:move|transfer|send)\b.{0,40}\b(?:your )?(?:money|funds|savings|balance)\b.{0,40}\b(?:safe|secure|protect|new account)",
        r"\bprotect (?:your|the) (?:money|funds|savings)\b",
        r"\bzelle (?:it |the money |yourself )?to yourself\b",
        r"\bsend (?:a |the )?(?:payment|money) to yourself\b",
    ]),
    ("otp_request", "Asks you to share or read back a one-time/verification code", 5, [
        r"\b(?:read|give|tell|provide|send|share|confirm|repeat|forward)\b(?: \w+){0,3} (?:the |that |your |this )?(?:\d[- ]?digit )?(?:verification |security |confirmation |one[- ]time |authentication |google voice )?(?:code|passcode|otp|pin)\b",
        r"\b(?:code|passcode) (?:we|that) (?:just )?(?:sent|texted)\b.{0,40}\b(?:read|tell|give|provide|confirm)",
        r"\bverify (?:that )?you(?:'re| are) (?:real|a real person|not a (?:bot|scammer))\b",
    ]),
    ("credential_request", "Asks for passwords, PINs, SSN, card or account details", 4, [
        r"\b(?:confirm|verify|update|provide|enter|send|validate|re-?enter)\b(?: \w+){0,3} (?:your )?(?:password|pin|ssn|social security(?: number)?|account (?:number|details|information|info)|login (?:details|credentials)|card (?:number|details|information)|banking (?:details|information)|date of birth|online banking)",
        r"\b(?:password|login) (?:expires?|will expire|has expired)\b",
        r"\bkeep (?:the )?same password\b",
    ]),
    ("gift_card_payment", "Demands payment by gift card", 5, [
        r"\b(?:gift ?cards?|itunes cards?|google play cards?|steam cards?|apple gift|ebay gift|target gift|vanilla (?:visa|card)|razer gold)\b",
        r"\bscratch (?:off )?the (?:back|silver)\b",
    ]),
    ("crypto_payment", "Asks for payment or deposits in cryptocurrency", 4, [
        r"\b(?:bitcoin|btc|usdt|tether|ethereum|eth|crypto ?currency|crypto)\b.{0,60}\b(?:send|deposit|pay|transfer|atm|wallet|address)\b",
        r"\b(?:send|deposit|pay|transfer)\b.{0,40}\b(?:bitcoin|btc|usdt|tether|crypto)\b",
        r"\b(?:bitcoin|crypto) (?:atm|kiosk|machine)\b",
        r"\bwallet address\b",
    ]),
    ("unusual_payment", "Pushes wire, P2P, cash courier or other hard-to-reverse payment", 3, [
        r"\b(?:western union|moneygram|wire (?:the |it |money|transfer)|wire transfer)\b",
        r"\b(?:send|pay|zelle|venmo|cash ?app)\b.{0,60}\b(?:via|through|with|on|by)? ?(?:zelle|venmo|cash ?app|paypal friends)\b",
        r"\b(?:courier|driver|someone) (?:will|to) (?:come|pick up|collect)\b.{0,40}\b(?:cash|money|package|envelope|gold)\b",
        r"\b(?:cash|money) in (?:a |an )?(?:box|envelope|package)\b",
        r"\bfriends (?:and|&) family\b",
        r"\bwithdraw (?:the )?cash\b",
    ]),
    ("urgency", "Creates urgency or a short deadline", 2, [
        r"\b(?:within|in the next|in) \d+ ?(?:hours?|hrs?|minutes?|mins?)\b",
        r"\b(?:immediately|urgent(?:ly)?|right away|right now|act now|asap|as soon as possible|final (?:notice|warning|reminder)|last (?:chance|warning|notice)|today only|expires? (?:today|tonight|soon)|before (?:midnight|it'?s too late|end of day))\b",
        r"\btime[- ]sensitive\b",
        r"\b(?:act fast|must act|many (?:people|others|applicants) are interested|first come,? first served)\b",
    ]),
    ("threat", "Threatens arrest, account closure, fines or other consequences", 3, [
        r"\b(?:arrest(?:ed)?|warrant|lawsuit|legal action|prosecut\w*|deport\w*|criminal charges?|jail)\b",
        r"\b(?:account|card|service|number|benefits?|license) (?:has been |will be |is |was )?(?:suspended|locked|frozen|closed|terminated|disabled|deactivated|restricted|blocked)\b",
        r"\b(?:late|penalty|additional) (?:fee|fine|charge)s?\b",
        r"\b(?:suspend|lock|freeze|close|terminate) your (?:account|card|number|license|benefits)\b",
    ]),
    ("secrecy", "Asks you to keep it secret or not to talk to your bank/family", 4, [
        rf"\b{_NEG} (?:tell|talk to|discuss (?:this )?with|mention (?:this|it) to|inform) (?:anyone|anybody|your bank|the bank|the teller|bank staff|(?:your )?(?:family|mom|dad|wife|husband|kids))\b",
        r"\bkeep (?:this|it) (?:confidential|secret|between us|private|quiet)\b",
        r"\bif (?:the bank|they|the teller) asks?\b.{0,40}\b(?:say|tell them)\b",
        r"\bbank (?:staff |employees? )?(?:may be|is|are) (?:involved|in on it|compromised)\b",
    ]),
    ("stay_on_line", "Pressures you to stay on the phone / not hang up", 3, [
        r"\b(?:stay on the (?:line|phone)|don'?t hang up|do not hang up|remain on the (?:line|phone)|keep me on the line)\b",
    ]),
    ("remote_access", "Wants remote access to your device", 5, [
        r"\b(?:anydesk|teamviewer|ultraviewer|quick ?assist|logmein|screenconnect|rustdesk|supremo|remote ?pc)\b",
        r"\bremote(?:ly)? (?:access|connect|control|into)\b",
        r"\b(?:download|install) (?:this|the|an?) (?:app|program|software)\b.{0,40}\b(?:so (?:i|we) can|to let (?:me|us)|for (?:me|us) to)\b",
    ]),
    ("authority_claim", "Claims to be a bank, government agency or well-known company", 2, [
        r"\b(?:this is|i am|i'm|we are|calling from|on behalf of|representative (?:of|from)|agent (?:of|from|with))\b.{0,30}\b(?:fraud (?:department|team|prevention)|security (?:team|department)|your bank|the bank|irs|internal revenue|social security|ssa|medicare|fbi|ftc|dea|homeland|border|marshals?|sheriff|police|amazon|apple|microsoft|paypal|zelle|geek squad|norton|mcafee|usps|customs)\b",
        r"\b(?:irs|internal revenue service|social security administration|federal trade commission|us marshals?|sheriff'?s (?:office|department)|department of (?:justice|treasury)|immigration (?:office|officer)|uscis)\b",
        r"\b(?:fraud|security) (?:department|team|alert center) (?:at|of|from)\b",
        r"\b(?:our|the) (?:fraud|security) (?:department|team|specialists?)\b",
    ]),
    ("callback_number", "Tells you to call a phone number given in the message", 2, [
        r"\b(?:call|contact|dial|reach|press \d+ or call)\b(?: \w+){0,4}\s*(?:at|on|:)?\s*(?:\+?1[ .-]*)?(?:\(?\d{3}\)?[ .-]*)?\d{3}[ .-]?\d{4}\b",
        r"\bif you did not (?:make|authorize|request|recognize)\b.{0,60}\bcall\b",
    ]),
    ("click_link", "Pushes you to click/tap a link to fix a problem", 2, [
        r"\b(?:click|tap|follow|visit|open|go to)\b(?: \w+){0,3} (?:the |this )?(?:link|here|below|url|button)\b",
        r"\b(?:click|tap|visit|go to)\b\s+(?:h(?:tt|xx)ps?://|www\.|[a-z0-9-]+\.(?:com|net|info|top|xyz|org|co))",
        r"\b(?:update|confirm|verify|pay|reschedule|resolve)\b.{0,40}\b(?:at|via|here|link)\b\s*:?\s*(?:h(?:tt|xx)ps?://|www\.)",
    ]),
    ("link_activation_trick", "Asks you to reply so a blocked link becomes clickable", 4, [
        r"\breply (?:with )?['\"]?y(?:es)?['\"]?\b.{0,60}\b(?:re-?open|exit|reactivate|activate the link|link)\b",
        r"\bcopy (?:the |this )?link (?:in|into|to) (?:your )?(?:browser|safari|chrome)\b",
    ]),
    ("too_good", "Promises winnings, guaranteed returns or free money", 4, [
        r"\b(?:guaranteed|risk[- ]free|no[- ]risk) (?:returns?|profits?|income|investment)\b",
        r"\b\d{1,3}(?:\.\d+)? ?% (?:daily|weekly|per day|a day|per week|monthly|returns?|profit|(?:last|this|every|a|per|in a) (?:week|day|month))\b",
        r"\b(?:i|we|she|he|they) (?:made|earned|got) \$?\d[\d,.]*(?: ?%|k)? (?:profit |return )?(?:last|this|in a|in one) (?:week|day|month)\b",
        r"\b(?:you(?:'ve| have) (?:won|been selected)|winner|congratulations\b.{0,40}\b(?:won|selected|prize))\b",
        r"\b(?:lottery|sweepstakes|jackpot|cash prize|inheritance|unclaimed (?:funds|money|inheritance)|beneficiary of)\b",
        r"\bdouble your (?:money|investment|bitcoin|crypto)\b",
        r"\bgrant\b.{0,30}\b(?:approved|eligible|qualif)",
    ]),
    ("advance_fee", "Requires a fee, tax or deposit before you can receive money", 4, [
        r"\b(?:pay|send|deposit)\b.{0,30}\b(?:fee|tax(?:es)?|deposit|processing|clearance|customs|release|activation|upgrade|unlock|verification|insurance) (?:fee|charge|payment|amount)?\b.{0,40}\b(?:receive|claim|release|unlock|withdraw|collect|get your)\b",
        r"\b(?:withdrawal|release|unlock|clearance|processing|activation) (?:fee|tax)\b",
        r"\b(?:recharge|top up|top-up) (?:your|the) (?:account|balance|wallet)\b",
    ]),
    ("overpayment", "Overpays and asks you to send back the difference", 5, [
        r"\b(?:overpaid|over-?payment|sent (?:you )?(?:too much|extra|more than)|accidentally (?:sent|refunded|transferred) (?:you )?(?:too much|extra|\$?\d))",
        r"\b(?:refund|send back|return|wire back|zelle back)\b(?: \w+){0,3} (?:the )?(?:difference|extra|excess|rest|remaining|balance)\b",
        r"\bdeposit (?:the|this) (?:check|cheque)\b.{0,80}\b(?:send|buy|transfer|zelle|wire)\b",
    ]),
    ("delivery_fee", "Missed delivery / unpaid toll / small fee pretext", 3, [
        r"\b(?:package|parcel|shipment|delivery|item)\b.{0,40}\b(?:could not be|couldn'?t be|was not|wasn'?t|unable to be|cannot be|on hold|failed|pending|suspended)\b",
        r"\b(?:incomplete|invalid|incorrect|unconfirmed) (?:address|zip|street|house number)\b",
        r"\b(?:unpaid|outstanding|overdue) (?:toll|tolls|balance|fee|invoice)\b",
        r"\b(?:redeliver|redelivery|re-?delivery|rescheduling fee|shipping fee of)\b",
        r"\btoll (?:service|road|balance|notice|bill)\b.{0,60}\b(?:pay|fee|fine|\$)",
    ]),
    ("remote_counterparty", "Seller/landlord/buyer can't meet or show the item in person", 3, [
        r"can'?t (?:show|meet|see you).{0,30}(?:in person|it|the (?:apartment|house|unit|item))",
        r"(?:out of the country|overseas|on a mission|traveling abroad|working abroad).{0,80}(?:keys?|ship|mail|deposit|send)",
        r"mail you the keys",
    ]),
    ("channel_switch", "Moves the conversation to WhatsApp/Telegram/another channel", 2, [
        r"\b(?:whatsapp|telegram|signal app|wechat|line app|kakao)\b",
        r"\b(?:text|message|contact|add) me (?:at|on)\b",
        r"\bmove (?:this|our|the) (?:chat|conversation)\b",
    ]),
    ("wrong_number_opener", "Unsolicited 'wrong number' / cold friendly opener", 3, [
        r"^\s*(?:hi|hello|hey|good (?:morning|evening|afternoon))[,!.\s]+(?:is this|are you)\s+[a-z]+\b",
        r"\b(?:sorry|oops)[,!.]? (?:i think )?(?:i have |i've got |i got |you have |you've got )?(?:the |a )?wrong (?:number|person)\b",
        r"\bis this (?:mr\.?|mrs\.?|ms\.?)? ?[a-z]+(?:'s)? (?:number|phone)\b",
    ]),
    ("romance_pretext", "Online relationship that turns into money requests", 3, [
        r"\b(?:my love|darling|sweetheart|honey|babe|dear one|my queen|my king)\b.{0,120}\b(?:money|send|pay|loan|help me|fees?|ticket|customs|hospital|bills?)\b",
        r"\b(?:deployed|deployment|oil rig|offshore|peacekeeping|un mission)\b.{0,80}\b(?:money|send|pay|fees?|leave|ticket)\b",
        r"\bcan'?t (?:video ?call|facetime|video chat)\b",
        r"\b(?:met|talking|been chatting) (?:on|through|via) (?:a )?(?:dating|tinder|hinge|bumble|facebook|instagram)\b",
    ]),
    ("family_pretext", "Claims a relative is in urgent trouble", 4, [
        r"\b(?:grandma|grandpa|grandmother|grandfather|nana|mom|mum|dad|auntie|uncle)\b.{0,40}\b(?:it'?s me|i'?m in trouble|need help|been arrested|in jail|accident|hospital)\b",
        r"\b(?:i'?ve been|i was|i got|your (?:grandson|granddaughter|son|daughter) (?:has been|was)) arrested\b",
        r"\b(?:bail|bond) (?:money|amount|is set)\b",
        r"\b(?:this is my new number|lost my phone|my phone (?:broke|is broken))\b",
        r"\b(?:don'?t|do not) tell (?:mom|dad|my parents|anyone in the family)\b",
    ]),
    ("job_too_easy", "Easy-money job: pay to work, tasks, or check-based equipment purchase", 3, [
        r"\b(?:earn|make|get paid)\b.{0,15}\$\s?\d[\d,]*\+? ?(?:-|to)? ?\$?\d*\s*(?:per|a|/|an|each)\s*(?:day|hour|hr|week|task)\b",
        r"\b(?:simple|easy) (?:online )?(?:tasks?|jobs?|work)\b",
        r"\b(?:rate|review|like|optimi[sz]e|boost)\b.{0,20}\b(?:products?|apps?|hotels?|videos?|orders?|data)\b.{0,40}\b(?:commission|earn|paid|income)\b",
        r"\b(?:mystery shopper|secret shopper|personal assistant|package reshipp?ing)\b",
        r"\bpurchase (?:your |the )?(?:equipment|software|supplies)\b.{0,60}\b(?:check|vendor|reimburs)",
        r"\bpart[- ]time\b.{0,60}\b(?:whatsapp|telegram|daily pay|per day)\b",
    ]),
    ("sextortion", "Threatens to expose intimate images or recordings", 5, [
        r"\b(?:recorded|video of you|webcam|intimate|explicit|nude|naked|pornograph\w*|adult (?:site|website|content))\b.{0,120}\b(?:send|pay|bitcoin|btc|contacts|friends|family|colleagues|release|expose|share)\b",
        r"\b(?:i have|we have) (?:hacked|access to) your (?:device|computer|phone|camera|email)\b",
    ]),
    ("tech_scare", "Says your device is infected/hacked or a pricey renewal was charged", 3, [
        r"\b(?:your )?(?:computer|device|pc|phone|mac|ip address|network) (?:is|has been|was) (?:infected|hacked|compromised|blocked|at risk)\b",
        r"\b(?:virus|malware|trojan|spyware) (?:detected|found|alert)\b",
        r"\b(?:subscription|membership|plan|antivirus|protection)\b.{0,40}\b(?:renewed|auto-?renew\w*|will be charged|has been charged)\b.{0,60}\$\s?\d{2,}",
        r"\b(?:to cancel|for a refund|if you did not (?:authorize|make|request)).{0,40}\bcall\b",
    ]),
    ("unauthorized_activity", "Describes transactions or account access you didn't make or approve", 3, [
        r"\b(?:i|we) (?:did not|didn'?t|never) (?:make|authorize|send|approve|initiate|recogni[sz]e)\b",
        r"\b(?:i|we)\b[^.]{0,60}\b(?:did not|didn'?t|never) (?:make|authorize|send|approve|initiate)\b",
        r"\b(?:unauthori[sz]ed|fraudulent) (?:transactions?|transfers?|charges?|withdrawals?|payments?|access|login)\b",
        r"\bsomeone (?:else )?(?:hacked|accessed|logged into|got into|broke into|took over) (?:my|our) (?:account|email|phone|app)\b",
        r"\b(?:sim[- ]swap|ported my (?:number|phone)|my phone (?:lost|had no) service)\b",
        r"\bwithout my (?:knowledge|permission|authori[sz]ation|consent)\b",
    ]),
]

# Signals that make a message LESS likely to be a scam. Weighted conservatively,
# because scammers copy legitimate boilerplate.
REASSURING: list[tuple[str, str, int, list[str]]] = [
    ("dont_share_code", "Standard 'don't share this code' wording in a code you requested", -2, [
        rf"\b(?:{_NEG}) (?:share|give)\b.{{0,30}}\b(?:this |the )?code\b",
        r"\b(?:we|.{0,20}) will never (?:ask|call|text|email)\b.{0,30}\b(?:for )?(?:this |the |your )?code\b",
    ]),
    ("verify_via_official", "Tells you to use the official app/number you already have", -2, [
        r"\b(?:number|phone number) on the back of your (?:card|debit card|credit card)\b",
        r"\b(?:log ?in|sign ?in|open|go)\b.{0,20}\b(?:the|our|your) (?:official )?(?:app|website)\b.{0,30}\b(?:directly|yourself|instead of)\b",
        r"\btype (?:the address|[a-z0-9.-]+\.(?:com|gov|org)) (?:into|in) your browser\b",
    ]),
    ("yes_no_alert", "Classic card-alert format: reply YES/NO, no link", -1, [
        r"\breply (?:yes|y|1) (?:if|or) (?:no|n|2)\b",
        r"\breply (?:yes|y) if you (?:made|authorized|attempted)\b",
    ]),
    ("in_person_meetup", "Proposes an in-person / platform-protected transaction", -2, [
        r"\b(?:meet|meeting|pick (?:it )?up) (?:in person|at (?:the )?(?:police station|bank|store|lobby|safe exchange))\b",
        r"\b(?:pay|purchase|checkout) (?:through|via|on) (?:the )?(?:app|platform)(?:'s)? (?:checkout|protected)\b",
    ]),
]

# --------------------------------------------------------------------------
# Typology cues (scored separately from risk)
# --------------------------------------------------------------------------

TYPOLOGY_CUES: dict[str, tuple[list[str], list[str]]] = {
    # typology: (strong flags that imply it, keyword patterns)
    "bank_impersonation": (["safe_account"], [
        r"\b(?:fraud (?:department|team|alert|prevention|specialist)|your bank|bank'?s? (?:security|fraud)|(?:chase|wells fargo|bank of america|citi(?:bank)?|capital one|us bank|pnc|truist|navy federal|usaa|td bank|chime) (?:fraud|security|alert|bank))\b",
        r"\b(?:suspicious|unusual|unauthori[sz]ed) (?:zelle|transfer|transaction|charge|activity|login|sign-?in)\b.{0,80}\b(?:call|reply|verify|code|cancel|reverse|press)\b",
        r"\b(?:reverse|cancel|stop) (?:the|this|that) (?:transaction|transfer|payment|charge)\b",
        r"\bzelle\b",
    ]),
    "government_impersonation": ([], [
        r"\b(?:irs|internal revenue|social security|ssa|medicare|fbi|ftc|dea|homeland security|customs and border|us marshals?|sheriff|police|court|jury duty|warrant|uscis|immigration|treasury|federal agent|tax (?:debt|owed|return|refund))\b",
    ]),
    "tech_support_refund": (["remote_access", "tech_scare"], [
        r"\b(?:microsoft|windows|apple support|icloud|geek squad|norton|mcafee|antivirus|tech(?:nical)? support|help ?desk)\b",
        r"\b(?:refund (?:department|team)|accidentally refunded|renewal|auto-?renew\w*|invoice)\b",
    ]),
    "delivery_toll_smishing": (["delivery_fee"], [
        r"\b(?:usps|ups|fedex|dhl|postal service|post office|package|parcel|shipment|delivery|toll|e-?zpass|sunpass|fastrak|txtag|turnpike|dmv)\b",
    ]),
    "credential_phishing": (["credential_request"], [
        r"\b(?:verify|confirm|update|validate|reactivate|unlock|restore) (?:your )?(?:account|identity|information|email|mailbox|profile|apple id|password)\b",
        r"\b(?:unusual|suspicious|new) (?:sign-?in|login|log-?in) (?:attempt|activity)\b",
        r"\b(?:mailbox|storage) (?:is )?(?:full|almost full|quota)\b",
        r"\b(?:shared (?:a )?(?:document|file) with you|docusign|review (?:and sign|document))\b",
    ]),
    "marketplace": ([], [
        r"\b(?:marketplace|listing|craigslist|offerup|ebay|poshmark|mercari|facebook market|for sale|still available|the item|buyer|seller|shipping agent|courier service)\b",
        r"\b(?:rental|apartment|landlord|lease|deposit to hold|hold the (?:unit|apartment|puppy)|puppy|kitten|tickets?)\b",
        r"\bgoogle voice\b",
        r"\b(?:zelle|cash ?app|venmo) (?:business|account) (?:upgrade|limit)\b",
        r"\bbusiness (?:account )?upgrade\b",
        r"\b(?:buy your|i want to buy|interested in (?:your|the) (?:item|couch|car|bike)|my (?:mover|movers|shipping agent|cousin will pick))\b",
    ]),
    "romance": (["romance_pretext"], [
        r"\b(?:love you|my love|darling|sweetheart|soulmate|dating|our future|marry|relationship|lonely|widow(?:er|ed)?)\b",
    ]),
    "investment_crypto": ([], [
        r"\b(?:invest\w*|trading (?:platform|app|account|firm|signals?)|signals|crypto\w*|bitcoin|usdt|forex|mining pool|liquidity|returns?|portfolio|profits?|withdraw(?:al)?|exchange|financial (?:advisor|mentor)|my (?:uncle|aunt|mentor) (?:is|works))\b",
    ]),
    "employment_task": (["job_too_easy"], [
        r"\b(?:job|hiring|position|recruit\w*|remote work|work from home|part[- ]time|salary|onboarding|hr department|interview|tasks?|commission|equipment|employment)\b",
    ]),
    "family_emergency": (["family_pretext"], [
        r"\b(?:grandson|granddaughter|grandma|grandpa|nephew|niece|son|daughter|mom|dad|it'?s me|bail|jail|accident|hospital|lawyer|attorney|public defender)\b",
    ]),
    "prize_advance_fee": (["too_good"], [
        r"\b(?:won|winner|prize|lottery|sweepstakes|jackpot|inheritance|beneficiary|unclaimed|grant|compensation|award|selected)\b",
    ]),
    "extortion": (["sextortion"], [
        r"\b(?:recorded|webcam|video of you|explicit|intimate|expose|your contacts|i know your password)\b",
    ]),
    "account_takeover": (["unauthorized_activity"], [
        r"\b(?:i (?:did not|didn'?t|never) (?:make|authorize|send|approve)|sim[- ]swap|hacked|someone (?:accessed|logged into)|without my (?:knowledge|permission))\b",
    ]),
}

# --------------------------------------------------------------------------


@dataclass
class Hit:
    id: str
    label: str
    weight: int
    evidence: list[str] = field(default_factory=list)


def _sentences(text: str) -> list[str]:
    parts = re.split(r"(?<=[.!?])\s+|\n+", text)
    return [p.strip() for p in parts if p.strip()]


def _quote(text: str, m: re.Match, limit: int = 180) -> str:
    """Return the sentence containing the match, trimmed around it."""
    start = max(text.rfind("\n", 0, m.start()), max(text.rfind(". ", 0, m.start()), text.rfind("! ", 0, m.start()), text.rfind("? ", 0, m.start())))
    start = 0 if start < 0 else start + 1
    end_candidates = [i for i in (text.find("\n", m.end()), text.find(". ", m.end()), text.find("! ", m.end()), text.find("? ", m.end())) if i >= 0]
    end = min(end_candidates) + 1 if end_candidates else len(text)
    q = text[start:end].strip()
    if len(q) > limit:
        a = max(0, m.start() - start - 60)
        q = ("…" if a else "") + q[a: a + limit].strip() + "…"
    return q


def find_flags(text: str, table=FLAGS) -> list[Hit]:
    hits: list[Hit] = []
    low = text
    for fid, label, weight, pats in table:
        ev: list[str] = []
        for p in pats:
            for m in re.finditer(p, low, re.I | re.M | re.S):
                q = _quote(text, m)
                if fid == "otp_request" and re.search(rf"\b{_NEG}\b[^.]{{0,25}}\b(?:share|give|tell|read|provide|send)\b", q, re.I):
                    continue  # "never share this code" is a reassuring cue, not a request
                if fid == "callback_number" and re.search(r"back of your (?:card|debit|credit)", q, re.I):
                    continue
                if q not in ev:
                    ev.append(q)
                if len(ev) >= 2:
                    break
            if len(ev) >= 2:
                break
        if ev:
            hits.append(Hit(fid, label, weight, ev))
    return hits


def score_typology(text: str, flag_ids: set[str]) -> list[tuple[str, int]]:
    scores = {}
    for typ, (strong, kws) in TYPOLOGY_CUES.items():
        s = sum(4 for f in strong if f in flag_ids)
        for p in kws:
            s += min(3, len(re.findall(p, text, re.I)))
        if s:
            scores[typ] = s
    # disambiguation nudges
    if "account_takeover" in scores and not ({"otp_request", "safe_account", "remote_access", "credential_request"} & flag_ids):
        scores["account_takeover"] += 2
    if "overpayment" in flag_ids:
        scores["marketplace"] = scores.get("marketplace", 0) + 2
        scores["employment_task"] = scores.get("employment_task", 0) + 1
        scores["tech_support_refund"] = scores.get("tech_support_refund", 0) + 1
    if "crypto_payment" in flag_ids or "too_good" in flag_ids:
        scores["investment_crypto"] = scores.get("investment_crypto", 0) + 1
    if "otp_request" in flag_ids and "marketplace" in scores:
        scores["marketplace"] += 1
    return sorted(scores.items(), key=lambda kv: -kv[1])
