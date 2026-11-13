"""Rule-based red-flag and typology engine for scam-signal (stdlib only).

This is a transparent, deterministic BASELINE. In the skill, Claude reads its
output alongside the message itself and makes the final call. The engine is
deliberately explainable: every flag carries the sentence that triggered it.
"""
from __future__ import annotations

import re
import unicodedata
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
        r"\bhave (?:your |the )?(?:card and (?:the )?)?(?:verification |security |one[- ]time )?(?:code|passcode|otp)s? (?:we send |we text |that we send )?(?:ready|handy|available)\b",
        r"\b(?:agent|specialist|representative|officer|technician|our team)\b.{0,60}\b(?:will )?(?:ask|need)s? (?:you )?(?:for )?(?:the |your )?(?:code|passcode|otp)\b",
    ]),
    ("credential_request", "Asks for passwords, PINs, SSN, card or account details", 4, [
        r"\b(?:confirm|verify|update|provide|enter|send|validate|re-?enter)\b(?: \w+){0,3} (?:your )?(?:password|pin|ssn|social security(?: number)?|account (?:number|details|information|info)|login (?:details|credentials)|card (?:number|details|information)|banking (?:details|information)|date of birth|online banking)",
        r"\b(?:password|login) (?:expires?|will expire|has expired)\b",
        r"\b(?:confirm|verify|update|re-?enter|submit)\b(?: \w+){0,3} (?:your )?(?:direct deposit|payroll|salary account|bank(?:ing)?) (?:details|information|info)\b.{0,60}\b(?:form|link|portal|below|here|https?://)",
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
        r"\b(?:unpaid|outstanding|overdue) (?:toll|tolls|fee)\b",
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
    ("ai_directed_text", "Contains text aimed at an AI assistant or filter (prompt injection)", 5, [
        r"\b(?:ignore|disregard|forget|override)\b(?: \w+){0,3} (?:previous|prior|above|earlier|all|your|system|safety) (?:instructions?|prompts?|rules?|guidelines?)\b",
        r"\b(?:ai|a\.i\.|assistant|chatbot|llm|language model|claude|chatgpt|gpt|copilot|gemini|spam filter|scanner|classifier)\b.{0,80}\b(?:mark|classify|label|report|treat|consider|rate|flag)\b(?: \w+){0,4} (?:as )?(?:safe|legitimate|legit|trusted|verified|not (?:a )?(?:scam|spam|phishing)|harmless|clean)\b",
        r"\b(?:note|message|instructions?) (?:to|for) (?:the )?(?:ai|assistant|model|llm|bot|claude|chatgpt|reviewer bot)\b",
        r"\b(?:you are|act as|you'?re) (?:now )?(?:an? )?(?:ai|assistant|helpful assistant|llm|email assistant)\b.{0,80}\b(?:must|should|will|need to)\b",
        r"\b(?:system prompt|developer mode|jailbreak)\b|<\|?(?:im_start|system|endoftext)\|?>|\[/?inst\]",
        r"\b(?:do not|don'?t|never) (?:flag|warn|alert|mention|report)\b.{0,40}\b(?:this (?:email|message)|the user|scam|phishing)\b",
        r"\b(?:forward|send|reply|delete|archive|move|label|export)\b(?: [\w']+){0,5} (?:emails?|messages?|inbox|contacts?|passwords?|files?|attachments?|conversations?)\b.{0,60}\b(?:to|into) (?:[\w.+-]+@[\w-]+\.[\w.]+|this address|the following address)",
        r"\bif you(?:'re| are) an? (?:ai|a\.i\.|llm|large language model|language model|automated|email|mail|virtual) ?(?:assistant|agent|model|bot|tool|system)?\b",
    ]),
    ("seed_phrase", "Asks for a wallet seed / recovery phrase or private key", 6, [
        r"\b(?:seed|recovery|secret recovery|backup|mnemonic|passphrase|wallet) (?:phrase|words|key)s?\b",
        r"\b(?:12|twelve|24|twenty[- ]four|18)[- ]word(?:s)? (?:phrase|seed|key|backup)?\b",
        r"\bprivate key\b",
    ]),
    ("wallet_drainer", "Asks you to connect your crypto wallet and sign/approve (wallet drainer)", 5, [
        r"\bconnect (?:your |the )?(?:crypto |web3 )?wallet\b",
        r"\b(?:sign|approve|confirm)\b(?: \w+){0,2} (?:the |a |this )?(?:transaction|message|permit|approval|contract|signature request)\b.{0,60}\b(?:claim|receive|airdrop|tokens?|nft|reward|unlock|validate|sync)\b",
        r"\b(?:claim|receive|get)\b(?: \w+){0,3} (?:\$?[a-z]{2,6} )?(?:airdrop|free (?:tokens?|nfts?|mint))\b",
        r"\bairdrop\b.{0,80}\b(?:wallet|claim|connect|sign)\b",
        r"\bwallet (?:is )?(?:out of sync|not synced|desynchroni[sz]ed|compromised|needs? (?:validation|verification|rectification|synchroni[sz]ation))\b",
    ]),
    ("recovery_offer", "Offers to recover lost/scammed money, usually for a fee", 5, [
        r"\b(?:recover|retrieve|get back|reclaim|trace)\b(?: \w+){0,3} (?:your )?(?:lost|stolen|scammed|missing)? ?(?:funds|money|crypto|bitcoin|assets|investment|savings)\b",
        r"\b(?:fund|funds|asset|crypto|money|scam) recovery\b",
        r"\b(?:lost|scammed|stolen)\b.{0,40}\b(?:we|our (?:team|agents|experts|hackers|lawyers))\b.{0,40}\b(?:recover|get (?:it|your money|your funds) back|retrieve)\b",
        r"\b(?:ethical |certified |licensed )?hackers?\b.{0,40}\b(?:recover|retrieve|get back)\b",
        r"\b(?:get|bring|win)\b (?:your |the |all your )?(?:lost )?(?:money|funds|crypto|bitcoin|investment|savings|deposit) back\b",
        r"\brecovery (?:agents?|experts?|specialists?|services?|team|company|firm|attorneys?|lawyers?)\b",
    ]),
    ("changed_bank_details", "Says bank/payment details changed and asks you to pay a new account", 5, [
        r"\b(?:new|updated|changed|different|alternative|alternate)\b(?: \w+){0,2} (?:bank(?:ing)?|account|remittance|payment|wire|wiring|ach|direct deposit) (?:details|information|info|instructions|account|number)s?\b",
        r"\b(?:our|the|my) (?:bank(?:ing)?|account|payment|remittance|wire) (?:details|information|instructions|account)s? (?:have|has) (?:been )?(?:changed|updated)\b",
        r"\b(?:do not|don'?t|stop) (?:use|pay|send)\b(?: \w+){0,3} (?:the |our )?(?:old|previous|former|usual) (?:account|bank|details)\b",
        r"\b(?:update|change)\b(?: \w+){0,3} (?:my|the) (?:direct deposit|payroll|bank) (?:details|information|account)\b.{0,40}\b(?:before|for) (?:the )?(?:next )?(?:payroll|pay ?day|payment)\b",
        r"\b(?:closing|settlement|escrow) (?:funds|costs|payment)\b.{0,80}\b(?:wire|new (?:instructions|account))\b",
        r"\b(?:new|switching to a new|moving to a new|changing) (?:payroll|hr|benefits) (?:provider|system|platform|portal)\b.{0,160}\b(?:confirm|update|re-?enter|verify|submit)\b.{0,40}\b(?:direct deposit|bank(?:ing)?|account|salary) (?:details|information|info)\b",
    ]),
    ("fake_invoice", "Invoice/renewal/receipt for something you may not have ordered, with a number to call", 3, [
        r"\b(?:invoice|receipt|order|subscription|renewal|purchase|charge)\b.{0,120}\b(?:if you did not|if you didn'?t|not you\??|to cancel|dispute|for a refund|did not authori[sz]e)\b.{0,60}\b(?:call|contact|dial|reach)\b",
        r"\b(?:auto-?renew(?:ed|al)?|renewed (?:for|automatically)|annual (?:plan|subscription))\b.{0,80}\$\s?\d{2,}",
        r"\b(?:geek squad|norton|mcafee|best buy|paypal|coinbase)\b.{0,60}\b(?:invoice|order (?:id|no|number|#)|renewal|subscription)\b",
    ]),
    ("qr_code_lure", "Pushes you to scan a QR code to pay, log in or verify", 3, [
        r"\bscan (?:the |this |our )?(?:qr|code|qr code)\b.{0,80}\b(?:pay|payment|verify|login|log in|sign in|authenticate|reactivate|confirm|update|unlock|parking)\b",
        r"\b(?:pay|payment|verify|login|log in|sign in|authenticate|reactivate|confirm|update|unlock|parking)\b.{0,80}\bscan (?:the |this |our )?(?:qr|code|qr code)\b",
        r"\[(?:qr ?code|qr)[^\]]{0,40}\]",
        r"\bqr code\b.{0,60}\b(?:multi-?factor|mfa|2fa|authenticat|security update|pay (?:here|now))\b",
    ]),
    ("unauthorized_activity", "Describes transactions or account access you didn't make or approve", 3, [
        r"\b(?:i|we) (?:did not|didn'?t|never) (?:make|authorize|send|approve|initiate|recogni[sz]e)\b",
        r"\b(?:i|we)\b[^.]{0,60}\b(?:did not|didn'?t|never) (?:make|authorize|send|approve|initiate)\b",
        r"\b(?:unauthori[sz]ed|fraudulent) (?:transactions?|transfers?|charges?|withdrawals?|payments?|access|login)\b",
        r"\bsomeone (?:else )?(?:hacked|accessed|logged into|got into|broke into|took over) (?:my|our) (?:account|email|phone|app)\b",
        r"\bsomeone (?:else )?(?:logged in|signed in|got in)\b.{0,60}\b(?:new device|another (?:state|country|city)|my (?:account|app|bank))\b",
        r"\b(?:i|we) (?:did not|didn'?t|never) (?:change|reset) (?:it|my password|the password)\b",
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
        rf"\b(?:{_NEG}) (?:share|give|enter|type)\b.{{0,30}}\b(?:recovery|seed|secret) phrase\b",
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
    "bec_payment_redirect": (["changed_bank_details"], [
        r"\b(?:invoice|remittance|vendor|supplier|wire|ach|escrow|closing|title company|settlement|payroll|direct deposit|accounts payable|outstanding balance)\b",
    ]),
    "fake_invoice": (["fake_invoice"], [
        r"\b(?:invoice|receipt|renewal|subscription|order (?:id|no|number|#)|billing|auto-?renew\w*)\b",
    ]),
    "qr_phishing": (["qr_code_lure"], [
        r"\b(?:qr|scan|parking (?:meter|ticket|fine|app))\b",
    ]),
    "wallet_drainer": (["wallet_drainer", "seed_phrase"], [
        r"\b(?:airdrop|nft|mint|metamask|phantom|trust wallet|ledger|trezor|seed phrase|recovery phrase|connect (?:your )?wallet|dapp|web3)\b",
    ]),
    "recovery_scam": (["recovery_offer"], [
        r"\b(?:recover\w*|lost funds|stolen funds|retrieve|trace(?:d)?|reclaim|refund of your (?:loss|investment))\b",
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


def _negated(text: str, m: re.Match) -> bool:
    """True if the match sits inside a negated clause ("we will never ask you to share the code").

    Only the same clause (back to the previous sentence break, semicolon or dash) counts, so
    boilerplate like "We never ask for codes. Read me the code." is NOT treated as negated.
    """
    head = text[:m.start()]
    cut = max(head.rfind(c) for c in (".", "!", "?", ";", "\n", " - ", "—"))
    clause = head[cut + 1:] if cut >= 0 else head
    return bool(re.search(rf"\b{_NEG}\b", clause[-60:], re.I)) or bool(
        re.match(rf"[^.;\n]{{0,6}}\b{_NEG}\b", text[m.start():m.end()], re.I))


_QUOTES = "\"'\u201c\u201d\u2018\u2019\u00ab\u00bb"


def _quoted(text: str, m: re.Match) -> bool:
    before, after = text[max(0, m.start() - 3):m.start()], text[m.end():m.end() + 3]
    return any(q in before for q in _QUOTES) and any(q in after for q in _QUOTES)


def find_flags(text: str, table=FLAGS) -> list[Hit]:
    hits: list[Hit] = []
    low = text
    for fid, label, weight, pats in table:
        ev: list[str] = []
        for p in pats:
            for m in re.finditer(p, low, re.I | re.M | re.S):
                q = _quote(text, m)
                if fid in ("otp_request", "seed_phrase", "gift_card_payment", "crypto_payment", "credential_request") and _negated(low, m):
                    continue  # "never share this code/phrase" is a reassuring cue, not a request
                if fid == "ai_directed_text" and _quoted(low, m):
                    continue  # quoting an injection phrase (e.g. in a security newsletter) is not an injection
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
    # Fake renewal + "call to cancel" + device scare is the classic tech-support/refund funnel (FTC files it there);
    # fake_invoice is for invoices/bills without the device-scare/remote-access part.
    techy = bool({"remote_access"} & flag_ids) or bool(re.search(
        r"\b(?:geek squad|norton|mcafee|antivirus|anti-virus|computer|device|pc|laptop|windows|microsoft|virus|malware|tech(?:nical)? support)\b",
        text, re.I))
    if "fake_invoice" in flag_ids and not techy:
        scores["fake_invoice"] = scores.get("fake_invoice", 0) + 3
    elif "fake_invoice" in flag_ids:
        scores["fake_invoice"] = max(0, scores.get("fake_invoice", 0) - 4)
    # "move your money to a new/safe account" is bank impersonation, not a vendor changing its details.
    if "changed_bank_details" in flag_ids and "safe_account" not in flag_ids:
        scores["bec_payment_redirect"] = scores.get("bec_payment_redirect", 0) + 3
    elif "safe_account" in flag_ids and "bec_payment_redirect" in scores:
        scores["bec_payment_redirect"] = max(0, scores["bec_payment_redirect"] - 6)
    return sorted(scores.items(), key=lambda kv: -kv[1])


# --------------------------------------------------------------------------
# Normalization / de-obfuscation (run BEFORE matching)
# --------------------------------------------------------------------------

ZERO_WIDTH = re.compile("[­͏؜ᅟᅠ឴឵᠎​-‏‪-‮⁠-⁤⁦-⁯ㅤ﻿ﾠ]")
_LEET = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s", "!": "i", "|": "l"})
# Words scammers obfuscate to slip past filters. A leet token only counts as
# evidence of obfuscation when it decodes to one of these.
SENSITIVE_WORDS = {
    "irs", "bitcoin", "btc", "crypto", "account", "verify", "verification", "password", "gift", "card", "cards", "paypal",
    "bank", "warrant", "arrest", "payment", "pay", "code", "wallet", "police", "refund", "suspended", "social", "security",
    "apple", "amazon", "usps", "login", "urgent", "tax", "taxes", "fbi", "zelle", "venmo", "cashapp", "seed", "phrase",
    "invest", "profit", "deposit", "otp", "pin", "locked", "blocked", "fine", "penalty", "legal", "court", "jail", "free",
    "winner", "prize", "claim", "click", "link", "chase", "wells", "fargo", "netflix", "microsoft",
}
_SPACED = re.compile(r"(?<![\w])(?:[A-Za-z][ .\-_*·]){2,}[A-Za-z](?![\w])")
_LEET_TOKEN = re.compile(r"(?<![\w@$])[A-Za-z0-9@$!|]*[A-Za-z][A-Za-z0-9@$!|]*(?![\w@$])")


@dataclass
class Normalized:
    text: str
    zero_width: int = 0
    spaced: list[str] = field(default_factory=list)
    leet: list[str] = field(default_factory=list)
    confusables: int = 0

    @property
    def obfuscated(self) -> bool:
        return bool(self.zero_width or self.leet or len(self.spaced) >= 1 or self.confusables >= 2)


def normalize_text(text: str) -> Normalized:
    """NFKC, strip zero-width/bidi characters, re-join s p a c e d letters, decode l33t in sensitive words."""
    zw = len(ZERO_WIDTH.findall(text))
    t = ZERO_WIDTH.sub("", text)
    nf = unicodedata.normalize("NFKC", t)
    # Cyrillic/Greek look-alikes inside otherwise Latin words (е, о, а, р, с, х, і)
    conf_map = str.maketrans("аеорсхуіјѕԁԛԝАВЕКМНОРСТХІЈЅοαρτνκιΑΒΕΗΙΚΜΝΟΡΤΧΥΖ",
                             "aeopcxyijsdqwABEKMHOPCTXIJSoaptvkiABEHIKMNOPTXYZ")
    conf = 0

    def _fix_conf(m: re.Match) -> str:
        nonlocal conf
        w = m.group(0)
        if re.search(r"[A-Za-z]", w) and re.search(r"[Ͱ-ϿЀ-ӿ]", w):
            conf += 1
            return w.translate(conf_map)
        return w
    nf = re.sub(r"[\w]+", _fix_conf, nf)
    # symbols/emoji wedged between letters ("B💎o💎t", "g🔹i🔹f🔹t")
    sym_sep = re.compile("(?<=[A-Za-z])(?:[\u2190-\u2bff\u25a0-\u27bf\ufe0f\u200d]|[\U0001F000-\U0001FAFF])+(?=[A-Za-z])")
    n_sym = len(sym_sep.findall(nf))
    nf = sym_sep.sub("", nf)
    spaced: list[str] = []
    if n_sym >= 2:
        spaced.append(f"{n_sym} emoji/symbols inside words")

    def _join(m: re.Match) -> str:
        joined = re.sub(r"[ .\-_*·]", "", m.group(0))
        # leave real abbreviations like "U.S." / "a.m." alone unless they spell a sensitive word or are long
        if joined.lower() in SENSITIVE_WORDS or len(joined) >= 4:
            spaced.append(m.group(0))
            return joined
        return m.group(0)
    nf = _SPACED.sub(_join, nf)
    if spaced:
        nf = re.sub(r"[ \t]{2,}", " ", nf)
    leet: list[str] = []

    def _deleet(m: re.Match) -> str:
        w = m.group(0)
        letters = sum(c.isalpha() for c in w)
        others = len(w) - letters
        if not others or letters < 2 or others > letters or len(w) > 20:
            return w
        d = w.translate(_LEET)
        cands = {d.lower(), d.lower().replace("i", "l"), d.lower().rstrip("s")}
        if cands & SENSITIVE_WORDS or any(c.startswith(("arrest", "warrant", "account", "verif", "gift", "bitcoin", "passw", "paypal", "suspend", "refund")) for c in cands):
            leet.append(w)
            return d
        return w
    nf = _LEET_TOKEN.sub(_deleet, nf)
    return Normalized(nf, zw, spaced, leet, conf)


# --------------------------------------------------------------------------
# Language coverage: the rules are English-only. Say so instead of "legit".
# --------------------------------------------------------------------------

_EN_STOP = set("the an and or to of in on for your you is are be this that it we our with at by from please not have has will can if".split())
# Frequent function words in languages scam texts commonly arrive in (es, pt, fr, de, it, romanized Hindi/Urdu, Tagalog).
_OTHER_STOP = set((
    "el la los las de del que y en su sus para por con una un es usted tu se al lo le ha sido este esta "
    "o os da do das dos em uma não você seu sua com "
    "le les des du et est vous votre pour avec une sur pas "
    "der die das und ist sie ihr ihre mit für nicht ein eine zu von "
    "il di che per non sono "
    "aap aapka aapki aapke hai hain ho ka ki ke ko se mein nahi kya abhi karo kare jayega jaega warna bhejo "
    "ang ng sa mga po ninyo"
).split())
_LATIN = re.compile(r"[A-Za-zÀ-ɏ]")


def language_coverage(text: str) -> dict:
    """Return {'covered': bool, 'reason': str}. Heuristic, stdlib-only, no language model."""
    letters = [c for c in text if c.isalpha()]
    if not letters:
        return {"covered": True, "reason": ""}
    non_latin = sum(1 for c in letters if not _LATIN.match(c))
    if non_latin / len(letters) > 0.3:
        return {"covered": False, "reason": "non-Latin script"}
    words = re.findall(r"[A-Za-zÀ-ɏ']+", text.lower())
    if len(words) < 6:
        return {"covered": True, "reason": ""}
    en = sum(1 for w in words if w in _EN_STOP)
    other = sum(1 for w in words if w in _OTHER_STOP and w not in _EN_STOP)
    accented = sum(1 for c in letters if "\u00c0" <= c <= "\u024f")
    if en / len(words) < 0.06 or (accented >= 3 and en / len(words) < 0.12) or (other >= 3 and other > 1.5 * en):
        return {"covered": False, "reason": "text does not look like English"}
    return {"covered": True, "reason": ""}
