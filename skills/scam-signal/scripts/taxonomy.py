"""Scam typology, official-category mappings, advice and reporting links.

The human-readable version (with sources and rationale) lives in
references/typology.md and references/reporting.md. Keep the two in sync.
"""
from __future__ import annotations

# Stage-1 label in the underlying research rubric:
#   scam                 = victim was deceived into authorizing the action
#   non_consensual_fraud = money moved / account used WITHOUT the victim's authorization
TYPOLOGY: dict[str, dict] = {
    "bank_impersonation": {
        "name": "Bank / fraud-department impersonation",
        "stage1": "scam",
        "ftc": "Imposter scams: business imposter (bank)",
        "ic3": "Government/Business Impersonation; Phishing/Spoofing",
        "cfpb": "Fraud or scam (Money transfer, virtual currency, or money service / Checking or savings account)",
        "summary": "Someone posing as your bank's fraud team gets you to move money to a 'safe account', read back a one-time code, or 'reverse' a fake charge, often via Zelle.",
    },
    "government_impersonation": {
        "name": "Government / law-enforcement impersonation",
        "stage1": "scam",
        "ftc": "Imposter scams: government imposter",
        "ic3": "Government Impersonation",
        "cfpb": "Fraud or scam",
        "summary": "Claims to be the IRS, Social Security, police, a court or immigration and threatens arrest, fines or a suspended benefit unless you pay now.",
    },
    "tech_support_refund": {
        "name": "Tech-support / fake refund or renewal",
        "stage1": "scam",
        "ftc": "Imposter scams: tech support",
        "ic3": "Tech Support",
        "cfpb": "Fraud or scam",
        "summary": "A pop-up, call or fake invoice says your device is infected or you were overcharged. They want remote access and then 'refund' you and ask you to send back the 'extra'.",
    },
    "delivery_toll_smishing": {
        "name": "Package delivery / unpaid toll text (smishing)",
        "stage1": "scam",
        "ftc": "Imposter scams: business imposter; Online shopping (delivery)",
        "ic3": "Phishing/Spoofing",
        "cfpb": "Fraud or scam (card data theft)",
        "summary": "A text about a missed delivery or unpaid toll links to a fake payment page that steals card details.",
    },
    "credential_phishing": {
        "name": "Account credential phishing",
        "stage1": "scam",
        "ftc": "Imposter scams: business imposter",
        "ic3": "Phishing/Spoofing",
        "cfpb": "Fraud or scam",
        "summary": "A 'verify your account / unusual sign-in / mailbox full / shared document' message that leads to a fake login page.",
    },
    "marketplace": {
        "name": "Online marketplace / purchase / rental scam",
        "stage1": "scam",
        "ftc": "Online shopping and negative reviews",
        "ic3": "Non-Payment/Non-Delivery; Overpayment; Real Estate (rental)",
        "cfpb": "Fraud or scam (P2P payment for goods)",
        "summary": "A fake seller, buyer or landlord. Often asks for a deposit by Zelle, Cash App or gift card, overpays and wants the difference back, or asks for a verification code.",
    },
    "romance": {
        "name": "Romance / confidence scam",
        "stage1": "scam",
        "ftc": "Imposter scams: romance scams",
        "ic3": "Romance / Confidence Fraud",
        "cfpb": "Fraud or scam",
        "summary": "An online-only relationship that turns into requests for money (emergency, travel, customs, medical) or into an 'investment' pitch.",
    },
    "investment_crypto": {
        "name": "Investment / crypto scam (incl. 'pig butchering')",
        "stage1": "scam",
        "ftc": "Investment related",
        "ic3": "Investment (incl. cryptocurrency investment fraud)",
        "cfpb": "Fraud or scam (Virtual currency)",
        "summary": "Promises of guaranteed or outsized returns on a trading platform you were steered to. The 'profits' are fake and withdrawals need ever-larger 'fees'.",
    },
    "employment_task": {
        "name": "Job / task / fake-check scam",
        "stage1": "scam",
        "ftc": "Business and job opportunities",
        "ic3": "Employment",
        "cfpb": "Fraud or scam (check / overpayment)",
        "summary": "A too-easy remote job (rate products, 'optimize orders', mystery shopper). You either pay in to 'unlock' tasks, or you deposit a check and send money out before it bounces.",
    },
    "family_emergency": {
        "name": "Family / friend emergency (grandparent, voice-clone)",
        "stage1": "scam",
        "ftc": "Imposter scams: family & friend imposter",
        "ic3": "Confidence Fraud",
        "cfpb": "Fraud or scam",
        "summary": "Someone claiming to be a relative (or their lawyer or police officer) in urgent trouble needs money now and asks you to keep it secret.",
    },
    "prize_advance_fee": {
        "name": "Prize / lottery / grant / advance-fee",
        "stage1": "scam",
        "ftc": "Prizes, sweepstakes and lotteries",
        "ic3": "Lottery/Sweepstakes/Inheritance; Advanced Fee",
        "cfpb": "Fraud or scam",
        "summary": "You 'won' something or are owed money, but must first pay a fee, tax or shipping charge to collect it.",
    },
    "extortion": {
        "name": "Sextortion / extortion",
        "stage1": "scam",
        "ftc": "Imposter scams / Other",
        "ic3": "Extortion",
        "cfpb": "Fraud or scam",
        "summary": "Threatens to release intimate images or 'recordings' unless you pay, usually in crypto. Mass-mailed versions often contain no real material.",
    },
    "bec_payment_redirect": {
        "name": "Changed bank details / payment redirection (business email compromise)",
        "stage1": "scam",
        "ftc": "Imposter scams: business imposter",
        "ic3": "Business Email Compromise (BEC)",
        "cfpb": "Fraud or scam (Money transfer / wire)",
        "summary": "An email that looks like it's from a vendor, landlord, title company, lawyer, employer or colleague says the bank details have changed and asks you to pay an invoice, deposit, closing funds or payroll to a new account. The mailbox is often hacked or a lookalike.",
    },
    "fake_invoice": {
        "name": "Fake invoice / renewal / bill",
        "stage1": "scam",
        "ftc": "Imposter scams: business imposter (fake renewal or invoice)",
        "ic3": "Phishing/Spoofing; Tech Support (callback phishing)",
        "cfpb": "Fraud or scam",
        "summary": "An invoice, receipt or PDF bill for something you didn't order (an antivirus renewal, a PayPal purchase, a domain or listing fee) pushes you to call a 'support' number or pay. The call then turns into a refund or remote-access scam.",
    },
    "qr_phishing": {
        "name": "QR-code phishing (quishing)",
        "stage1": "scam",
        "ftc": "Imposter scams: business imposter",
        "ic3": "Phishing/Spoofing",
        "cfpb": "Fraud or scam",
        "summary": "A QR code on a parking meter sticker, flyer, letter, email or PDF leads to a fake payment or login page. QR codes hide the destination and slip past email link scanners.",
    },
    "wallet_drainer": {
        "name": "Crypto wallet drainer (connect / sign to claim)",
        "stage1": "scam",
        "ftc": "Imposter scams; cryptocurrency",
        "ic3": "Phishing/Spoofing (cryptocurrency)",
        "cfpb": "Fraud or scam (virtual currency)",
        "summary": "An airdrop, free mint, 'wallet sync' or support message gets you to connect your wallet and sign an approval, or to type your recovery phrase. That hands over control and the wallet is emptied.",
    },
    "recovery_scam": {
        "name": "Fund-recovery scam (targets past victims)",
        "stage1": "scam",
        "ftc": "Imposter scams (often posing as a law firm, agency or 'ethical hackers')",
        "ic3": "Government Impersonation; Advanced Fee (fund recovery)",
        "cfpb": "Fraud or scam",
        "summary": "Someone promises to recover money you lost to an earlier scam, for an upfront fee, tax or 'release' payment. Real agencies and police don't charge to recover funds.",
    },
    "account_takeover": {
        "name": "Unauthorized transaction / account takeover (not a scam)",
        "stage1": "non_consensual_fraud",
        "ftc": "Identity theft",
        "ic3": "Identity Theft; SIM Swap; Personal Data Breach",
        "cfpb": "Fraud or scam: unauthorized transaction (Reg E error resolution)",
        "summary": "Money moved or your account was used without your knowledge or approval. Legally this is different from a scam you were tricked into authorizing.",
    },
    "unclear": {
        "name": "Suspicious, type unclear",
        "stage1": "ambiguous",
        "ftc": "Other",
        "ic3": "Other",
        "cfpb": "Fraud or scam",
        "summary": "Has red flags but doesn't clearly match one known pattern.",
    },
}

LINKS = {
    "ftc": ("FTC (all U.S. scams)", "https://reportfraud.ftc.gov"),
    "ic3": ("FBI IC3 (internet, crypto, investment, extortion, large losses)", "https://www.ic3.gov"),
    "cfpb": ("CFPB (if your bank/app won't help after a fraud or scam)", "https://www.consumerfinance.gov/complaint/"),
    "idtheft": ("IdentityTheft.gov (personal info exposed or misused)", "https://www.identitytheft.gov"),
    "sms7726": ("Forward the text to 7726 (SPAM) to report it to your carrier; then use 'Report Junk' and delete", None),
    "apwg": ("Forward phishing email to reportphishing@apwg.org and use your mail app's 'Report phishing' button", None),
    "irs": ("IRS impersonation: forward email to phishing@irs.gov; report calls to TIGTA", "https://www.tigta.gov"),
    "ssa": ("Social Security impersonation: SSA Office of the Inspector General", "https://oig.ssa.gov"),
    "uspis": ("USPS-themed texts/email: U.S. Postal Inspection Service", "https://www.uspis.gov/report"),
    "fcc": ("Robocalls/spoofed caller ID: FCC", "https://consumercomplaints.fcc.gov"),
    "elder": ("Victim is 60+: National Elder Fraud Hotline 1-833-FRAUD-11 (1-833-372-8311)", None),
    "ncmec": ("If a minor is involved: NCMEC CyberTipline / Take It Down", "https://report.cybertip.org"),
    "bank": ("Your bank or card issuer: use the number on the back of your card or in the official app, never one from the message", None),
    "platform": ("Report the profile/listing/account inside the app or site where it happened", None),
    "freeze": ("Free credit freeze at Equifax, Experian and TransUnion", "https://www.usa.gov/credit-freeze"),
}

REPORT_BY_TYPE = {
    "bank_impersonation": ["bank", "ftc", "cfpb", "fcc"],
    "government_impersonation": ["ftc", "irs", "ssa", "ic3"],
    "tech_support_refund": ["bank", "ftc", "ic3"],
    "delivery_toll_smishing": ["sms7726", "ftc", "uspis", "ic3"],
    "credential_phishing": ["apwg", "ftc", "ic3"],
    "marketplace": ["platform", "bank", "ftc", "ic3"],
    "romance": ["platform", "ftc", "ic3"],
    "investment_crypto": ["ic3", "ftc", "platform"],
    "employment_task": ["ftc", "ic3", "bank"],
    "family_emergency": ["ftc", "ic3", "elder"],
    "prize_advance_fee": ["ftc", "ic3"],
    "extortion": ["ic3", "ncmec", "platform"],
    "bec_payment_redirect": ["bank", "ic3", "ftc"],
    "fake_invoice": ["bank", "ftc", "ic3"],
    "qr_phishing": ["bank", "ftc", "ic3"],
    "wallet_drainer": ["ic3", "ftc", "platform"],
    "recovery_scam": ["ic3", "ftc"],
    "account_takeover": ["bank", "idtheft", "cfpb", "ftc"],
    "unclear": ["ftc"],
}

DO_NOW_GENERAL = [
    "Don't reply, click links, scan QR codes, or call numbers in the message.",
    "Verify independently: open the official app, or call the number on the back of your card / on the official website you type in yourself.",
    "Don't send money, gift cards or crypto, and never share one-time codes, passwords or your SSN with anyone who contacted you.",
    "Keep the evidence (screenshot it), then block the sender and report it (see below).",
]

DO_NOW_BY_TYPE = {
    "bank_impersonation": [
        "Your real bank will never ask you to move money to a 'safe account', read back a code, or send a Zelle payment to yourself or to 'reverse' a charge.",
        "Hang up and call the number on the back of your card.",
    ],
    "government_impersonation": [
        "Government agencies don't demand payment by gift card, crypto, wire or Zelle, and don't threaten immediate arrest by phone or text.",
        "If unsure, look up the agency's number yourself (e.g. irs.gov, ssa.gov) and call it.",
    ],
    "tech_support_refund": [
        "Don't install remote-access apps (AnyDesk, TeamViewer, etc.) for anyone who contacted you.",
        "If you already gave access: disconnect from the internet, remove the app, run a security scan, change passwords from another device, and call your bank.",
    ],
    "delivery_toll_smishing": [
        "Check deliveries only in the carrier's official app/site, and tolls only on your toll agency's official site, by typing the address yourself.",
        "If you entered card details, call your card issuer to cancel the card.",
    ],
    "credential_phishing": [
        "Go to the service directly (not via the link) to check for alerts.",
        "If you entered a password: change it everywhere you reused it, turn on two-factor authentication, and sign out other sessions.",
    ],
    "marketplace": [
        "Pay only through the platform's protected checkout; P2P apps like Zelle and Cash App are meant for people you know and have little purchase protection.",
        "Never share a verification code (e.g. Google Voice) to 'prove you're real'. Don't accept overpayments, and don't refund 'the difference'.",
        "For rentals, see the property in person and verify the owner before paying any deposit.",
    ],
    "bec_payment_redirect": [
        "Before paying to new or changed bank details, call the person or company on a number you already have (old invoice, contract, website typed by hand), not one in the email.",
        "If you already sent the payment: call your bank's fraud line now and ask for a wire recall. Hours matter.",
    ],
    "fake_invoice": [
        "Don't call the phone number on the invoice. Check your account directly in the official app or website.",
        "Never let a 'refund' agent connect to your computer, and never send back an 'over-refund'.",
    ],
    "qr_phishing": [
        "Don't scan QR codes on stickers, flyers or unexpected letters or emails to pay or log in. Use the official app or type the address yourself.",
        "To check a code safely, preview it: the iPhone camera and Google Lens show the link before opening it. Read the domain, but don't tap it.",
    ],
    "wallet_drainer": [
        "Never type your recovery phrase anywhere except your own wallet on your own device. No support team or airdrop needs it.",
        "Don't connect your wallet to sites from DMs, replies or ads. If you signed something, revoke approvals with your wallet's official tools and move funds to a new wallet.",
    ],
    "recovery_scam": [
        "Real police and agencies never charge a fee to recover your money. Anyone asking for one is running a second scam.",
        "Report the original loss yourself (IC3/FTC, or your country's equivalent) and work with your bank.",
    ],
    "romance": [
        "Don't send money, gift cards or crypto to someone you've only met online, whatever the emergency.",
        "Talk to a friend or family member you trust. Scammers ask for secrecy for a reason.",
    ],
    "investment_crypto": [
        "Don't deposit more to 'unlock' a withdrawal; the balance shown is fake.",
        "Check the platform and adviser at investor.gov and FINRA BrokerCheck before investing anything.",
    ],
    "employment_task": [
        "Real jobs don't make you pay to work, buy equipment with their check, or 'recharge' an account to unlock tasks.",
        "Never deposit a check and send part of it back: it will bounce after the money is gone.",
    ],
    "family_emergency": [
        "Hang up and call the family member directly on the number you already have, or agree on a family code word.",
        "Voices can be AI-cloned from short clips; a familiar voice isn't proof.",
    ],
    "prize_advance_fee": [
        "Real prizes never require you to pay a fee, tax or shipping charge up front.",
    ],
    "extortion": [
        "Don't pay or engage. Mass-mailed 'I recorded you' emails usually have no real material, and paying invites more demands.",
        "If a password is quoted, change it. If a minor is involved, contact NCMEC.",
    ],
    "account_takeover": [
        "Call your bank or app now (official number) and report the transactions as UNAUTHORIZED. Prompt reporting matters for your liability under Reg E.",
        "Change your passwords, turn on 2FA, ask your carrier about a SIM/port-out lock, and consider a credit freeze.",
    ],
}

IF_ALREADY_ACTED = [
    "Sent money by bank/Zelle/wire: call your bank's fraud line immediately and ask them to stop or recall it. Speed matters.",
    "Paid with gift cards: contact the card brand right away with the card numbers and receipt.",
    "Sent crypto: report to the exchange you used and to IC3 with wallet addresses and transaction IDs.",
    "Shared a password or code: change it, enable 2FA, and sign out other devices.",
    "Shared your SSN or ID: go to IdentityTheft.gov and freeze your credit.",
    "Beware 'recovery' services that contact you promising to get the money back. That is a second scam.",
]


# --------------------------------------------------------------------------
# Reporting outside the U.S.  Keep in sync with references/reporting.md.
# Only contacts confirmed on official or reputable sources (Nov 2026) are listed.
# --------------------------------------------------------------------------

COUNTRY_REPORTING: dict[str, dict] = {
    "us": {"name": "United States"},  # uses LINKS / REPORT_BY_TYPE above
    "uk": {"name": "United Kingdom", "report": [
        ("Report Fraud (formerly Action Fraud), England, Wales & Northern Ireland: reportfraud.police.uk or 0300 123 2040", "https://www.reportfraud.police.uk"),
        ("Scotland: Police Scotland on 101", None),
        ("Call 159 to reach your bank's fraud team safely (most UK banks)", None),
        ("Scam texts: forward to 7726 (free)", None),
        ("Scam emails: forward to report@phishing.gov.uk (NCSC)", None),
    ], "note": "If you were tricked into sending a bank payment, tell your bank right away: UK payment-scam reimbursement rules may apply."},
    "in": {"name": "India", "report": [
        ("Money lost? Call 1930 (National Cyber Crime Helpline) immediately", None),
        ("File a complaint at cybercrime.gov.in", "https://cybercrime.gov.in"),
        ("Suspicious call/SMS/WhatsApp (no money lost): report on Chakshu, Sanchar Saathi", "https://sancharsaathi.gov.in/sfc/"),
        ("Your bank: report unauthorized electronic transactions at once (RBI rules limit your liability if you report quickly)", None),
    ], "note": "Never share an OTP, UPI PIN, or screen-share with anyone who calls you."},
    "au": {"name": "Australia", "report": [
        ("Scamwatch (National Anti-Scam Centre)", "https://www.scamwatch.gov.au/report-a-scam"),
        ("ReportCyber, if you lost money or data to cybercrime", "https://www.cyber.gov.au/report-and-recover"),
        ("IDCARE, identity and cyber support", "https://www.idcare.org"),
        ("Your bank, using the number on your card or in its app", None),
    ]},
    "ca": {"name": "Canada", "report": [
        ("Canadian Anti-Fraud Centre: 1-888-495-8501", "https://reportcyberandfraud.canada.ca"),
        ("Scam texts: forward to 7726 (SPAM)", None),
        ("Your bank, and local police if you lost money", None),
    ]},
    "ie": {"name": "Ireland", "report": [
        ("Your bank first, then your local Garda station", "https://www.garda.ie"),
        ("FraudSMART (Banking & Payments Federation Ireland) guidance", "https://www.fraudsmart.ie"),
    ], "note": "EU countries: report to your national police and your bank. Each country runs its own fraud-reporting service."},
    "eu": {"name": "EU (other)", "report": [
        ("Your bank or payment provider, immediately", None),
        ("Your national police (most have an online fraud/cybercrime report form)", None),
    ], "note": "I'm less certain of local specifics outside the countries listed. Check your national police site."},
    "nz": {"name": "New Zealand", "report": [
        ("Scam texts: forward to 7726 (free, Department of Internal Affairs)", None),
        ("Netsafe takes reports of all scams", "https://netsafe.org.nz"),
        ("NCSC (formerly CERT NZ) for cyber incidents", "https://www.ncsc.govt.nz"),
        ("Your bank, and Police on 105 if you lost money", None),
    ]},
}

_COUNTRY_CUES = [
    ("in", r"\b(?:upi|aadhaar|aadhar|pan card|paytm|phonepe|bhim|\+91[\s-]?\d|rs\.? ?\d|inr|lakh|crore|kyc (?:update|pending|expired)|rbi|sbi|hdfc|icici|trai|dot|cyber cell|\bmumbai|\bdelhi)\b|₹"),
    ("uk", r"\b(?:hmrc|dvla|royal mail|nhs|council tax|tv licen[cs]e|\+44[\s-]?\d|sort code|ofcom|barclays|natwest|lloyds|halifax|santander uk|monzo|evri|post office uk)\b|£"),
    ("au", r"\b(?:ato|mygov|centrelink|medicare card|australia ?post|auspost|\+61[\s-]?\d|commbank|westpac|anz|nab|linkt|e-?toll)\b|a\$"),
    ("ca", r"\b(?:cra|canada revenue|service canada|sin number|interac|e-?transfer|canada post|\+1[\s-]?(?:416|604|514|403|613|647)|rbc|td canada|scotiabank|bmo)\b|c\$"),
    ("nz", r"\b(?:ird|inland revenue nz|nz post|waka kotahi|nzta|\+64[\s-]?\d|kiwibank|asb)\b|nz\$"),
    ("ie", r"\b(?:revenue\.ie|an post|garda|\+353|ppsn|aib|bank of ireland|permanent tsb)\b"),
    ("us", r"\b(?:irs|ssa|social security|usps|zelle|venmo|cash ?app|e-?zpass|sunpass|medicare|\+1[\s-]?\d{3})\b"),
]


def guess_country(text: str) -> str | None:
    """Best-effort country hint from currency, phone prefixes and institutions. None = unclear (ask)."""
    import re
    hits = {}
    for cc, pat in _COUNTRY_CUES:
        n = len(re.findall(pat, text, re.I))
        if n:
            hits[cc] = n
    if not hits:
        return None
    best = sorted(hits.items(), key=lambda kv: -kv[1])
    if len(best) > 1 and best[0][1] == best[1][1]:
        return None
    return best[0][0]
