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
