# Scam typology reference

This typology comes from an in-progress research study of CFPB consumer complaints about P2P / real-time payments (Zelle, Venmo, Cash App, PayPal). It is aligned with the public category schemes used by the **FTC Consumer Sentinel Network**, the **FBI Internet Crime Complaint Center (IC3)** and the **CFPB Consumer Complaint Database**, so a finding can be reported in the vocabulary each agency uses.

## The first question: scam or unauthorized fraud?

The study's central distinction (its "Stage 1") is:

> *At the moment the money moved, did the person take the action themselves (send, approve, authorize) because they were deceived, or did the money move without their knowledge or authorization?*

| | **Scam** (authorized under deception) | **Unauthorized / non-consensual fraud** |
|---|---|---|
| Who pressed "send" | The victim, believing it was legitimate | Someone else (stolen login, SIM swap, hacked app) |
| Typical words | "they told me to…", "I sent it because…" | "I didn't make this", "without my knowledge" |
| U.S. rights | Reg E error-resolution generally does **not** cover payments the consumer authorized, even if induced by fraud; recovery depends on the bank's/app's voluntary policies, so report fast anyway | Reg E (EFTA) treats these as **unauthorized EFTs**: report promptly, as liability limits depend on how quickly you notify the institution |
| What to tell the bank | "I was the victim of a scam; please attempt a recall and review" | "These are **unauthorized** transactions; I'm filing an error-resolution dispute" |

Edge cases the study flags (handle them carefully and tell the user it's a gray area):
- **OTP read-back.** A fake "fraud department" gets the victim to read back a one-time code, which the scammer uses to authorize a transfer the victim never saw. The victim was deceived, but the transfer itself wasn't knowingly approved. Advise reporting it to the bank as **unauthorized** and also describing the deception. Let the institution and, if needed, the CFPB sort out liability.
- **Remote access.** The victim installed AnyDesk or similar and the scammer clicked "send". Same advice: describe both the access and the fact that the victim did not initiate the transfer.
- **"Safe account."** The victim moved money "to protect it". This is a scam (authorized), and it is the most common bank-impersonation endgame.

## Types

Each entry gives: what it looks like · common tells · **FTC** / **IC3** / **CFPB** category.

### 1. Bank / fraud-department impersonation (`bank_impersonation`)
A text, call or email "from your bank's fraud team" about a suspicious charge or Zelle payment. Endgames: move money to a "safe account", send a Zelle "to yourself" or "to reverse the charge", read back a code, or give your login.
Tells: spoofed caller ID, "don't tell the teller", "stay on the line", a callback number inside the text, links to lookalike bank domains.
**FTC:** Imposter scams: business imposters · **IC3:** Government/Business Impersonation, Phishing/Spoofing · **CFPB:** Fraud or scam.

### 2. Government / law-enforcement impersonation (`government_impersonation`)
IRS, Social Security, Medicare, police, sheriff, court/jury duty, immigration (USCIS), customs. Threatens arrest, suspended SSN or deportation; demands gift cards, crypto, cash courier or wire.
**FTC:** Imposter scams: government imposters · **IC3:** Government Impersonation.

### 3. Tech support / fake refund / fake renewal (`tech_support_refund`)
Pop-up "virus detected, call Microsoft", or a fake Geek Squad/Norton/McAfee renewal invoice with a phone number. Leads to remote access, then a staged "accidental over-refund" and a demand to send back the difference (wire, gift cards, cash).
**FTC:** Imposter scams: tech support · **IC3:** Tech Support.

### 4. Package delivery / unpaid toll smishing (`delivery_toll_smishing`)
"USPS: package on hold, update address", "Unpaid toll $4.15, pay now to avoid $50 fee". Small fee, link to a lookalike payment page that harvests card data. May use the "reply Y then reopen to activate the link" trick.
**FTC:** Imposter scams: business imposters · **IC3:** Phishing/Spoofing.

### 5. Account credential phishing (`credential_phishing`)
"Verify your account", "password expires today", "mailbox full", "unusual sign-in", "document shared with you (DocuSign)". Leads to a fake login page.
**FTC:** Imposter scams: business imposters · **IC3:** Phishing/Spoofing.

### 6. Marketplace / purchase / rental (`marketplace`)
Fake sellers (pets, tickets, cars, rentals: "I'm out of the country, I'll mail the keys"), fake buyers (overpay "for the mover", fake "Zelle business upgrade" email), and the Google Voice "verify you're real, tell me the code" scam. P2P apps are designed for paying people you know and offer little purchase protection.
**FTC:** Online shopping · **IC3:** Non-Payment/Non-Delivery, Overpayment, Real Estate · **CFPB:** Fraud or scam (P2P).

### 7. Romance / confidence (`romance`)
An online-only relationship (dating apps, social media), often with a far-away job (military, oil rig, doctor abroad) and no video calls, followed by emergencies, customs fees, travel money, or a pivot to "investing together".
**FTC:** Imposter scams: romance scams · **IC3:** Romance/Confidence Fraud.

### 8. Investment / crypto ("pig butchering") (`investment_crypto`)
Often starts with a "wrong number" text or a friendly stranger, moves to WhatsApp/Telegram, then introduces a "mentor/uncle" and a trading platform showing fake gains. Withdrawals require ever-larger "taxes/fees".
**FTC:** Investment related · **IC3:** Investment (largest reported losses in recent IC3 reports).

### 9. Job / task / fake check (`employment_task`)
Easy remote work ("rate products", "optimize orders", earn $300 to $800/day), pay-to-unlock "task sets", mystery shopper, or "deposit our check and buy equipment from our vendor".
**FTC:** Business and job opportunities · **IC3:** Employment.

### 10. Family / friend emergency (`family_emergency`)
"Grandma, it's me, I'm in jail", "Hi Mum, new number". Urgent, secret, sometimes with a fake lawyer or courier collecting cash. Voices can be AI-cloned.
**FTC:** Imposter scams: family & friend imposters · **IC3:** Confidence Fraud.

### 11. Prize / lottery / grant / inheritance (advance fee) (`prize_advance_fee`)
"You won", "unclaimed inheritance", "government grant", but you have to pay a fee, tax or shipping charge first.
**FTC:** Prizes, sweepstakes and lotteries · **IC3:** Lottery/Sweepstakes/Inheritance, Advanced Fee.

### 12. Sextortion / extortion (`extortion`)
"I recorded you through your webcam", "pay in Bitcoin or I'll send it to your contacts". Mass-mailed versions often quote an old leaked password and have no real material.
**FTC:** Imposter/other · **IC3:** Extortion. If a minor is involved: NCMEC.

### 13. Unauthorized transaction / account takeover (`account_takeover`): not a scam
"Money left my account and I didn't do it": stolen credentials, SIM swap, hacked email used to reset the app. Advise an **unauthorized-transaction dispute**, password and 2FA reset, a carrier port-out lock, and a credit freeze.
**FTC:** Identity theft · **IC3:** Identity Theft / SIM Swap · **CFPB:** Fraud or scam (unauthorized transactions, Reg E).

## Context from the data (for orientation, not prediction)

The underlying study uses the public CFPB Consumer Complaint Database export filtered to *Issue = "Fraud or scam"*, *Product = "Money transfer, virtual currency, or money service"*, sub-products *Mobile or digital wallet* and *Domestic (US) money transfer* (complaints received 2023-07 to 2026-07; 10,008 narratives after cleaning; 4,361 explicitly naming a P2P rail).

A **preliminary keyword scan** of those narratives (not a validated classifier; categories overlap; keyword presence ≠ scam type) gives a rough sense of what people complain about:

| cue (keyword family) | share of narratives |
|---|---|
| uses the word "scam/scammer" | 43.6% |
| first-person "unauthorized / didn't authorize / without my permission" | 13.5% |
| marketplace terms (seller, listing, tickets, rental, landlord…) | 13.4% |
| bank / fraud-department impersonation terms | 8.3% |
| investment / crypto terms | 5.0% |
| government-agency terms | 1.8% |
| romance terms | 0.9% |
| one-time / verification code mentions | 0.6% |

Two takeaways shape this skill: (1) roughly a seventh of complaints describe **unauthorized** activity rather than a scam, so the tool always checks which side of that line a story falls on; (2) **marketplace** and **bank-impersonation** patterns are prominent on P2P rails, so those get detailed handling.

Public agency figures (check the latest annual reports for current numbers): the FTC's Consumer Sentinel data for 2024 reported about $12.5B in consumer fraud losses, with **imposter scams** the most-reported category and **investment scams** the largest losses. The FBI IC3 2024 report recorded about $16.6B in losses, with **phishing/spoofing** the most-reported crime type and **investment fraud** the costliest.


---

## Added in v0.3

| Type (`id`) | Stage 1 | FTC Consumer Sentinel | FBI IC3 | CFPB | What it looks like |
|---|---|---|---|---|---|
| Changed bank details / payment redirection (`bec_payment_redirect`) | scam | Imposter: business | **Business Email Compromise** | Fraud or scam (money transfer) | "Our bank details have changed, pay invoice #… to the new account". Also used for real-estate closing funds, payroll direct-deposit changes, landlord deposits. Often sent from a hacked or lookalike mailbox. |
| Fake invoice / renewal (`fake_invoice`) | scam | Imposter: business | Phishing/Spoofing; Tech Support (callback) | Fraud or scam | An invoice or PDF "receipt" for something you didn't buy (PayPal, Geek Squad, antivirus, a domain listing), with a phone number to "cancel". *If it pairs with a device scare or remote access, use* `tech_support_refund`. |
| QR-code phishing (`qr_phishing`) | scam | Imposter: business | Phishing/Spoofing | Fraud or scam | Stickers on parking meters and EV chargers, letters, emails or PDFs that say "scan to pay / re-verify MFA". The QR hides the destination from the user and from mail filters. |
| Crypto wallet drainer (`wallet_drainer`) | scam | Imposter; cryptocurrency | Phishing/Spoofing (crypto) | Fraud or scam (virtual currency) | Airdrop, free mint, "wallet out of sync", fake support. You "connect wallet and sign", or are asked for the recovery phrase. |
| Fund-recovery scam (`recovery_scam`) | scam | Imposter (law firm, agency, "ethical hackers") | Government Impersonation; Advanced Fee | Fraud or scam | Targets past victims: "we traced your lost funds", fee or tax up front. Agencies and police never charge to recover money. |

Mappings for these five are best-fit. FTC and IC3 don't have exact categories for every subtype, so name the subtype in the free-text field when reporting.

**Multi-message long cons.** Pig-butchering (`investment_crypto`), job/task (`employment_task`) and romance (`romance`) often look harmless message by message. Use a chat export and look at the progression of stages (`scripts/chat_export.py`).
