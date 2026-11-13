# Red-flag catalog

Use these to explain *why* something is risky. Always quote the exact words from the message as evidence. Strength: **S** = strong on its own, **M** = meaningful in combination, **W** = weak/context.

## Strong (any one usually means "treat as a scam")

| Flag | Examples |
|---|---|
| Move money to a "safe/secure/new" account, or Zelle "to yourself" | "transfer your savings to the protected account" |
| Asks you to read back / share a one-time or verification code | "read me the 6-digit code we just sent", "tell me the code to verify you're real" |
| Payment by gift card, crypto/Bitcoin ATM, cash courier, cash in a box | "buy Google Play cards and read me the numbers" |
| Remote-access software | AnyDesk, TeamViewer, Quick Assist, ScreenConnect |
| Overpayment + "send back the difference" | "I accidentally refunded $3,000 instead of $300" |
| Pay a fee/tax to receive money | "15% withdrawal tax", "processing fee to release your prize" |
| Secrecy from bank/family | "don't tell the teller", "bank staff may be involved", "don't tell mom" |
| Lookalike / punycode / brand-in-wrong-domain link | `paypa1-secure.com`, `chase-alerts.top`, `apple.com.verify-id.cyou` |
| DMARC fail, display name ≠ sender, Reply-To to another domain | "PayPal Service" &lt;service@paypa1-resolution.com&gt; replying to a Gmail address |
| "Reply Y and reopen to activate the link" | iMessage link-activation trick |
| Sextortion threats | "I recorded you… pay in Bitcoin" |

## Medium

- Threats: arrest, warrant, suspended SSN/account, legal action, late fee
- Urgency: "within 24 hours", "final notice", "act fast, many people interested"
- Callback number inside the message ("if NOT you, call 555-…"). Real banks say "call the number on the back of your card".
- Claims to be a bank, agency or big brand while contacting you out of the blue
- Moves you to WhatsApp/Telegram; "wrong number" friendly openers
- Too good to be true: guaranteed returns, "30% weekly", easy $500/day tasks
- Can't meet or video call; seller/landlord abroad; "my shipping agent will pick it up"
- Shortened links (bit.ly, etc.), free site builders, Google Forms for "account verification"
- Risky attachments: .html, .zip, .iso, .exe, macro-enabled Office files

## Weak / context

- Spelling and grammar errors (many real scams are polished; many real messages are sloppy)
- Generic greeting ("Dear Customer")
- High-abuse TLDs (.top, .xyz, .icu, .cyou…)
- Message-ID or bounce domain differs (often normal for bulk-mail services)

## Legitimate look-alikes (don't over-flag)

| Looks scary but is usually fine | Why |
|---|---|
| Card alert "Did you attempt $612 at BESTBUY? Reply YES or NO", with no link and no number to call | Banks do use YES/NO texts; the danger is a link or a callback number |
| A 2FA code text that you just requested, saying "don't share this code" | Normal. It becomes a scam the moment someone *asks you for it* |
| Delivery or shipping notice from the carrier's real domain (usps.com, amazon.com) with no fee | No payment request |
| A crypto exchange receipt for a transaction you made | Crypto words alone aren't a scam |
| A friend/roommate asking you to Venmo/Zelle for rent or dinner | Known person, expected payment. Still confirm by another channel if it comes from a "new number" |
| "Your card was locked, use the app or the number on your card" | Directs you to the official channel |

## Weighing

- One strong flag → **Likely a scam**. Two or more strong flags, or a strong flag plus pressure → **Very likely**.
- Only medium flags → **Suspicious: verify before acting**.
- Only weak flags, or reassuring signals + no payment/credential ask → **Probably legitimate**, but always add "verify through the official app or a number you look up yourself".
- Missing info (a cropped screenshot, a forwarded email with no headers) → say what would raise confidence.
