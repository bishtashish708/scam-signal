# Getting started (no coding needed)

Set it up once on a computer (about 3 minutes). After that, check suspicious texts from your phone by sending Claude a screenshot.

> You need a Claude account (claude.ai). Custom skills work on Free, Pro, Max and Ultra plans. On Team and Enterprise plans, an owner has to allow skills first (see the last section).

---

## Part 1: Install once, on a computer

**1. Download the skill**
- Open **https://github.com/bishtashish708/scam-signal/releases/latest** and click **`scam-signal.zip`** under *Assets*.
- Or use the direct link: https://github.com/bishtashish708/scam-signal/releases/latest/download/scam-signal.zip
- **Don't unzip it.** Claude wants the .zip file itself.

**2. Turn on code execution** (it lets the skill's checks run)
1. Go to **claude.ai**, then click your name or initials (bottom-left), then **Settings**.
2. Open **Capabilities**.
3. Switch on **Code execution and file creation**. In newer layouts it's called **Create and edit files**.

**3. Upload the skill**
1. Open **Customize → Skills**.
2. Click **+**, then **+ Create skill**, then **Upload a skill**.
3. Choose the `scam-signal.zip` you downloaded.
4. Make sure **scam-signal** shows up in the list and its toggle is **on**.

**4. Test it**
Start a new chat and paste:
> is this a scam? "USPS: your package is on hold. Pay $1.99 at usps-redelivery-help.top within 12 hours"

You should get a **Verdict**, **Red flags** with quotes, **What to do now** and **Where to report**.

---

## Part 2: Use it from your phone

Your skills belong to your Claude account. Install the **Claude** app (App Store / Google Play) and sign in with the same account.

> If the phone app doesn't seem to use the skill, check that the toggle under **Customize → Skills** is still on, then ask directly: "use scam-signal: is this a scam?"

### Got a weird text? (iPhone)
1. Take a screenshot: press **Side button + Volume up** at the same time.
2. Tap the thumbnail in the corner, then the **Share** icon (square with an arrow), then **Claude**. Or open the Claude app, tap **+**, then **Photos**, and pick the screenshot.
3. Type **"is this a scam?"** and send.

### Got a weird text? (Android)
1. Take a screenshot: press **Power + Volume down**.
2. Tap **Share** on the preview, then **Claude**. Or open Claude, tap **+**, and pick the image.
3. Type **"is this a scam?"** and send.

### Other things you can send
| Situation | What to send |
|---|---|
| Suspicious email | A screenshot, or forward/paste it. For the most thorough check, save it as a file (Gmail: ⋮ → **Download message**) and attach it in Claude on a computer. |
| A link | Long-press the link → **Copy**, then paste it. **Don't open it.** |
| A long WhatsApp chat | In WhatsApp, open the chat → tap the name → **Export chat → Without media** → share to Claude. Scams like "wrong number" crypto friendships only show up across many messages. |
| A QR code | **Don't scan it to pay.** Point your camera at it *without tapping*, read the web address it shows, and send Claude that address. |
| A phone call | Describe it in your own words: who they said they were, and what they wanted you to do or pay. |
| "I already paid / gave a code" | Say exactly that first. Claude will lead with what to do right now. |

**Tips**
- Crop out anything private that isn't needed: your own account numbers, codes you received, other people's names.
- Never send Claude passwords, full card numbers or one-time codes. It will never ask for them.
- Want it to check your whole inbox? Connect Gmail or Outlook in Claude's **Connectors** settings, then ask *"check my inbox for scams from the last week"*. It only reads; it never replies, deletes or moves mail.

---

## Team / Enterprise plans

An owner goes to **Organization settings → Plugins & skills → Policy** and turns on **Code execution and file creation** and **Skills**. Owners can also upload `scam-signal.zip` there to provision it for everyone.

## Claude Code (developers)

```bash
/plugin marketplace add bishtashish708/scam-signal
/plugin install scam-signal@scam-signal
```

---

*Menu names follow Anthropic's help article ["Use skills in Claude"](https://support.claude.com/en/articles/12512180-use-skills-in-claude) as of November 2026. If a menu has moved, search the settings for "Skills".*
