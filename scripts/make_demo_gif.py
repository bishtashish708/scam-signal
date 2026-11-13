"""Render docs/demo.gif: a screenshot-only demo built from clearly FICTIONAL content.

Dev-only helper (needs Pillow; the skill itself stays stdlib-only):
    pip install pillow && python3 scripts/make_demo_gif.py
The bank name, number and domain below are invented (555 number, .example-style domain).
"""
from __future__ import annotations

from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

W, H = 960, 600
BG, PANEL, INK, MUTED = "#0f1115", "#181b22", "#e8e8e8", "#8a8f98"
AMBER, RED, GREEN, BUBBLE = "#f5a524", "#ff5d5d", "#4cc38a", "#2a2d35"
OUT = Path(__file__).resolve().parents[1] / "docs" / "demo.gif"


def font(size: int, mono: bool = False):
    for p in (["/System/Library/Fonts/Menlo.ttc", "DejaVuSansMono.ttf"] if mono else
              ["/System/Library/Fonts/Helvetica.ttc", "DejaVuSans.ttf"]):
        try:
            return ImageFont.truetype(p, size)
        except OSError:
            continue
    return ImageFont.load_default()


F, FB, FS, FM = font(17), font(20), font(13), font(15, mono=True)

SMS = ("Northwind Credit Union ALERT: Did you attempt a $1,250.00 transfer to "
       "M. LOPEZ? If NOT, call our fraud dept now at 555-0142 or verify at "
       "northwind-cu-secure.top. Account locks in 30 min.")

REPORT = [
    ("Verdict: Very likely a scam (confidence: high)", RED, FB),
    ("Type: Bank / fraud-department impersonation", INK, F),
    ("FTC: Imposter scams · IC3: Gov't/Business Impersonation · CFPB: Fraud or scam", MUTED, FS),
    ("", INK, F),
    ("Red flags", AMBER, F),
    ('1. Callback number inside the text: "call our fraud dept now at 555-0142"', INK, F),
    ('2. Link is not the bank\'s domain: northwind-cu-secure.top (.top TLD)', INK, F),
    ('3. Countdown threat: "Account locks in 30 min."', INK, F),
    ("", INK, F),
    ("What to do now", GREEN, F),
    ("- Don't call or tap. Use the number on the back of your card / the official app.", INK, F),
    ("- Never read back a code or move money to a \"safe\" account.", INK, F),
    ("Report: forward to 7726 · reportfraud.ftc.gov · your bank", MUTED, F),
]


def wrap(d, text, fnt, width):
    words, lines, cur = text.split(), [], ""
    for w in words:
        t = (cur + " " + w).strip()
        if d.textlength(t, font=fnt) <= width:
            cur = t
        else:
            lines.append(cur)
            cur = w
    return lines + [cur]


def base(step: str) -> tuple[Image.Image, ImageDraw.ImageDraw]:
    im = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(im)
    d.rectangle([0, 0, W, 34], fill=PANEL)
    d.text((14, 8), "scam-signal demo", font=F, fill=INK)
    d.text((W - 14, 10), "FICTIONAL SAMPLE: not a real bank, number or site", font=FS, fill=AMBER, anchor="ra")
    d.text((14, H - 24), step, font=FS, fill=MUTED)
    return im, d


def phone(d, x=40, y=60):
    d.rounded_rectangle([x, y, x + 300, y + 500], 28, fill=PANEL, outline="#2f333c", width=2)
    d.text((x + 150, y + 22), "+1 (555) 010-0199", font=FS, fill=MUTED, anchor="ma")
    d.text((x + 150, y + 40), "Not in your contacts", font=FS, fill=MUTED, anchor="ma")
    lines = wrap(d, SMS, FS, 230)
    h = 18 * len(lines) + 20
    d.rounded_rectangle([x + 18, y + 80, x + 262, y + 80 + h], 14, fill=BUBBLE)
    for i, ln in enumerate(lines):
        d.text((x + 30, y + 90 + 18 * i), ln, font=FS, fill=INK)


def frames():
    out = []
    im, d = base("1/3  Screenshot the text. No copy-paste needed.")
    phone(d)
    out += [(im, 1800)]
    prompt = "[screenshot attached]  is this real?"
    for k in range(0, len(prompt) + 1, 3):
        im, d = base("2/3  Drop it into Claude and ask.")
        phone(d)
        d.rounded_rectangle([370, 470, W - 30, 530], 12, fill=PANEL, outline="#2f333c")
        d.text((388, 490), prompt[:k] + "▌", font=FM, fill=INK)
        out.append((im, 60))
    out[-1] = (out[-1][0], 900)
    for n in range(1, len(REPORT) + 1):
        im, d = base("3/3  Evidence-quoted verdict, what to do, where to report.")
        d.rounded_rectangle([30, 50, W - 30, H - 40], 14, fill=PANEL)
        y = 66
        for text, col, fnt in REPORT[:n]:
            for ln in wrap(d, text, fnt, W - 110) if text else [""]:
                d.text((52, y), ln, font=fnt, fill=col)
                y += 30 if fnt is FB else 25
        out.append((im, 3500 if n == len(REPORT) else 260))
    return out


def main():
    fr = frames()
    OUT.parent.mkdir(parents=True, exist_ok=True)
    pal = [f[0].convert("P", palette=Image.ADAPTIVE, colors=64) for f in fr]
    pal[0].save(OUT, save_all=True, append_images=pal[1:], duration=[f[1] for f in fr], loop=0, optimize=True)
    print(OUT, OUT.stat().st_size // 1024, "KB,", len(fr), "frames")


if __name__ == "__main__":
    main()
