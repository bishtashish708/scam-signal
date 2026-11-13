# Demo GIF plan (≈20 s, synthetic data only)

**Never record a real inbox, real messages, or real phone numbers.**

1. **Asset:** a synthetic iPhone-style screenshot of a text from a 5-digit short code:
   "Wells Fargo Fraud Alert: Did you attempt a Zelle payment of $1,250.00 to MARIA L? If NOT, call our fraud department immediately at 555-0142. Your account will be locked in 30 minutes."
   Build it as a small HTML mock (fictional brand styling, clearly labeled "DEMO" in a corner) and screenshot it. Don't use a real bank's logo.
2. **Scene 1 (0-8 s):** Claude.ai with the skill enabled. Drag in the screenshot and type "is this real?".
3. **Scene 2 (8-15 s):** the report streams in: verdict, type with FTC/IC3/CFPB mapping, red flags with quoted evidence, what to do, report to 7726 / reportfraud.ftc.gov. Zoom on the red-flags block.
4. **Scene 3 (15-20 s), optional:** "check my inbox for scams from the last week" against a **seeded test Gmail account** containing 10 synthetic emails from `evals/dev.jsonl`. Show the triage table.
5. **Capture:** macOS screen recording → `ffmpeg -i in.mov -vf "fps=12,scale=900:-1:flags=lanczos" -loop 0 demo.gif`; keep it under 5 MB; save it as `assets/demo.gif` and reference it at the top of the README.
