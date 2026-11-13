# Demo GIF

**Shipped:** [`demo.gif`](demo.gif) is a screenshot-only demo rendered by [`scripts/make_demo_gif.py`](../scripts/make_demo_gif.py) (dev-only, needs Pillow: `pip install pillow && python3 scripts/make_demo_gif.py`).

- **All content is fictional.** "Northwind Credit Union" is a made-up institution. The phone numbers are 555-01xx. `northwind-cu-secure.top` is invented. Every frame is labeled "FICTIONAL SAMPLE".
- **Scenes:**
  1. A text from an unknown number.
  2. It's dropped into Claude with "is this real?".
  3. The verdict appears, with quoted red flags, what to do, and where to report.
- The report frame is a condensed rendering of the skill's output format. The live Claude answers for comparable prompts are in [`evals/RESULTS.md`](../evals/RESULTS.md#live-llm-in-the-loop-check-claude-code-skill-loaded-via---plugin-dir).

## Not recorded (by choice)

Inbox triage on video would need a seeded **test** mailbox. Never record a real inbox, real messages or real phone numbers. If one is made later:
1. Seed a throwaway Gmail account with about 10 synthetic emails from `evals/dev.jsonl`.
2. Connect it in Claude.ai and ask "check my inbox for scams from the last week".
3. Capture with `ffmpeg -i in.mov -vf "fps=12,scale=900:-1:flags=lanczos" -loop 0 docs/demo-inbox.gif` and keep the file under 5 MB.
