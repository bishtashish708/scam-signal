# Roadmap / ideas for later (not implemented)

## Lower-friction inputs
- **iOS Shortcut / share sheet:** "Share → Check with scam-signal" on a text, email or screenshot. The Shortcut would OCR the image or take the text and open Claude with the skill prompt pre-filled. No server needed; the content goes only to the user's own Claude app.
- **Browser extension:** a right-click "Check this link/email with scam-signal" that runs the offline URL checks in-browser (the URL logic is pure and portable to JS) and hands the page/email text to Claude. Must never auto-visit links.
- **Forward-to-address flow:** e.g. forward a suspicious email to a personal address that triggers analysis. Requires running a mail-receiving service, which breaks the "no servers" privacy guarantee; it would need to be self-hosted by the user (e.g. a Cloudflare Email Worker they own). Lowest priority.
- **Android:** share-sheet intent equivalent of the iOS Shortcut.

## Detection
- LLM-in-the-loop eval (screenshots rendered from the eval sets; inbox triage against a seeded test mailbox).
- Close the stress-set gaps: "have your code ready" primers, implied overpayment, salary-range task-scam openers, legit crypto receipts.
- QR-code screenshots (quishing): decode and run url_check on the payload.
- Non-U.S. reporting tables (UK, CA, AU, IN).
- Optional local allow-list of the user's real bank/employer domains to cut false positives.
