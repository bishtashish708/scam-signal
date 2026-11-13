# Eval results: rule engine (v0.1.0)

These numbers measure the **deterministic signal engine** (`skills/scam-signal/scripts/analyze.py`) on its own, with no LLM. In the skill, Claude reads this engine's evidence *and* the message itself and makes the final call. The engine is the transparent floor, not the ceiling.

Reproduce: `python3 evals/run_eval.py evals/dev.jsonl evals/heldout.jsonl evals/stress.jsonl`

## Sets

| set | n | how it was made | tuned on? |
|---|---|---|---|
| `dev.jsonl` | 50 (30 scam / 3 unauthorized-fraud / 17 legit look-alikes) | Hand-written synthetic messages following patterns described in public FTC/IC3/CFPB consumer guidance | **Yes**: rules were developed against it, so its score is optimistic |
| `heldout.jsonl` | 30 (16 / 2 / 12) | Written by a separate agent that never saw the rules | First run with rules frozen (below), then two regex bugs fixed |
| `stress.jsonl` | 12 (4 subtle scams / 8 scary-looking legit) | Deliberately hard cases: link-free lures, legit messages with threat/urgency/crypto words | **No**: never tuned, kept as a known-limits benchmark |

All examples are synthetic. No real messages, people, or phone numbers (fictional 555-01xx only).

## Held-out, first run (rules frozen, the honest number)

| set | precision | recall | F1 | false-positive rate | 3-way acc | typology acc |
|---|---|---|---|---|---|---|
| heldout.jsonl (v1, frozen) | 1.00 | 0.89 | 0.94 | 0.00 (0/12) | 0.93 | 1.00 |

The two misses were regex bugs, not overfitting: `"sorry, wrong number!"` (punctuation variant) + `"I made 32% last week"`, and `"I … did not make or approve"` (words between subject and verb). After fixing those generic patterns:

## Current

| set | n (scam/fraud/legit) | precision | recall | F1 | false-positive rate | 3-way acc | typology acc |
|---|---|---|---|---|---|---|---|
| dev.jsonl | 50 (30/3/17) | 1.00 | 1.00 | 1.00 | 0.00 (0/17) | 1.00 | 0.97 |
| heldout.jsonl | 30 (16/2/12) | 1.00 | 1.00 | 1.00 | 0.00 (0/12) | 1.00 | 1.00 |
| stress.jsonl | 12 (4/0/8) | 0.00 | 0.00 | 0.00 | 0.12 (1/8) | 0.58 | 0.00 |

**dev.jsonl: errors**

| id | gold | pred | gold type | pred type | score | top flags |
|---|---|---|---|---|---|---|
| D18 | scam | scam | investment_crypto | unclear | 3 | wrong_number_opener |

**stress.jsonl: errors**

| id | gold | pred | gold type | pred type | score | top flags |
|---|---|---|---|---|---|---|
| S03 | legit | scam | none | investment_crypto | 4 | crypto_payment |
| S09 | scam | legit | bank_impersonation | none | 0 |  |
| S10 | scam | legit | marketplace | none | 0 |  |
| S11 | scam | legit | credential_phishing | none | 0 |  |
| S12 | scam | legit | employment_task | none | 0 |  |

### What the stress set shows

- **Link-free, low-pressure lures slip past rules** (S09 "a specialist will call you, have your code ready"; S11 "mailbox almost full, visit the portal"; S12 "earn a daily salary of 200-500 USD"; S10 implied overpayment). These are the cases where the LLM layer matters: Claude sees intent that keyword rules can't.
- **Crypto vocabulary over-triggers** (S03, a real exchange receipt with a wallet address). The skill tells Claude to weigh sender authentication and whether a payment is being *requested*.

## Metric definitions

- *precision / recall / F1 / FPR*: binary "needs action" (scam **or** unauthorized fraud) vs legit.
- *3-way acc*: exact label among scam / fraud / legit (the scam-vs-unauthorized distinction from the underlying research).
- *typology acc*: on true scams the engine flagged, whether the top type matches the gold type.

## Not yet measured

- End-to-end skill behaviour with Claude (screenshots, inbox triage via connector). Planned: a small LLM-in-the-loop run over `stress.jsonl` + screenshot renders, kept minimal to avoid burning shared subscription quota.
