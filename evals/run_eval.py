#!/usr/bin/env python3
"""Evaluate the scam-signal rule engine on a JSONL eval set.

Each line: {"id", "channel", "label": scam|fraud|legit, "typology", "text"}

Metrics:
  * binary "needs action" (scam or fraud) vs legit: precision, recall, F1,
    false-positive rate on legit look-alikes
  * 3-way label accuracy (scam / fraud / legit)
  * typology accuracy on true scams that were detected

Usage:
    python3 evals/run_eval.py evals/dev.jsonl [evals/heldout.jsonl ...] [--md results.md] [--min-precision 0.9]
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "skills" / "scam-signal" / "scripts"))
import analyze  # noqa: E402

CHANNEL_MAP = {"call_transcript": "call", "social_dm": "dm", "sms": "sms", "email": "email", "complaint": "complaint"}


def run(path: Path) -> dict:
    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    out = []
    for r in rows:
        ch = CHANNEL_MAP.get(r["channel"], "unknown")
        text = r["text"]
        if analyze.looks_like_email(text):
            res = analyze.analyze(raw_email=text.encode(), channel="email")
        else:
            res = analyze.analyze(text, channel=ch)
        out.append({**r, "pred": res["label"], "pred_typology": res["typology"]["id"],
                    "score": res["score"]["total"], "risk": res["risk_level"],
                    "top_flags": [f["id"] for f in res["red_flags"][:4]]})
    # "unsupported" (language the rules don't cover) is an abstention: it is NOT a scam call,
    # so it counts as a miss on scams and as a non-flag on legit messages.
    pos = ("scam", "fraud")
    tp = sum(1 for o in out if o["label"] != "legit" and o["pred"] in pos)
    fp = sum(1 for o in out if o["label"] == "legit" and o["pred"] in pos)
    fn = sum(1 for o in out if o["label"] != "legit" and o["pred"] not in pos)
    tn = sum(1 for o in out if o["label"] == "legit" and o["pred"] not in pos)
    abstain = sum(1 for o in out if o["pred"] == "unsupported")
    prec = tp / (tp + fp) if tp + fp else 1.0
    rec = tp / (tp + fn) if tp + fn else 1.0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
    fpr = fp / (fp + tn) if fp + tn else 0.0
    acc3 = sum(1 for o in out if o["label"] == o["pred"]) / len(out)
    det = [o for o in out if o["label"] == "scam" and o["pred"] == "scam"]
    typ_acc = sum(1 for o in det if o["pred_typology"] == o["typology"]) / len(det) if det else 0.0
    return {
        "file": path.name, "n": len(out),
        "counts": {k: sum(1 for o in out if o["label"] == k) for k in ("scam", "fraud", "legit")},
        "tp": tp, "fp": fp, "fn": fn, "tn": tn, "abstained": abstain,
        "precision": round(prec, 3), "recall": round(rec, 3), "f1": round(f1, 3),
        "false_positive_rate": round(fpr, 3), "label_accuracy_3way": round(acc3, 3),
        "typology_accuracy_on_detected_scams": round(typ_acc, 3),
        "rows": out,
        "errors": [o for o in out if o["label"] != o["pred"] or (o["label"] == "scam" and o["pred_typology"] != o["typology"])],
    }


def to_md(results: list[dict]) -> str:
    L = ["| set | n (scam/fraud/legit) | precision | recall | F1 | false-positive rate | 3-way acc | typology acc | abstained |",
         "|---|---|---|---|---|---|---|---|---|"]
    for r in results:
        c = r["counts"]
        L.append(f"| {r['file']} | {r['n']} ({c['scam']}/{c['fraud']}/{c['legit']}) | {r['precision']:.2f} | {r['recall']:.2f} | "
                 f"{r['f1']:.2f} | {r['false_positive_rate']:.2f} ({r['fp']}/{r['fp'] + r['tn']}) | {r['label_accuracy_3way']:.2f} | "
                 f"{r['typology_accuracy_on_detected_scams']:.2f} | {r['abstained']} |")
    for r in results:
        if r["errors"]:
            L.append(f"\n**{r['file']}: errors**\n")
            L.append("| id | gold | pred | gold type | pred type | score | top flags |\n|---|---|---|---|---|---|---|")
            for e in r["errors"]:
                L.append(f"| {e['id']} | {e['label']} | {e['pred']} | {e['typology']} | {e['pred_typology']} | {e['score']} | {', '.join(e['top_flags'])} |")
    cats = {}
    for r in results:
        for o in r.get("rows", []):
            if "category" in o:
                c = cats.setdefault(o["category"], [0, 0])
                c[1] += 1
                c[0] += (o["label"] != "legit") == (o["pred"] in ("scam", "fraud"))
    if cats:
        L.append("\n**By category (correct / n)**: " + " · ".join(f"{k} {v[0]}/{v[1]}" for k, v in cats.items()))
    return "\n".join(L) + "\n"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("files", nargs="+")
    ap.add_argument("--md", help="write markdown summary here")
    ap.add_argument("--json", help="write full JSON results here")
    ap.add_argument("--min-precision", type=float, default=0.0)
    ap.add_argument("--max-fpr", type=float, default=1.0)
    a = ap.parse_args(argv)
    results = [run(Path(f)) for f in a.files]
    md = to_md(results)
    print(md)
    if a.md:
        Path(a.md).write_text(md, encoding="utf-8")
    if a.json:
        Path(a.json).write_text(json.dumps(results, indent=2), encoding="utf-8")
    bad = [r for r in results if r["precision"] < a.min_precision or r["false_positive_rate"] > a.max_fpr]
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main())
