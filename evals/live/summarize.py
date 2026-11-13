"""Summarize run_live.sh output: did scam-signal trigger, which tools ran, final answer head."""
import json
import sys
from pathlib import Path

cases = [json.loads(line) for line in open(Path(__file__).with_name("cases.jsonl"))]
out = Path(sys.argv[1])
for c in cases:
    skill, tools, final = False, [], ""
    for line in open(out / f"{c['id']}.jsonl"):
        e = json.loads(line)
        if e.get("type") == "assistant":
            for b in e["message"].get("content", []):
                if b.get("type") == "tool_use":
                    tools.append(b["name"])
                    skill |= b["name"] == "Skill" and "scam-signal" in json.dumps(b["input"])
        if e.get("type") == "result":
            final = e.get("result", "")
    print(f"{c['id']} expect={c['expect']}/{c['gold']} skill={'yes' if skill else 'no'} tools={tools}")
    print("   " + final[:300].replace("\n", " ") + "\n")
