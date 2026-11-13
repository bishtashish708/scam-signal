#!/usr/bin/env python3
"""Build dist/scam-signal.zip for uploading to Claude.ai / Cowork (Settings -> Capabilities -> Skills)."""
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SKILL = ROOT / "skills" / "scam-signal"
out = ROOT / "dist" / "scam-signal.zip"
out.parent.mkdir(exist_ok=True)
with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
    for p in sorted(SKILL.rglob("*")):
        if p.is_file() and "__pycache__" not in p.parts and not p.name.startswith("."):
            z.write(p, Path("scam-signal") / p.relative_to(SKILL))
print(f"wrote {out} ({out.stat().st_size // 1024} KB)")
