import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "skills" / "scam-signal" / "scripts"
for p in (str(SCRIPTS), str(ROOT / "tests"), str(ROOT / "evals"), str(ROOT / "experimental")):
    if p not in sys.path:
        sys.path.insert(0, p)
