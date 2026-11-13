"""Regression gate: the rule engine must keep precision/false-positive rate on the eval sets."""
import unittest

import _paths  # noqa: F401
import run_eval
from _paths import ROOT


class EvalGate(unittest.TestCase):
    def test_dev_and_heldout(self):
        for name in ("dev.jsonl", "heldout.jsonl"):
            r = run_eval.run(ROOT / "evals" / name)
            self.assertGreaterEqual(r["precision"], 0.95, name)
            self.assertLessEqual(r["false_positive_rate"], 0.10, name)
            self.assertGreaterEqual(r["recall"], 0.85, name)

    def test_stress_fpr_documented(self):
        # The stress set is intentionally NOT tuned on; only guard against FPR regressions.
        r = run_eval.run(ROOT / "evals" / "stress.jsonl")
        self.assertLessEqual(r["false_positive_rate"], 0.25)


if __name__ == "__main__":
    unittest.main()
