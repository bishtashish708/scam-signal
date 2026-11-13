import json
import re
import unittest

from _paths import ROOT

SKILL = ROOT / "skills" / "scam-signal" / "SKILL.md"


class PackagingTests(unittest.TestCase):
    def test_manifests(self):
        plugin = json.loads((ROOT / ".claude-plugin" / "plugin.json").read_text())
        market = json.loads((ROOT / ".claude-plugin" / "marketplace.json").read_text())
        self.assertEqual(plugin["name"], "scam-signal")
        self.assertEqual(market["plugins"][0]["name"], "scam-signal")
        # skills-only plugin: no hooks, commands, agents or MCP servers
        for k in ("hooks", "mcpServers", "commands", "agents"):
            self.assertNotIn(k, plugin)
        for d in ("hooks", "commands", "agents"):
            self.assertFalse((ROOT / d).exists(), d)
        self.assertFalse((ROOT / ".mcp.json").exists())

    def test_skill_frontmatter(self):
        text = SKILL.read_text()
        m = re.match(r"^---\n(.*?)\n---\n", text, re.S)
        self.assertIsNotNone(m)
        fm = dict(line.split(": ", 1) for line in m.group(1).splitlines() if ": " in line)
        self.assertEqual(fm["name"], "scam-signal")
        self.assertLessEqual(len(fm["description"]), 1024)
        for trigger in ("is this a scam", "check my inbox", "screenshot"):
            self.assertIn(trigger, fm["description"].lower())

    def test_referenced_files_exist(self):
        text = SKILL.read_text()
        for ref in set(re.findall(r"`((?:scripts|references)/[\w./-]+)`", text)):
            self.assertTrue((SKILL.parent / ref.split()[0]).exists(), ref)

    def test_no_real_pii_in_repo(self):
        # Phone numbers in data must be 555-01xx fictional range or short codes.
        pat = re.compile(r"(?<![\d-])\(?(\d{3})\)?[ .-]?(\d{3})[ .-]?(\d{4})(?![\d-])")
        for p in list((ROOT / "evals").glob("*.jsonl")) + list((ROOT / "tests" / "fixtures").glob("*")):
            for m in pat.finditer(p.read_text(errors="ignore")):
                a, b, c = m.groups()
                if b == "555" or a == "555" or (a + b + c).startswith(("1833372", "18333728")):
                    continue
                if a == "021" and b == "000":  # public routing number used in redaction test
                    continue
                self.fail(f"possible real phone number {m.group(0)} in {p.name}")


if __name__ == "__main__":
    unittest.main()
