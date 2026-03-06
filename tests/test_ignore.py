from __future__ import annotations

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from skillray_scan.ignore import load_ignore_file, match_ignore
from skillray_scan.models import Finding


class IgnoreTest(unittest.TestCase):
    def _finding(self, file_path: str) -> Finding:
        return Finding(
            id="SR-SCRIPT-001",
            severity="High",
            title="Potential shell command execution in script",
            file=file_path,
            line=10,
            evidence="subprocess.run(cmd, shell=True)",
            recommendation="Avoid shell=True.",
        )

    def test_global_rule_ignore(self) -> None:
        with TemporaryDirectory() as tmp:
            ignore_path = Path(tmp) / ".skillrayignore"
            ignore_path.write_text("SR-SCRIPT-001\n", encoding="utf-8")

            config = load_ignore_file(ignore_path)
            reason = match_ignore(self._finding("skills/a/scripts/run.py"), config)

            self.assertIsNotNone(reason)
            self.assertIn("globally", reason or "")

    def test_scoped_rule_ignore(self) -> None:
        with TemporaryDirectory() as tmp:
            ignore_path = Path(tmp) / ".skillrayignore"
            ignore_path.write_text(
                "SR-SCRIPT-001:skills/*/scripts/*.py\n",
                encoding="utf-8",
            )

            config = load_ignore_file(ignore_path)
            matched = match_ignore(self._finding("skills/a/scripts/run.py"), config)
            not_matched = match_ignore(self._finding("skills/a/SKILL.md"), config)

            self.assertIsNotNone(matched)
            self.assertIn("pattern", matched or "")
            self.assertIsNone(not_matched)


if __name__ == "__main__":
    unittest.main()
