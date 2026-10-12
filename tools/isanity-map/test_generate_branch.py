"""Regression checks for the source-derived branch handoff table."""

from __future__ import annotations

import subprocess
import sys
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("generate_branch.py")


class BranchGeneratorTests(unittest.TestCase):
    def test_checked_in_table_matches_both_pinned_isanity_slices(self) -> None:
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "--check"],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("16 near-Jcc identities", result.stdout)


if __name__ == "__main__":
    unittest.main()
