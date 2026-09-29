import subprocess
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class StatementParityFixture(unittest.TestCase):
    def test_generator_reproduces_committed_bytes(self):
        generated = subprocess.check_output(
            [sys.executable, str(ROOT / "tools/gen_consent_v2_statement_parity.py")], cwd=ROOT)
        self.assertEqual(generated, (ROOT / "testdata/consent-v2.statement-parity.json").read_bytes())


if __name__ == "__main__":
    unittest.main()
