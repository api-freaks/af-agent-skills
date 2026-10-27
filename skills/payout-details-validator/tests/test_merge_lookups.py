"""Tests for scripts/merge_lookups.py. No network."""

import json
import os
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(__file__)
SCRIPT = os.path.join(HERE, "..", "scripts", "merge_lookups.py")


def run(tmp, lines, prepared):
    pp = os.path.join(tmp, "prepared.json")
    jp = os.path.join(tmp, "lookups.jsonl")
    out = os.path.join(tmp, "lookups.json")
    with open(pp, "w") as fh:
        json.dump(prepared, fh)
    with open(jp, "w") as fh:
        fh.write(lines)
    proc = subprocess.run([sys.executable, "-I", SCRIPT, "--prepared", pp, "--jsonl", jp, "--out", out],
                          capture_output=True, text=True)
    data = json.load(open(out)) if os.path.exists(out) else None
    return proc, data


PREP = {"to_lookup": {"ibans": ["DE89370400440532013000", "GB29NWBK60161331926819"], "bics": ["DEUTDEFF"]}}


class MergeLookups(unittest.TestCase):
    def test_complete_exits_zero(self):
        with tempfile.TemporaryDirectory() as tmp:
            lines = "".join(json.dumps(x) + "\n" for x in [
                {"kind": "iban", "key": "DE89370400440532013000", "result": {"valid": True}},
                {"kind": "iban", "key": "GB29NWBK60161331926819", "result": {"valid": True}},
                {"kind": "bic", "key": "DEUTDEFF", "result": {"found": True}}])
            proc, data = run(tmp, lines, PREP)
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            self.assertEqual(len(data["ibans"]), 2)

    def test_last_record_wins_and_keys_normalised(self):
        with tempfile.TemporaryDirectory() as tmp:
            lines = "".join(json.dumps(x) + "\n" for x in [
                {"kind": "iban", "key": "de89 3704 0044 0532 0130 00", "result": {"valid": False}},
                {"kind": "iban", "key": "DE89370400440532013000", "result": {"valid": True}}])
            proc, data = run(tmp, lines, PREP)
            self.assertEqual(proc.returncode, 3)
            self.assertTrue(data["ibans"]["DE89370400440532013000"]["valid"])

    def test_truncated_line_is_skipped_and_counts_as_remaining(self):
        with tempfile.TemporaryDirectory() as tmp:
            lines = json.dumps({"kind": "bic", "key": "DEUTDEFF", "result": {"found": True}}) + '\n{"kind":"iban","key":"DE89'
            proc, data = run(tmp, lines, PREP)
            self.assertEqual(proc.returncode, 3)
            self.assertIn("unreadable", proc.stdout)
            self.assertEqual(len(data["bics"]), 1)

    def test_unrequested_keys_are_dropped(self):
        with tempfile.TemporaryDirectory() as tmp:
            lines = json.dumps({"kind": "iban", "key": "FR1420041010050500013M02606", "result": {"valid": True}}) + "\n"
            proc, data = run(tmp, lines, PREP)
            self.assertEqual(data["ibans"], {})
            self.assertIn("match no requested value", proc.stdout)


if __name__ == "__main__":
    unittest.main()
