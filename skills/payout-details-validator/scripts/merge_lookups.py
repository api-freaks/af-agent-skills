#!/usr/bin/env python3
"""Merge per-call lookup records into lookups.json and report what is still missing.

The agent appends one JSON object per MCP call to lookups.jsonl:

  {"kind": "iban", "key": "DE89370400440532013000", "result": {...flat or tool body...}}
  {"kind": "bic",  "key": "DEUTDEFF", "result": {"found": false, "error": null}}

Keys are the values from prepared.json to_lookup. The last record for a key wins,
so a retry simply appends. This script never calls the network.

Usage:
  python scripts/merge_lookups.py --prepared pdv-work/prepared.json \
      --jsonl pdv-work/lookups.jsonl --out pdv-work/lookups.json

Prints done and remaining counts. Exit code 0 when nothing remains, 3 when some
lookups are still missing (so the agent knows to continue), 2 on bad input.
"""
import argparse
import json
import sys


def norm(value):
    return "".join(str(value).split()).upper()


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--prepared", required=True)
    ap.add_argument("--jsonl", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--remaining", help="write the still-missing keys to this JSON file")
    args = ap.parse_args()

    try:
        with open(args.prepared, encoding="utf-8") as fh:
            prepared = json.load(fh)
        wanted = {"iban": [norm(v) for v in prepared["to_lookup"]["ibans"]],
                  "bic": [norm(v) for v in prepared["to_lookup"]["bics"]]}
    except (OSError, KeyError, ValueError) as exc:
        print("cannot read prepared file: %s" % exc, file=sys.stderr)
        return 2

    got = {"iban": {}, "bic": {}}
    bad = 0
    try:
        with open(args.jsonl, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                    kind, key, result = rec["kind"], norm(rec["key"]), rec["result"]
                    if kind not in got or not isinstance(result, dict):
                        raise ValueError("bad record")
                except (ValueError, KeyError, TypeError):
                    bad += 1  # truncated final line after an interruption, or a typo
                    continue
                got[kind][key] = result
    except FileNotFoundError:
        pass

    missing = {k: [v for v in wanted[k] if v not in got[k]] for k in wanted}
    unknown = {k: [v for v in got[k] if v not in set(wanted[k])] for k in got}

    out = {"ibans": {k: v for k, v in got["iban"].items() if k in set(wanted["iban"])},
           "bics": {k: v for k, v in got["bic"].items() if k in set(wanted["bic"])}}
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=1, sort_keys=True)
    if args.remaining:
        with open(args.remaining, "w", encoding="utf-8") as fh:
            json.dump(missing, fh, indent=1)

    print("IBANs: %d of %d done, %d remaining" % (len(out["ibans"]), len(wanted["iban"]), len(missing["iban"])))
    print("BICs:  %d of %d done, %d remaining" % (len(out["bics"]), len(wanted["bic"]), len(missing["bic"])))
    if bad:
        print("warning: %d unreadable line(s) skipped; their lookups count as remaining" % bad)
    if any(unknown.values()):
        print("warning: %d record(s) match no requested value and were dropped" %
              sum(len(v) for v in unknown.values()))
    return 0 if not (missing["iban"] or missing["bic"]) else 3


if __name__ == "__main__":
    sys.exit(main())
