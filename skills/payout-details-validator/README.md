# payout-details-validator

Checks a file of payee bank details before a payment run. Local checks cover IBAN length, structure and checksum, BIC format, country pairs, QR-IBANs and duplicates. IBAN and BIC lookups go through the APIFreaks MCP server. Rows split into clean, review and rejected.

## Files

| Path | Purpose |
|---|---|
| `SKILL.md` | Instructions the agent follows |
| `references/lookup-schema.md` | How tool responses map into `lookups.json` |
| `references/reason-codes.md` | Every reason code and what to do about it |
| `scripts/prepare.py` | Reads the file, runs local checks, lists lookups |
| `scripts/merge_lookups.py` | Merges per-call lookup records (`lookups.jsonl`) into `lookups.json` and lists what is still missing, so an interrupted run can resume |
| `scripts/assemble.py` | Joins lookups and writes the three result files |
| `scripts/iban_registry.py` | Country length and structure, SWIFT IBAN Registry release 101 (December 2025) |
| `examples/sample-payouts.csv` | Small file with deliberate errors, including a title row |
| `examples/sample-baseline.csv` | A previous file for `--baseline` |
| `evals/evals.json` | Test prompts with expected behavior |
| `tests/test_scripts.py`, `tests/test_merge_lookups.py` | Offline regression tests |

## Requirements

- APIFreaks MCP server with the `financial` module enabled, and an `APIFREAKS_API_KEY`
- Python 3.9 or newer, standard library only
- `openpyxl` to read `.xlsx` (`pip install openpyxl`). CSV needs nothing extra

## Try the scripts

```
python scripts/prepare.py examples/sample-payouts.csv --outdir work/
python scripts/prepare.py examples/sample-payouts.csv --baseline examples/sample-baseline.csv --outdir work/
```

Prepare does not call the network. Without a `lookups.json` from the MCP tools, assemble will mark every looked-up row `LOOKUP_FAILED`. That is the point of the offline tests: they feed recorded results, including the shapes the live tools return.

The sample uses published example IBANs (the German Commerzbank example, the UK NatWest example, and others from the IBAN registry). It is not a real payment file.

`tests/test_scripts.py` needs no network. Excel cases need `openpyxl` and are skipped when it is missing.

## Lookup records and resuming

The agent appends one line per MCP call to `lookups.jsonl`, then runs:

```
python scripts/merge_lookups.py --prepared work/prepared.json --jsonl work/lookups.jsonl --out work/lookups.json --remaining work/remaining.json
```

Exit code 3 means lookups remain, 0 means done. The last record for a key wins, so a retry just appends. A truncated final line is skipped and its lookup counts as remaining.

## Notes

- The working directory holds full account numbers. Keep it outside any git repository and delete it when the run is finished.

- Clean means the IBAN passed and the lookup returned a bank. It does not mean the account is open or belongs to the payee. A row with no IBAN is never clean.
- `bank_data.sepa` is whether the IBAN's country is in SEPA. `--sepa-run` is the only mode that sends a non-SEPA country to review.
- Prices are read at run time from https://apifreaks.com/llms-full.txt. The tools return no cost field, so spend is unverified.
- Cells that start with `=`, `+`, `-` or `@` get a leading apostrophe in the output CSV so Excel will not treat them as formulas.
