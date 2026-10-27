#!/usr/bin/env python3
"""Combine local findings and recorded lookup results into clean, review and rejected files.

Usage:
  python scripts/assemble.py --prepared pdv-work/prepared.json --lookups pdv-work/lookups.json \
      --outdir pdv-work [--sepa-run]

Writes <stem>_clean.csv, <stem>_review.csv, <stem>_rejected.csv and <stem>_validation_summary.md.
Original account numbers are not corrected. Cells that start with =, +, - or @ gain a leading
apostrophe so Excel does not run them. No network calls.
"""
import argparse
import csv
import json
import os
import sys
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import (  # noqa: E402
    REASONS, REJECTED, REVIEW, excel_safe, institution_code, mask_iban, norm_bic, norm_iban,
)

ADDED = ["status", "reason_codes", "explanation", "bank_name", "checks_performed", "notes"]

_MISSING = object()


def die(message):
    print(message, file=sys.stderr)
    raise SystemExit(1)


def add(findings, code, detail=None):
    findings.append({"code": code, "detail": detail or REASONS[code][1]})


def validation_reason(validation):
    """Plain sentence from the IBAN tool's per-check flags. bban 'unknown' is not a failure."""
    if not isinstance(validation, dict):
        return None
    parts = []
    labels = (
        ("is_alpha_numeric", "characters are not alphanumeric"),
        ("is_iban_supported_country", "country is not supported"),
        ("is_valid_length", "length is wrong for the country"),
        ("is_valid_structure", "national format is wrong"),
        ("is_iban_check_digit_valid", "checksum is wrong"),
    )
    for key, text in labels:
        if validation.get(key) is False:
            parts.append(text)
    bban = validation.get("bban")
    if isinstance(bban, str) and bban not in ("valid", "unknown", ""):
        parts.append("national checksum is %s" % bban)
    if not parts:
        return None
    return "IBAN validation failed: " + ", ".join(parts) + "."


def interpret_iban(entry):
    """Flatten one IBAN lookup. Missing or non-boolean `valid` is unusable, not a pass."""
    if not isinstance(entry, dict):
        return {"missing": True}
    if entry.get("error"):
        return {"error": str(entry["error"])}
    valid = entry.get("valid", _MISSING)
    if not isinstance(valid, bool):
        return {"missing": True}
    bank = entry.get("bank_data") if isinstance(entry.get("bank_data"), dict) else None
    if bank is not None:
        bank_name = bank.get("bank") or entry.get("bank_name") or ""
        bic = bank.get("bic") if bank.get("bic") is not None else entry.get("bic")
        bank_code = bank.get("bank_code") if "bank_code" in bank else entry.get("bank_code")
        sepa = bank.get("sepa") if "sepa" in bank else entry.get("sepa")
    else:
        bank_name = entry.get("bank_name") or ""
        bic = entry.get("bic")
        bank_code = entry.get("bank_code")
        sepa = entry.get("sepa")
    reason = entry.get("invalid_reason")
    if valid is False and not reason:
        reason = validation_reason(entry.get("validation"))
    return {
        "valid": valid,
        "sepa": sepa if isinstance(sepa, bool) else None,
        "bank_name": bank_name or "",
        "bic": bic if isinstance(bic, str) else "",
        "bank_code": bank_code if isinstance(bank_code, str) else "",
        "invalid_reason": reason or None,
    }


def bic_not_found_text(text):
    """The SWIFT tool raises this text for an unknown code. It is not an outage."""
    return "no bank found" in str(text).lower()


def interpret_bic(entry):
    """Flatten one BIC lookup. A 404-shaped body is not found. Anything else without `found` is unusable."""
    if isinstance(entry, str):
        if bic_not_found_text(entry):
            return {"found": False, "bank_name": "", "note": ""}
        return {"error": entry}
    if not isinstance(entry, dict):
        return {"missing": True}
    if entry.get("error"):
        if bic_not_found_text(entry["error"]):
            return {"found": False, "bank_name": "", "note": entry.get("note") or ""}
        return {"error": str(entry["error"])}
    note = entry.get("note") or ""
    if "found" in entry:
        if entry["found"] is True:
            name = entry.get("bank_name") or entry.get("bankName") or ""
            return {"found": True, "bank_name": name, "note": note}
        if entry["found"] is False:
            return {"found": False, "bank_name": entry.get("bank_name") or "", "note": note}
        return {"missing": True}
    if entry.get("bankName") or entry.get("swiftCode"):
        return {"found": True, "bank_name": entry.get("bankName") or "", "note": note}
    status = entry.get("status", entry.get("status_code", entry.get("http_status")))
    if status == 404 or status == "404":
        return {"found": False, "bank_name": "", "note": note}
    return {"missing": True}


def index_lookups(raw, normalizer, interpret):
    if not isinstance(raw, dict):
        die("lookups.json entries must be objects keyed by the value from to_lookup.")
    indexed = {}
    for key, entry in raw.items():
        if not isinstance(key, str):
            continue
        indexed[normalizer(key)] = interpret(entry)
    return indexed


def locally_rejected(row):
    return any(REASONS[item["code"]][0] == REJECTED for item in row["findings"])


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--prepared", required=True)
    ap.add_argument("--lookups", required=True)
    ap.add_argument("--outdir", default="pdv-work")
    ap.add_argument("--sepa-run", action="store_true",
                    help="Flag IBANs whose country is outside SEPA for review. Use only for a SEPA payment run.")
    args = ap.parse_args(argv)

    with open(args.prepared, encoding="utf-8") as fh:
        prep = json.load(fh)
    with open(args.lookups, encoding="utf-8") as fh:
        lk = json.load(fh)
    if not isinstance(lk, dict):
        die("lookups.json must be an object with ibans and bics.")
    iban_lk = index_lookups(lk.get("ibans") or {}, norm_iban, interpret_iban)
    bic_lk = index_lookups(lk.get("bics") or {}, norm_bic, interpret_bic)

    headers = prep["headers"]
    out_cols = [("validator_" + col if col in headers else col) for col in ADDED]
    stem = os.path.splitext(os.path.basename(prep["source"]))[0]

    buckets = {"clean": [], "review": [], "rejected": []}
    reason_counts = Counter()
    lookup_failures = 0
    non_iban_rows = 0
    formula_cells = 0

    for row in prep["rows"]:
        findings = [dict(item) for item in row["findings"]]
        notes = list(row["notes"])
        checks, bank_name = [], ""
        expect_lookups = not locally_rejected(row)

        if row["iban"]:
            checks.append("iban-checksum" if row.get("iban_format_ok") else "iban-format")
        if row["bic"]:
            checks.append("bic-format")

        if row["iban_ok_local"] and expect_lookups:
            parsed = iban_lk.get(row["iban"])
            if parsed is None or parsed.get("missing"):
                add(findings, "LOOKUP_FAILED", "No usable IBAN lookup result was recorded for this row.")
            elif parsed.get("error"):
                add(findings, "LOOKUP_FAILED", "IBAN lookup failed: %s" % parsed["error"])
            elif parsed.get("valid") is False:
                add(findings, "IBAN_INVALID", parsed.get("invalid_reason") or None)
                checks.append("iban-lookup")
            else:
                checks.append("iban-lookup")
                bank_name = parsed.get("bank_name") or ""
                if parsed.get("sepa") is False and args.sepa_run:
                    add(findings, "NON_SEPA")
                elif parsed.get("sepa") is False:
                    notes.append("IBAN country is outside SEPA.")
                derived = institution_code(parsed.get("bic")) or institution_code(parsed.get("bank_code"))
                supplied = institution_code(row["bic"]) if row["bic_ok_local"] else ""
                if derived and supplied:
                    checks.append("iban-vs-bic")
                    if derived != supplied:
                        add(findings, "BANK_MISMATCH",
                            "The IBAN points to bank code %s but the BIC institution code is %s."
                            % (derived, supplied))

        if row["bic_ok_local"] and expect_lookups:
            parsed = bic_lk.get(row["bic"])
            if parsed is None or parsed.get("missing"):
                add(findings, "LOOKUP_FAILED", "No usable BIC lookup result was recorded for this row.")
            elif parsed.get("error"):
                add(findings, "LOOKUP_FAILED", "BIC lookup failed: %s" % parsed["error"])
            elif parsed.get("found") is False:
                add(findings, "BIC_NOT_FOUND")
                checks.append("bic-lookup")
                if parsed.get("note"):
                    notes.append(parsed["note"])
            else:
                checks.append("bic-lookup")
                bank_name = bank_name or parsed.get("bank_name") or ""

        if not row["iban"] and (row["account"] or row["bic"]):
            non_iban_rows += 1
            if row["account"] and row["bic"]:
                add(findings, "ACCOUNT_UNCHECKED")
            elif row["account"]:
                add(findings, "NOTHING_TO_VERIFY",
                    "Only an account number was given, so there was nothing this skill could verify.")
            elif row["bic"]:
                add(findings, "NOTHING_TO_VERIFY",
                    "A BIC alone is not enough to pay. No account number was checked.")

        if row["iban"] or row["bic"]:
            checks.append("duplicates")

        codes = []
        for item in findings:
            if item["code"] not in codes:
                codes.append(item["code"])
        severities = {REASONS[code][0] for code in codes}
        status = "rejected" if REJECTED in severities else ("review" if REVIEW in severities else "clean")
        if "LOOKUP_FAILED" in codes:
            lookup_failures += 1
        for code in codes:
            reason_counts[code] += 1

        written = {}
        for key, value in row["original"].items():
            safe, changed = excel_safe(value)
            written[key] = safe
            formula_cells += int(changed)
        explanation = " ".join(item["detail"] for item in findings)
        note_text = " ".join(notes)
        extras = [status, ";".join(codes), explanation, bank_name, ",".join(dict.fromkeys(checks)), note_text]
        for col, value in zip(out_cols, extras):
            safe, changed = excel_safe(value)
            written[col] = safe
            formula_cells += int(changed)
        buckets[status].append((written, row))

    os.makedirs(args.outdir, exist_ok=True)
    paths = {}
    for name, items in buckets.items():
        dest = os.path.join(args.outdir, "%s_%s.csv" % (stem, name))
        with open(dest, "w", encoding="utf-8-sig", newline="") as fh:
            writer = csv.DictWriter(fh, fieldnames=headers + out_cols)
            writer.writeheader()
            for written, _row in items:
                writer.writerow(written)
        paths[name] = dest

    total = sum(len(items) for items in buckets.values())
    lines = [
        "# Payout details validation summary", "",
        "Rows checked: %d" % total,
        "Clean: %d | Needs review: %d | Rejected: %d" % (
            len(buckets["clean"]), len(buckets["review"]), len(buckets["rejected"])),
        "SEPA run mode: %s" % ("on" if args.sepa_run else "off"),
        "Lookups: %d IBANs, %d BICs; %d rows with failed or missing lookups" % (
            len(iban_lk), len(bic_lk), lookup_failures),
    ]
    if non_iban_rows:
        lines.append("Rows without an IBAN (not in the clean file): %d" % non_iban_rows)
    if formula_cells:
        lines.append(
            "Cells starting with =, +, - or @ were prefixed with an apostrophe so Excel will not treat them as formulas: %d"
            % formula_cells)
    lines += ["", "## Reasons", ""]
    for code, count in reason_counts.most_common():
        lines.append("- %s: %d row(s). %s" % (code, count, REASONS[code][1]))
    if not reason_counts:
        lines.append("- None")
    examples = [(written[out_cols[1]], row["row"], mask_iban(row["iban"]))
                for written, row in buckets["rejected"][:5]]
    if examples:
        lines += ["", "## Rejected rows (first few, IBANs masked)", ""]
        for codes, rownum, masked in examples:
            lines.append("- Row %s %s: %s" % (rownum, masked, codes))
    lines += ["", "## What this does and does not confirm", "",
              "Clean means the IBAN is well formed and the lookup returned a bank for it. "
              "It does not confirm that the account is open or that it belongs to the named payee. "
              "A row with no IBAN is never clean. "
              "The SEPA flag reports whether the IBAN's country is in SEPA, not whether this account can be paid."]
    summary_path = os.path.join(args.outdir, "%s_validation_summary.md" % stem)
    with open(summary_path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")

    print("\n".join(lines))
    print("\nFiles:")
    for path in list(paths.values()) + [summary_path]:
        print("  " + path)
    return 0


if __name__ == "__main__":
    main()
