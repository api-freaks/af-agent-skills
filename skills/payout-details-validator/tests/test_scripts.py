"""Regression tests for the payout-details-validator scripts. No network."""

import csv
import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))
import assemble  # noqa: E402
import prepare  # noqa: E402
from iban_registry import SPECS, assess_iban, typo_hint, with_checksum  # noqa: E402

ROOT = os.path.join(os.path.dirname(__file__), "..")
SAMPLE = os.path.join(ROOT, "examples", "sample-payouts.csv")
BASELINE = os.path.join(ROOT, "examples", "sample-baseline.csv")

PUBLISHED = {
    "AE": "AE070331234567890123456",
    "AT": "AT611904300234573201",
    "BE": "BE68539007547034",
    "BR": "BR1800360305000010009795493C1",
    "CH": "CH9300762011623852957",
    "CZ": "CZ6508000000192000145399",
    "DE": "DE89370400440532013000",
    "DK": "DK5000400440116243",
    "EG": "EG380019000500000000263180002",
    "ES": "ES9121000418450200051332",
    "FI": "FI2112345600000785",
    "FR": "FR1420041010050500013M02606",
    "GB": "GB29NWBK60161331926819",
    "GR": "GR1601101250000000012300695",
    "HU": "HU42117730161111101800000000",
    "IE": "IE29AIBK93115212345678",
    "IT": "IT60X0542811101000000123456",
    "LI": "LI21088100002324013AA",
    "LC": "LC55HEMM000100010012001200023015",
    "LU": "LU280019400644750000",
    "MT": "MT84MALT011000012345MTLCAST001S",
    "MU": "MU17BOMM0101101030300200000MUR",
    "NL": "NL91ABNA0417164300",
    "NO": "NO9386011117947",
    "PL": "PL61109010140000071219812874",
    "PT": "PT50000201231234567890154",
    "QA": "QA58DOHB00001234567890ABCDEFG",
    "SA": "SA0380000000608010167519",
    "SC": "SC18SSCB11010000000000001497USD",
    "SE": "SE4550000000058398257466",
    "TR": "TR330006100519786457841326",
    "UA": "UA213223130000026007233566001",
    "VA": "VA59001123000012345678",
    "XK": "XK051212012345678906",
}

DE = PUBLISHED["DE"]
GB = PUBLISHED["GB"]


def codes_of(row):
    return [item["code"] for item in row["findings"]]


def row_by_payee(prep, payee):
    found = [row for row in prep["rows"] if row["payee"] == payee]
    if len(found) != 1:
        raise AssertionError("%s matched %d rows" % (payee, len(found)))
    return found[0]


class Workspace:
    def __init__(self):
        self.tmp = tempfile.TemporaryDirectory()

    def close(self):
        self.tmp.cleanup()

    def path(self, name):
        return os.path.join(self.tmp.name, name)

    def write(self, name, text, binary=None):
        dest = self.path(name)
        if binary is not None:
            with open(dest, "wb") as fh:
                fh.write(binary)
        else:
            with open(dest, "w", encoding="utf-8", newline="") as fh:
                fh.write(text)
        return dest

    def prepare(self, source, extra=None):
        out = self.path("work-" + os.path.basename(source))
        argv = [source, "--outdir", out] + (extra or [])
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = prepare.main(argv)
        with open(os.path.join(out, "prepared.json"), encoding="utf-8") as fh:
            prep = json.load(fh)
        return code, prep, stdout.getvalue(), stderr.getvalue(), out

    def prepare_text(self, text, name="payouts.csv", extra=None, binary=None):
        source = self.write(name, text, binary=binary)
        return self.prepare(source, extra)

    def assemble(self, prepared_dir, lookups, extra=None):
        lookup_path = self.path("lookups-%s.json" % os.path.basename(prepared_dir))
        with open(lookup_path, "w", encoding="utf-8") as fh:
            json.dump(lookups, fh)
        argv = [
            "--prepared", os.path.join(prepared_dir, "prepared.json"),
            "--lookups", lookup_path,
            "--outdir", prepared_dir,
        ] + (extra or [])
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = assemble.main(argv)
        return code, stdout.getvalue(), stderr.getvalue()

    def read_bucket(self, prepared_dir, stem, status):
        path = os.path.join(prepared_dir, "%s_%s.csv" % (stem, status))
        with open(path, encoding="utf-8-sig", newline="") as fh:
            return list(csv.DictReader(fh))


def fails(argv_func, argv):
    stdout, stderr = io.StringIO(), io.StringIO()
    with redirect_stdout(stdout), redirect_stderr(stderr):
        try:
            argv_func(argv)
        except SystemExit as exc:
            return exc.code, stdout.getvalue(), stderr.getvalue()
    raise AssertionError("expected SystemExit")


class RegistryTests(unittest.TestCase):
    def test_published_examples_pass(self):
        for country, iban in PUBLISHED.items():
            result = assess_iban(iban)
            self.assertTrue(result["checksum_ok"], iban)
            self.assertEqual(iban[:2], country)
            self.assertFalse(result["qr"])

    def test_every_country_spec_round_trips(self):
        for country, (_length, spec) in SPECS.items():
            parts = []
            for count, kind in __import__("re").findall(r"(\d+)!([nac])", spec):
                parts.append({"n": "1", "a": "A", "c": "C"}[kind] * int(count))
            iban = with_checksum(country, "".join(parts))
            result = assess_iban(iban)
            self.assertTrue(result["checksum_ok"], iban)
            self.assertEqual(len(iban), _length)

    def test_wrong_length_names_the_country(self):
        result = assess_iban("DE893704004405320130")
        self.assertFalse(result["format_ok"])
        self.assertIn("DE IBANs are 22 characters", result["detail"])
        self.assertIn("20", result["detail"])

    def test_unknown_country_with_checksum_is_not_rejected(self):
        iban = with_checksum("ZZ", "1234567890123")
        result = assess_iban(iban)
        self.assertFalse(result["known_country"])
        self.assertTrue(result["checksum_ok"])

    def test_qr_range(self):
        self.assertTrue(assess_iban("CH5730000123456789012")["qr"])
        self.assertFalse(assess_iban(PUBLISHED["CH"])["qr"])

    def test_typo_hint_is_unique_and_does_not_cross_countries(self):
        self.assertEqual(typo_hint("DE8937O400440532013000"), DE)
        self.assertEqual(typo_hint("DE98370400440532013000"), DE)
        self.assertIsNone(typo_hint(DE))


class PrepareTests(unittest.TestCase):
    def setUp(self):
        self.ws = Workspace()

    def tearDown(self):
        self.ws.close()

    def test_sample_local_findings(self):
        _code, prep, stdout, _err, _out = self.ws.prepare(SAMPLE)
        self.assertEqual(len(prep["rows"]), 17)
        self.assertIn("payee -> Payee", stdout)
        self.assertNotIn(DE, stdout)
        self.assertIn("DE89...3000", stdout)

        acme = row_by_payee(prep, "Acme GmbH")
        self.assertEqual(acme["iban"], DE)
        self.assertEqual(codes_of(acme), [])
        self.assertIn("original value is unchanged", " ".join(acme["notes"]))
        self.assertEqual(acme["original"]["IBAN"], "DE89 3704 0044 0532 0130 00")

        typo = row_by_payee(prep, "Typo Co")
        self.assertEqual(codes_of(typo), ["IBAN_BAD_CHECKSUM"])
        self.assertTrue(typo["iban_format_ok"])
        self.assertIn(DE, " ".join(typo["notes"]))
        self.assertNotIn(typo["iban"], prep["to_lookup"]["ibans"])

        short = row_by_payee(prep, "Short GmbH")
        self.assertEqual(codes_of(short), ["IBAN_BAD_FORMAT"])
        self.assertIn("22 characters", short["findings"][0]["detail"])
        self.assertFalse(short["iban_format_ok"])

        self.assertEqual(codes_of(row_by_payee(prep, "Alpha Shared")), ["DUPLICATE_IBAN"])
        self.assertEqual(codes_of(row_by_payee(prep, "Beta Shared")), ["DUPLICATE_IBAN"])
        two = [row for row in prep["rows"] if row["payee"] == "Two Banks Ltd"]
        self.assertTrue(all("MULTIPLE_IBANS_PER_PAYEE" in codes_of(row) for row in two))
        repeats = [row for row in prep["rows"] if row["payee"] == "Repeat SA"]
        self.assertTrue(all("DUPLICATE_ROW" in codes_of(row) for row in repeats))
        self.assertTrue(all("DUPLICATE_IBAN" not in codes_of(row) for row in repeats))

        paper = row_by_payee(prep, "Martinique Paper")
        self.assertNotIn("COUNTRY_MISMATCH", codes_of(paper))
        self.assertIn("not a country mismatch", " ".join(paper["notes"]))

        wrong = row_by_payee(prep, "Wrong Country")
        self.assertIn("COUNTRY_MISMATCH", codes_of(wrong))
        self.assertIn("QR_IBAN", codes_of(row_by_payee(prep, "Swiss QR Bills")))
        self.assertEqual(codes_of(row_by_payee(prep, "No Details")), ["MISSING_FIELD"])
        self.assertIn("BIC_BAD_FORMAT", codes_of(row_by_payee(prep, "Messy BIC")))
        self.assertNotIn("NOTABIC", prep["to_lookup"]["bics"])
        self.assertIn(DE, prep["to_lookup"]["ibans"])
        self.assertIn(PUBLISHED["CH"], prep["to_lookup"]["ibans"])

    def test_baseline_matches_the_normalized_name_only(self):
        text = "Payee,IBAN\nAcme GmbH,%s\nAcme Limited,%s\n,%s\n" % (DE, GB, GB)
        _code, prep, stdout, _err, _out = self.ws.prepare_text(
            text, extra=["--baseline", BASELINE])
        self.assertIn("IBAN_CHANGED", codes_of(row_by_payee(prep, "Acme GmbH")))
        self.assertNotIn("IBAN_CHANGED", codes_of(row_by_payee(prep, "Acme Limited")))
        blank = [row for row in prep["rows"] if row["payee"] == ""]
        self.assertNotIn("IBAN_CHANGED", codes_of(blank[0]))
        self.assertIn("Baseline IBAN changes: 1", stdout)

    def test_specific_header_beats_name_and_account(self):
        text = "Name,Vendor,Account,Account Number,IBAN\nBob,Acme GmbH,holder,12345,%s\n" % DE
        _code, prep, _out, _err, _dir = self.ws.prepare_text(text)
        self.assertEqual(prep["columns"]["payee"], "Vendor")
        self.assertEqual(prep["columns"]["account"], "Account Number")
        self.assertEqual(prep["columns"]["iban"], "IBAN")
        self.assertEqual(prep["rows"][0]["payee"], "Acme GmbH")

    def test_values_promote_an_account_column_full_of_ibans(self):
        text = "Payee,Account\nAcme GmbH,%s\n" % DE
        _code, prep, stdout, _err, _dir = self.ws.prepare_text(text)
        self.assertEqual(prep["columns"]["iban"], "Account")
        self.assertNotIn("account", prep["columns"])
        self.assertIn("IBAN column taken from values", stdout)

    def test_title_row_is_not_the_header(self):
        text = "Payment run March\nPayee,IBAN\nAcme GmbH,%s\n" % DE
        _code, prep, _out, _err, _dir = self.ws.prepare_text(text)
        self.assertEqual(len(prep["rows"]), 1)
        self.assertEqual(prep["rows"][0]["row"], 3)
        self.assertEqual(prep["rows"][0]["iban"], DE)

    def test_headerless_file_is_rejected(self):
        text = "%s,Acme GmbH\n" % DE
        source = self.ws.write("bare.csv", text)
        code, _stdout, stderr = fails(prepare.main, [source, "--outdir", self.ws.path("nope")])
        self.assertEqual(code, 1)
        self.assertIn("no header row", stderr)

    def test_utf16_and_sep_line_and_cp1252(self):
        body = "Payee,IBAN\nAcme GmbH,%s\n" % DE
        _code, prep, _out, _err, _dir = self.ws.prepare_text(
            "", name="wide.csv", binary=body.encode("utf-16"))
        self.assertEqual(prep["rows"][0]["iban"], DE)

        semi = "sep=;\nPayee;IBAN\nAcme GmbH;%s\n" % DE
        _code, prep, _out, _err, _dir = self.ws.prepare_text(semi, name="semi.csv")
        self.assertEqual(prep["rows"][0]["row"], 3)
        self.assertEqual(prep["rows"][0]["iban"], DE)

        latin = "Payee,IBAN\nJosé,%s\n" % DE
        _code, prep, _out, _err, _dir = self.ws.prepare_text(
            "", name="latin.csv", binary=latin.encode("cp1252"))
        self.assertEqual(prep["rows"][0]["payee"], "José")

    def test_dots_are_removed_and_original_kept(self):
        dotted = "DE89.3704.0044.0532.0130.00"
        _code, prep, _out, _err, _dir = self.ws.prepare_text(
            "Payee,IBAN\nAcme,%s\n" % dotted)
        self.assertEqual(prep["rows"][0]["iban"], DE)
        self.assertEqual(prep["rows"][0]["original"]["IBAN"], dotted)

    def test_unknown_country_is_looked_up_and_a_bad_checksum_is_not(self):
        good = with_checksum("ZZ", "1234567890123")
        bad = good[:-1] + ("0" if good[-1] != "0" else "1")
        text = "Payee,IBAN\nNewland,%s\nBroken,%s\n" % (good, bad)
        _code, prep, _out, _err, _dir = self.ws.prepare_text(text)
        self.assertIn(good, prep["to_lookup"]["ibans"])
        self.assertNotIn(bad, prep["to_lookup"]["ibans"])
        self.assertIn("IBAN_BAD_CHECKSUM", codes_of(row_by_payee(prep, "Broken")))

    def test_xls_is_rejected_clearly(self):
        source = self.ws.write("old.xls", "", binary=b"not a workbook")
        code, _stdout, stderr = fails(prepare.main, [source, "--outdir", self.ws.path("nope")])
        self.assertEqual(code, 1)
        self.assertIn(".xlsx", stderr)

    def test_channel_islands_bic_is_a_note(self):
        text = "Payee,IBAN,BIC\nJersey Co,%s,BOFIJE2X\n" % GB
        _code, prep, _out, _err, _dir = self.ws.prepare_text(text)
        self.assertNotIn("COUNTRY_MISMATCH", codes_of(prep["rows"][0]))
        self.assertIn("GB IBANs", " ".join(prep["rows"][0]["notes"]))


class AssembleTests(unittest.TestCase):
    def setUp(self):
        self.ws = Workspace()

    def tearDown(self):
        self.ws.close()

    def pipeline(self, text, lookups, prepare_extra=None, assemble_extra=None, name="payouts.csv"):
        _code, prep, _stdout, _err, out = self.ws.prepare_text(text, name=name, extra=prepare_extra)
        self.ws.assemble(out, lookups, assemble_extra)
        stem = os.path.splitext(name)[0]
        buckets = {status: self.ws.read_bucket(out, stem, status) for status in ("clean", "review", "rejected")}
        summary = os.path.join(out, stem + "_validation_summary.md")
        with open(summary, encoding="utf-8") as fh:
            text_summary = fh.read()
        return prep, buckets, text_summary

    def test_sample_with_matching_lookups(self):
        _code, prep, _stdout, _err, out = self.ws.prepare(SAMPLE)
        lookups = {"ibans": {}, "bics": {}}
        for iban in prep["to_lookup"]["ibans"]:
            inst = ""
            for row in prep["rows"]:
                if row["iban"] == iban and row["bic_ok_local"]:
                    inst = row["bic"][:4]
                    break
            lookups["ibans"][iban] = {
                "valid": True, "sepa": True, "bank_name": "Example Bank",
                "bic": (inst + "XXXX")[:8] if inst else None, "error": None,
            }
        for bic in prep["to_lookup"]["bics"]:
            lookups["bics"][bic] = {"found": True, "bank_name": "Example Bank", "error": None}
        self.ws.assemble(out, lookups)
        clean = self.ws.read_bucket(out, "sample-payouts", "clean")
        review = self.ws.read_bucket(out, "sample-payouts", "review")
        rejected = self.ws.read_bucket(out, "sample-payouts", "rejected")
        self.assertEqual({row["Payee"] for row in clean}, {"Acme GmbH", "Northwind Ltd", "Martinique Paper"})
        self.assertEqual({row["Payee"] for row in rejected}, {"Typo Co", "Short GmbH", "No Details"})
        self.assertEqual(len(review), 11)
        by_payee = {row["Payee"]: row for row in rejected}
        self.assertIn("iban-checksum", by_payee["Typo Co"]["checks_performed"])
        self.assertIn("iban-format", by_payee["Short GmbH"]["checks_performed"])
        self.assertEqual(by_payee["Typo Co"]["IBAN"], "DE98370400440532013000")
        with open(os.path.join(out, "sample-payouts_validation_summary.md"), encoding="utf-8") as fh:
            summary = fh.read()
        self.assertNotIn("DE98370400440532013000", summary)
        self.assertIn("DE98...3000", summary)
        globex = next(row for row in review if row["Payee"] == "Globex US")
        self.assertEqual(globex["status"], "review")
        self.assertIn("ACCOUNT_UNCHECKED", globex["reason_codes"])
        petty = next(row for row in review if row["Payee"] == "Petty Cash")
        self.assertIn("NOTHING_TO_VERIFY", petty["reason_codes"])

    def test_raw_tool_body_and_fail_closed(self):
        text = "Payee,IBAN,BIC\nAcme,%s,COBADEFFXXX\nBlank,%s,COBADEFF\n" % (DE, GB)
        raw = {
            "valid": True,
            "validation": {"bban": "unknown", "is_valid_length": True},
            "bank_data": {
                "bic": "COBADEFFXXX",
                "bank": "COMMERZBANK AG",
                "bank_code": "37040044",
                "sepa": True,
            },
        }
        prep, buckets, _summary = self.pipeline(text, {"ibans": {DE: raw, GB: {"bank_name": "Guess"}}, "bics": {
            "COBADEFFXXX": {"swiftCode": "COBADEFFXXX", "bankName": "COMMERZBANK AG"},
            "COBADEFF": {"found": True, "bank_name": "COMMERZBANK"},
        }})
        self.assertEqual(len(buckets["clean"]), 1)
        self.assertEqual(buckets["clean"][0]["bank_name"], "COMMERZBANK AG")
        self.assertIn("iban-vs-bic", buckets["clean"][0]["checks_performed"])
        self.assertNotIn("BANK_MISMATCH", buckets["clean"][0]["reason_codes"])
        self.assertEqual(buckets["review"][0]["Payee"], "Blank")
        self.assertIn("LOOKUP_FAILED", buckets["review"][0]["reason_codes"])

    def test_spaced_key_branch_difference_and_digit_bank_code(self):
        text = "Payee,IBAN,BIC\nNorthwind,%s,NWBKGB2L\n" % GB
        lookups = {"ibans": {"GB29 NWBK 6016 1331 9268 19": {
            "valid": True,
            "sepa": True,
            "bank_name": "NATIONAL WESTMINSTER BANK PLC",
            "bic": "NWBKGB2104T",
            "bank_code": "601613",
        }}, "bics": {"NWBKGB2L": {"found": True, "bank_name": "NATIONAL WESTMINSTER BANK PLC"}}}
        _prep, buckets, _summary = self.pipeline(text, lookups)
        self.assertEqual(len(buckets["clean"]), 1)
        self.assertNotIn("BANK_MISMATCH", buckets["clean"][0]["reason_codes"])

    def test_bank_mismatch_and_invalid_iban_keeps_bic_result(self):
        text = "Payee,IBAN,BIC\nAcme,%s,COBADEFF\n" % DE
        lookups = {
            "ibans": {DE: {
                "valid": False,
                "validation": {"is_valid_structure": False, "bban": "unknown"},
                "bank_data": {"bic": None, "bank": None, "sepa": False},
            }},
            "bics": {"COBADEFF": {"status": 404, "note": "Primary office was not checked."}},
        }
        _prep, buckets, _summary = self.pipeline(text, lookups)
        row = buckets["rejected"][0]
        self.assertIn("IBAN_INVALID", row["reason_codes"])
        self.assertIn("national format is wrong", row["explanation"])
        self.assertIn("BIC_NOT_FOUND", row["reason_codes"])
        self.assertIn("Primary office", row["notes"])

    def test_string_valid_is_not_a_pass(self):
        text = "Payee,IBAN\nAcme,%s\n" % DE
        _prep, buckets, _summary = self.pipeline(text, {"ibans": {DE: {"valid": "true", "bank_name": "Nope"}}, "bics": {}})
        self.assertIn("LOOKUP_FAILED", buckets["review"][0]["reason_codes"])

    def test_sepa_is_a_country_note_unless_the_run_is_sepa(self):
        other = PUBLISHED["AE"]
        text = "Payee,IBAN\nGulf,%s\n" % other
        lookups = {"ibans": {other: {"valid": True, "sepa": False, "bank_name": "Example", "bic": None}}, "bics": {}}
        _prep, buckets, summary = self.pipeline(text, lookups)
        self.assertEqual(len(buckets["clean"]), 1)
        self.assertIn("outside SEPA", buckets["clean"][0]["notes"])
        self.assertNotIn("NON_SEPA", buckets["clean"][0]["reason_codes"])
        _prep, buckets, summary = self.pipeline(text, lookups, assemble_extra=["--sepa-run"], name="sepa.csv")
        self.assertIn("NON_SEPA", buckets["review"][0]["reason_codes"])
        self.assertIn("country is outside SEPA", buckets["review"][0]["explanation"])
        self.assertIn("SEPA run mode: on", summary)

    def test_bank_mismatch_uses_institution_letters_only(self):
        text = "Payee,IBAN,BIC\nAcme,%s,NWBKGB2L\n" % DE
        lookups = {"ibans": {DE: {"valid": True, "sepa": True, "bank_name": "Commerzbank", "bic": "COBADEFF", "bank_code": "37040044"}},
                   "bics": {"NWBKGB2L": {"found": True, "bank_name": "NatWest"}}}
        _prep, buckets, _summary = self.pipeline(text, lookups)
        self.assertIn("BANK_MISMATCH", buckets["review"][0]["reason_codes"])
        self.assertIn("COBA", buckets["review"][0]["explanation"])
        self.assertIn("NWBK", buckets["review"][0]["explanation"])

    def test_bic_only_and_account_only_stay_out_of_clean(self):
        text = "Payee,IBAN,BIC,Account\nWire,,CHASUS33,123\nCode only,,CHASUS33,\nCash,,,9988\n"
        lookups = {"ibans": {}, "bics": {"CHASUS33": {"found": True, "bank_name": "JPMORGAN"}}}
        _prep, buckets, summary = self.pipeline(text, lookups)
        self.assertEqual(buckets["clean"], [])
        by_payee = {row["Payee"]: row for row in buckets["review"]}
        self.assertIn("ACCOUNT_UNCHECKED", by_payee["Wire"]["reason_codes"])
        self.assertIn("NOTHING_TO_VERIFY", by_payee["Code only"]["reason_codes"])
        self.assertIn("NOTHING_TO_VERIFY", by_payee["Cash"]["reason_codes"])
        self.assertIn("not in the clean file", summary)

    def test_formula_cells_are_prefixed_and_the_iban_is_not_rewritten(self):
        text = 'Payee,IBAN\n"=cmd|calc",%s\n' % DE
        lookups = {"ibans": {DE: {"valid": True, "sepa": True, "bank_name": "Commerzbank", "bic": "COBADEFF"}}, "bics": {}}
        _prep, buckets, summary = self.pipeline(text, lookups)
        self.assertEqual(buckets["clean"][0]["Payee"], "'=cmd|calc")
        self.assertEqual(buckets["clean"][0]["IBAN"], DE)
        self.assertIn("apostrophe", summary)

    def test_swift_404_text_is_not_found_and_bban_invalid_does_not_override_valid(self):
        text = "Payee,IBAN,BIC\nParis,%s,BNPAFRPP\nGhost,%s,ZZZZDEFF\n" % (PUBLISHED["FR"], DE)
        lookups = {
            "ibans": {
                PUBLISHED["FR"]: {
                    "valid": True,
                    "validation": {
                        "is_valid_structure": True,
                        "is_iban_check_digit_valid": True,
                        "bban": "invalid",
                    },
                    "bank_data": {"bank": None, "bic": None, "sepa": True},
                },
                DE: {"valid": True, "sepa": True, "bank_name": "Commerzbank", "bic": "ZZZZDEFF"},
            },
            "bics": {
                "BNPAFRPP": {"found": True, "bank_name": "BNP"},
                "ZZZZDEFF": {"error": '[404] {"message":"No bank found with the provided SWIFT code"}'},
            },
        }
        _prep, buckets, _summary = self.pipeline(text, lookups)
        self.assertEqual(buckets["clean"][0]["Payee"], "Paris")
        self.assertNotIn("invalid", buckets["clean"][0]["explanation"])
        self.assertIn("BIC_NOT_FOUND", buckets["review"][0]["reason_codes"])
        self.assertNotIn("LOOKUP_FAILED", buckets["review"][0]["reason_codes"])

    def test_lookup_error_is_not_invalid(self):
        text = "Payee,IBAN\nAcme,%s\n" % DE
        _prep, buckets, _summary = self.pipeline(
            text, {"ibans": {DE: {"error": "timeout"}}, "bics": {}})
        self.assertIn("LOOKUP_FAILED", buckets["review"][0]["reason_codes"])
        self.assertNotIn("IBAN_INVALID", buckets["review"][0]["reason_codes"])

    def test_every_reason_code_is_produced(self):
        changed = "DE70500105171234567890"
        rows = [
            "Payee,IBAN,BIC,Account",
            "Missing,,,",
            "Short,DE893704004405320130,,",
            "Typo,DE98370400440532013000,COBADEFF,",
            "Invalid,%s,COBADEFF," % DE,
            "Messy,%s,NOTABIC," % GB,
            "Lost,%s,NWBKGB2L," % GB,
            "Abroad,%s,COBADEFF," % PUBLISHED["CH"],
            "Mismatch,%s,NWBKGB2L," % DE,
            "Gulf,%s,," % PUBLISHED["AE"],
            "Alpha,%s,ABNANL2A," % PUBLISHED["NL"],
            "Beta,%s,ABNANL2A," % PUBLISHED["NL"],
            "Two,%s,GEBABEBB," % PUBLISHED["BE"],
            "Two,%s,BKAUATWW," % PUBLISHED["AT"],
            "Same,%s,DNBANOKK," % PUBLISHED["NO"],
            "Same,%s,DNBANOKK," % PUBLISHED["NO"],
            "Moved,%s,COBADEFF," % DE,
            "QR,CH5730000123456789012,RAIFCH22,",
            "Wire,,CHASUS33,123",
            "Cash,,,9988",
            "Unchecked,%s,," % changed,
        ]
        baseline = self.ws.write("base.csv", "Payee,IBAN\nMoved,%s\n" % changed)
        lookups = {
            "ibans": {
                DE: {"valid": False, "invalid_reason": "structure"},
                GB: {"missing": True},
                PUBLISHED["CH"]: {"valid": True, "sepa": True, "bic": "COBADEFF", "bank_name": "X"},
                PUBLISHED["AE"]: {"valid": True, "sepa": False, "bank_name": "Gulf Bank"},
                PUBLISHED["NL"]: {"valid": True, "sepa": True, "bic": "ABNANL2A", "bank_name": "ABN"},
                PUBLISHED["BE"]: {"valid": True, "sepa": True, "bic": "GEBABEBB", "bank_name": "BNP"},
                PUBLISHED["AT"]: {"valid": True, "sepa": True, "bic": "BKAUATWW", "bank_name": "Bank Austria"},
                PUBLISHED["NO"]: {"valid": True, "sepa": False, "bic": "DNBANOKK", "bank_name": "DNB"},
                "CH5730000123456789012": {"valid": True, "sepa": True, "bic": "RAIFCH22", "bank_name": "QR"},
                changed: {"error": "timeout"},
            },
            "bics": {
                "COBADEFF": {"found": False},
                "NWBKGB2L": {"found": False, "note": "Primary office NWBKGB2L is listed."},
                "ABNANL2A": {"found": True, "bank_name": "ABN"},
                "GEBABEBB": {"found": True, "bank_name": "BNP"},
                "BKAUATWW": {"found": True, "bank_name": "Bank Austria"},
                "DNBANOKK": {"found": True, "bank_name": "DNB"},
                "RAIFCH22": {"found": True, "bank_name": "Raiffeisen"},
                "CHASUS33": {"found": True, "bank_name": "JPMorgan"},
            },
        }
        # Lost's IBAN lookup is omitted on purpose (GB is stored as unusable above).
        # Mismatch needs a valid DE lookup, so give Moved and Mismatch different treatment:
        # DE is used by Invalid (valid false) and Mismatch (needs valid + different bank).
        # Split them: Invalid uses DE with valid false, Mismatch cannot share it.
        # Use the baseline IBAN for mismatch instead and a fresh valid lookup.
        text = "\n".join(rows) + "\n"
        prep, buckets, _summary = self.pipeline(
            text, lookups, prepare_extra=["--baseline", baseline], assemble_extra=["--sepa-run"])
        seen = set()
        for status in buckets.values():
            for row in status:
                seen.update(code for code in row["reason_codes"].split(";") if code)
        expected = {
            "MISSING_FIELD", "IBAN_BAD_FORMAT", "IBAN_BAD_CHECKSUM", "IBAN_INVALID",
            "BIC_BAD_FORMAT", "BIC_NOT_FOUND", "COUNTRY_MISMATCH", "NON_SEPA",
            "DUPLICATE_ROW", "DUPLICATE_IBAN", "MULTIPLE_IBANS_PER_PAYEE",
            "IBAN_CHANGED", "QR_IBAN", "NOTHING_TO_VERIFY", "ACCOUNT_UNCHECKED",
            "LOOKUP_FAILED",
        }
        self.assertTrue(expected <= seen, expected - seen)
        # Bank mismatch needs its own valid lookup with a different institution.
        mismatch_text = "Payee,IBAN,BIC\nMismatch,%s,NWBKGB2L\n" % DE
        _prep, mismatch_buckets, _summary = self.pipeline(
            mismatch_text,
            {"ibans": {DE: {"valid": True, "sepa": True, "bic": "COBADEFF", "bank_name": "Commerzbank"}},
             "bics": {"NWBKGB2L": {"found": True, "bank_name": "NatWest"}}},
            name="mismatch.csv")
        self.assertIn("BANK_MISMATCH", mismatch_buckets["review"][0]["reason_codes"])


class ExcelTests(unittest.TestCase):
    def setUp(self):
        try:
            import openpyxl
        except ImportError:
            self.skipTest("openpyxl is not installed")
        self.openpyxl = openpyxl
        self.ws = Workspace()

    def tearDown(self):
        self.ws.close()

    def test_numeric_account_and_sheet_names(self):
        book = self.openpyxl.Workbook()
        sheet = book.active
        sheet.title = "Vendors"
        book.create_sheet("Other")
        sheet.append(["Payee", "IBAN", "Account"])
        sheet.append(["Acme GmbH", DE, 12345])
        dest = self.ws.path("book.xlsx")
        book.save(dest)
        _code, prep, stdout, _err, _out = self.ws.prepare(dest)
        self.assertIn("Sheet: Vendors", stdout)
        self.assertEqual(prep["rows"][0]["account"], "12345")
        self.assertIn("stored as a number", " ".join(prep["rows"][0]["notes"]))
        code, _stdout, stderr = fails(
            prepare.main, [dest, "--sheet", "Missing", "--outdir", self.ws.path("bad")])
        self.assertEqual(code, 1)
        self.assertIn("Vendors", stderr)
        self.assertIn("Other", stderr)


if __name__ == "__main__":
    unittest.main()
