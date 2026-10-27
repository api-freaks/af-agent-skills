"""Shared definitions for the payout-details-validator scripts.

Standard library only. Nothing in here calls a network service.
"""
import re

from iban_registry import GENERIC_IBAN, iban_checksum_ok  # noqa: F401

REJECTED = "rejected"
REVIEW = "review"

# code -> (severity, default explanation)
REASONS = {
    "MISSING_FIELD": (REJECTED, "No IBAN, account number or BIC was provided."),
    "IBAN_BAD_FORMAT": (REJECTED, "The IBAN is not in a valid format."),
    "IBAN_BAD_CHECKSUM": (REJECTED, "The IBAN fails the checksum test, so it contains a typo."),
    "IBAN_INVALID": (REJECTED, "The IBAN validation tool reports this IBAN as invalid."),
    "BIC_BAD_FORMAT": (REVIEW, "The BIC/SWIFT code is not in a valid format."),
    "BIC_NOT_FOUND": (REVIEW, "The BIC/SWIFT code was not found in the directory."),
    "COUNTRY_MISMATCH": (REVIEW, "The BIC country does not match the IBAN country."),
    "BANK_MISMATCH": (REVIEW, "The bank implied by the IBAN does not match the BIC."),
    "NON_SEPA": (REVIEW, "The IBAN country is outside SEPA, so a SEPA transfer cannot be used."),
    "DUPLICATE_ROW": (REVIEW, "The same payee and account appear more than once."),
    "DUPLICATE_IBAN": (REVIEW, "The same IBAN is used by more than one payee name."),
    "MULTIPLE_IBANS_PER_PAYEE": (REVIEW, "One payee name appears with more than one IBAN."),
    "IBAN_CHANGED": (REVIEW, "This payee's IBAN differs from the baseline file."),
    "QR_IBAN": (REVIEW, "This is a QR-IBAN. It cannot receive a normal credit transfer."),
    "NOTHING_TO_VERIFY": (REVIEW, "There is no IBAN, so this skill could not verify an account."),
    "ACCOUNT_UNCHECKED": (REVIEW, "No IBAN was given, so the account number was not checked."),
    "LOOKUP_FAILED": (REVIEW, "A lookup failed or returned no result, so this row could not be fully checked."),
}

IBAN_RE = GENERIC_IBAN
BIC_RE = re.compile(r"^[A-Z]{4}[A-Z]{2}[A-Z0-9]{2}([A-Z0-9]{3})?$")
FORMULA_PREFIX = ("=", "+", "-", "@")


def norm_iban(value):
    """Strip spaces, dots and hyphens, then uppercase."""
    return re.sub(r"[\s.\-]+", "", value or "").upper()


def norm_bic(value):
    """Strip spaces and hyphens, then uppercase."""
    return re.sub(r"[\s\-]+", "", value or "").upper()


def norm_name(value):
    """Loose key for comparing payee names: casefolded, punctuation and spaces removed."""
    return re.sub(r"[\W_]+", "", (value or "").casefold())


def mask_iban(iban):
    """Show only the first 4 and last 4 characters (for chat summaries)."""
    if not iban:
        return ""
    if len(iban) <= 8:
        return "*" * len(iban)
    return iban[:4] + "..." + iban[-4:]


def institution_code(value):
    """First four letters of a BIC. A national clearing number (digits) returns empty."""
    if not isinstance(value, str):
        return ""
    compact = re.sub(r"[\s\-]+", "", value).upper()
    if len(compact) >= 4 and compact[:4].isalpha():
        return compact[:4]
    return ""


def excel_safe(value):
    """Prefix a cell Excel would treat as a formula. Returns (text, changed)."""
    if isinstance(value, str) and value[:1] in FORMULA_PREFIX:
        return "'" + value, True
    return value, False
