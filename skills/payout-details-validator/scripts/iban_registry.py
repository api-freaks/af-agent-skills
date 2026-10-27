"""Country length and BBAN structure for local IBAN checks.

SWIFT IBAN Registry release 101 (December 2025). A country that is not in
this table is not rejected here: a checksum that passes still goes to lookup,
so a registry newer than this file is not failed offline.

French territories and the Crown Dependencies are not IBAN prefixes. Their
BICs sit next to an FR or GB IBAN. See TERRITORY_BIC.
"""
import re

# country -> (iban length, BBAN spec). n digit, a letter, c alphanumeric.
SPECS = {
    "AD": (24, "4!n4!n12!c"),
    "AE": (23, "3!n16!n"),
    "AL": (28, "8!n16!c"),
    "AT": (20, "5!n11!n"),
    "AZ": (28, "4!a20!c"),
    "BA": (20, "3!n3!n8!n2!n"),
    "BE": (16, "3!n7!n2!n"),
    "BG": (22, "4!a4!n2!n8!c"),
    "BH": (22, "4!a14!c"),
    "BI": (27, "5!n5!n11!n2!n"),
    "BR": (29, "8!c5!n10!n1!c1!c"),
    "BY": (28, "4!c4!n16!c"),
    "CH": (21, "5!n12!c"),
    "CR": (22, "4!n14!n"),
    "CY": (28, "3!n5!n16!c"),
    "CZ": (24, "4!n16!n"),
    "DE": (22, "8!n10!n"),
    "DJ": (27, "5!n5!n11!n2!n"),
    "DK": (18, "4!n9!n1!n"),
    "DO": (28, "4!c20!n"),
    "EE": (20, "2!n14!n"),
    "EG": (29, "4!n4!n17!n"),
    "ES": (24, "4!n4!n1!n1!n10!n"),
    "FI": (18, "3!n11!n"),
    "FK": (18, "2!a12!n"),
    "FO": (18, "4!n9!n1!n"),
    "FR": (27, "5!n5!n11!c2!n"),
    "GB": (22, "4!a6!n8!n"),
    "GE": (22, "2!a16!n"),
    "GI": (23, "4!a15!c"),
    "GL": (18, "4!n9!n1!n"),
    "GR": (27, "3!n4!n16!c"),
    "GT": (28, "4!c20!c"),
    "HN": (28, "4!a20!n"),
    "HR": (21, "7!n10!n"),
    "HU": (28, "3!n4!n1!n15!n1!n"),
    "IE": (22, "4!a6!n8!n"),
    "IL": (23, "3!n3!n13!n"),
    "IQ": (23, "4!a3!n12!n"),
    "IS": (26, "4!n2!n6!n10!n"),
    "IT": (27, "1!a5!n5!n12!c"),
    "JO": (30, "4!a4!n18!c"),
    "KW": (30, "4!a22!c"),
    "KZ": (20, "3!n13!c"),
    "LB": (28, "4!n20!c"),
    "LC": (32, "4!a24!c"),
    "LI": (21, "5!n12!c"),
    "LT": (20, "5!n11!n"),
    "LU": (20, "3!n13!c"),
    "LV": (21, "4!a13!c"),
    "LY": (25, "3!n3!n15!n"),
    "MC": (27, "5!n5!n11!c2!n"),
    "MD": (24, "2!c18!c"),
    "ME": (22, "3!n13!n2!n"),
    "MK": (19, "3!n10!c2!n"),
    "MN": (20, "4!n12!n"),
    "MR": (27, "5!n5!n11!n2!n"),
    "MT": (31, "4!a5!n18!c"),
    "MU": (30, "4!a2!n2!n12!n3!n3!a"),
    "NI": (28, "4!a20!n"),
    "NL": (18, "4!a10!n"),
    "NO": (15, "4!n6!n1!n"),
    "OM": (23, "3!n16!c"),
    "PK": (24, "4!a16!c"),
    "PL": (28, "8!n16!n"),
    "PS": (29, "4!a21!c"),
    "PT": (25, "4!n4!n11!n2!n"),
    "QA": (29, "4!a21!c"),
    "RO": (24, "4!a16!c"),
    "RS": (22, "3!n13!n2!n"),
    "RU": (33, "9!n5!n15!c"),
    "SA": (24, "2!n18!c"),
    "SC": (31, "4!a2!n2!n16!n3!a"),
    "SD": (18, "2!n12!n"),
    "SE": (24, "3!n16!n1!n"),
    "SI": (19, "5!n8!n2!n"),
    "SK": (24, "4!n6!n10!n"),
    "SM": (27, "1!a5!n5!n12!c"),
    "SO": (23, "4!n3!n12!n"),
    "ST": (25, "4!n4!n11!n2!n"),
    "SV": (28, "4!a20!n"),
    "TL": (23, "3!n14!n2!n"),
    "TN": (24, "2!n3!n13!n2!n"),
    "TR": (26, "5!n1!n16!c"),
    "UA": (29, "6!n19!c"),
    "VA": (22, "3!n15!n"),
    "VG": (24, "4!a16!n"),
    "XK": (20, "4!n10!n2!n"),
    "YE": (30, "4!a4!n18!c"),
}

# IBAN country -> BIC countries that belong to the same IBAN prefix.
TERRITORY_BIC = {
    "FR": frozenset("GF GP MQ RE PF TF YT NC BL MF PM WF".split()),
    "GB": frozenset("GG JE IM".split()),
}

TERRITORY_WHY = {
    "FR": "French territories use FR IBANs",
    "GB": "Guernsey, Jersey and the Isle of Man use GB IBANs",
}

# SIX QR-IID range. A QR-IBAN is a valid IBAN and cannot take a normal credit transfer.
QR_COUNTRIES = frozenset(("CH", "LI"))
QR_IID_MIN = 30000
QR_IID_MAX = 31999

GENERIC_IBAN = re.compile(r"^[A-Z]{2}[0-9]{2}[A-Z0-9]{11,30}$")
_TOKEN = re.compile(r"(\d+)!([nac])")
_CLASSES = {"n": "0-9", "a": "A-Z", "c": "A-Z0-9"}
_CONFUSABLE = {"O": "0", "0": "O", "I": "1", "1": "I", "B": "8", "8": "B"}

_COMPILED = {}
for _cc, (_length, _spec) in SPECS.items():
    _parts = _TOKEN.findall(_spec)
    if not _parts or _TOKEN.sub("", _spec):
        raise RuntimeError("bad BBAN spec for %s" % _cc)
    _body = "".join("[%s]{%s}" % (_CLASSES[kind], count) for count, kind in _parts)
    _bban_len = sum(int(count) for count, _kind in _parts)
    if _bban_len + 4 != _length:
        raise RuntimeError("length mismatch for %s" % _cc)
    _COMPILED[_cc] = (_length, re.compile(_body))


def iban_checksum_ok(iban):
    """ISO 7064 mod 97-10. The IBAN is already normalized."""
    rearranged = iban[4:] + iban[:4]
    digits = "".join(str(int(ch, 36)) for ch in rearranged)
    return int(digits) % 97 == 1


def with_checksum(country, bban):
    """Build an IBAN from a country code and BBAN. Used by tests."""
    country = country.upper()
    rearranged = bban.upper() + country + "00"
    digits = "".join(str(int(ch, 36)) for ch in rearranged)
    check = 98 - (int(digits) % 97)
    return "%s%02d%s" % (country, check, bban.upper())


def assess_iban(iban):
    """Classify a normalized IBAN.

    format_ok means length, check-digit characters and national structure
    passed (or, for an unknown country, the generic 15-34 character shape).
    checksum_ok implies format_ok. qr is only set when both passed.
    """
    result = {
        "format_ok": False,
        "checksum_ok": False,
        "known_country": False,
        "qr": False,
        "detail": "The IBAN is not in a valid format.",
    }
    if len(iban) < 2 or not iban[:2].isalpha():
        return result
    cc = iban[:2]
    spec = _COMPILED.get(cc)
    if spec:
        result["known_country"] = True
        length, pattern = spec
        if len(iban) != length:
            result["detail"] = "%s IBANs are %d characters; this one is %d." % (cc, length, len(iban))
            return result
        if not iban[2:4].isdigit():
            result["detail"] = "%s IBANs need two numeric check digits." % cc
            return result
        if pattern.fullmatch(iban[4:]) is None:
            result["detail"] = (
                "The national part of this %s IBAN does not match the structure for that country." % cc)
            return result
    elif GENERIC_IBAN.fullmatch(iban) is None:
        return result
    result["format_ok"] = True
    if not iban_checksum_ok(iban):
        result["detail"] = ""
        return result
    result["checksum_ok"] = True
    result["detail"] = ""
    if cc in QR_COUNTRIES and iban[4:9].isdigit():
        iid = int(iban[4:9])
        result["qr"] = QR_IID_MIN <= iid <= QR_IID_MAX
    return result


def territory_note(iban_cc, bic_cc):
    """Note when a BIC country is the territory behind an FR or GB IBAN. Otherwise None."""
    if bic_cc in TERRITORY_BIC.get(iban_cc, ()):
        return ("BIC country is %s and IBAN country is %s. %s, so this is not a country mismatch."
                % (bic_cc, iban_cc, TERRITORY_WHY[iban_cc]))
    return None


def typo_hint(iban):
    """Return the single one-edit correction that passes, or None.

    Edits are an adjacent transposition or one O/0, I/1 or B/8 swap.
    The country code is kept. More than one passing candidate returns None,
    because a guess that could be several accounts is not a hint.
    """
    if len(iban) < 4 or assess_iban(iban)["checksum_ok"]:
        return None
    country = iban[:2]
    found = []

    def consider(trial):
        if trial.startswith(country) and trial not in found and assess_iban(trial)["checksum_ok"]:
            found.append(trial)

    chars = list(iban)
    for i in range(len(chars) - 1):
        if chars[i] == chars[i + 1]:
            continue
        trial = chars[:]
        trial[i], trial[i + 1] = trial[i + 1], trial[i]
        consider("".join(trial))
    for i, ch in enumerate(chars):
        swapped = _CONFUSABLE.get(ch)
        if not swapped:
            continue
        trial = chars[:]
        trial[i] = swapped
        consider("".join(trial))
    if len(found) == 1:
        return found[0]
    return None
