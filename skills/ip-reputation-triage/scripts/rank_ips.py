#!/usr/bin/env python3
"""Rank enriched IPs by triage priority.

Usage:
  python rank_ips.py ENRICHMENT.json [--activity ips.csv] [--out ranked.csv]
                     [--ownership ownership.json] [--high 70] [--medium 30]
                     [--act-high 50] [--act-medium 5]

ENRICHMENT.json is a JSON array, one object per IP. See references/input-schema.md.
The rules are documented in references/ranking.md. Addresses are compared in
canonical form, so the same IPv6 address written in long or short form is one
address. Standard library only.
"""
import argparse
import csv
import ipaddress
import math
import json
import sys

ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "unchecked": 4}
MATRIX = {
    "high":    {"high": "critical",  "medium": "high",   "low": "medium", "unknown": "high"},
    "medium":  {"high": "high",      "medium": "medium", "low": "low",    "unknown": "medium"},
    "low":     {"high": "medium",    "medium": "low",    "low": "low",    "unknown": "low"},
    "unknown": {"high": "unchecked", "medium": "unchecked", "low": "unchecked", "unknown": "unchecked"},
}
UNDECLARED_BOTS = {"scanner", "scraper", "exploit", "credential_stuffing", "brute_force"}


def canon(value):
    """Canonical text form of an address, so '2001:4860:4860:0:0:0:0:8888' and
    '2001:4860:4860::8888' are the same key. Unparseable values are returned stripped."""
    text = str(value).strip()
    try:
        addr = ipaddress.ip_address(text)
    except ValueError:
        return text
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
        addr = addr.ipv4_mapped
    return str(addr)


def flatten(item):
    """Accept the nested {'ip':..., 'security': {...}} shape as well as a flat one."""
    flat = dict(item)
    sec = flat.pop("security", None)
    if isinstance(sec, dict):
        for k, v in sec.items():
            flat.setdefault(k, v)
    return flat


def truthy(rec, key):
    return rec.get(key) is True


def number(value):
    """A usable threat score is a finite number from 0 to 100. Anything else is unknown."""
    if isinstance(value, bool) or value is None or value == "":
        return None
    try:
        n = float(value)
    except (TypeError, ValueError):
        return None
    if not math.isfinite(n) or n < 0 or n > 100:
        return None
    return n


def lookup_failed(rec):
    ok = rec.get("ok")
    return ok is False or (isinstance(ok, str) and ok.strip().lower() == "false")


REPUTATION_KEYS = ("is_tor", "is_proxy", "is_vpn", "is_bot", "is_known_attacker", "is_known_good_bot",
                   "is_anonymous", "is_residential_proxy", "is_spam")


def csv_safe(value):
    """Stop a spreadsheet from running a text cell as a formula."""
    if isinstance(value, str) and value[:1] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + value
    return value


def reputation(rec, hi, med):
    """Return (level, reasons)."""
    score = number(rec.get("threat_score"))
    if lookup_failed(rec) or (score is None and not any(isinstance(rec.get(k), bool) for k in REPUTATION_KEYS)):
        return "unknown", []
    reasons = []
    attacker = truthy(rec, "is_known_attacker")
    if truthy(rec, "is_known_good_bot") and not attacker:
        return "low", ["declared good bot"]
    undeclared = truthy(rec, "is_bot") and not truthy(rec, "is_known_good_bot")
    if score is not None and score >= hi:
        reasons.append(f"threat score {int(score)}")
    if truthy(rec, "is_tor"):
        reasons.append("Tor")
    if attacker:
        reasons.append("known attacker")
    if undeclared:
        bt = rec.get("bot_type") or "bot"
        reasons.append(f"undeclared bot ({bt})")
    if reasons:
        return "high", reasons
    if score is not None and score >= med:
        reasons.append(f"threat score {int(score)}")
    for key, label in (("is_vpn", "VPN"), ("is_proxy", "proxy"), ("is_residential_proxy", "residential proxy"),
                       ("is_spam", "spam listed"), ("is_anonymous", "anonymizer")):
        if truthy(rec, key):
            reasons.append(label)
    if reasons:
        return "medium", reasons
    return "low", []


def activity_level(events, ah, am):
    if events is None:
        return "unknown"
    if events >= ah:
        return "high"
    if events >= am:
        return "medium"
    return "low"


def load_activity(path):
    out = {}
    with open(path, newline="") as f:
        for row in csv.DictReader(f):
            try:
                key = canon(row["ip"])
                events = int(row["events"])
            except (KeyError, ValueError):
                continue
            first, last = row.get("first_seen", ""), row.get("last_seen", "")
            if key in out:  # same address written two ways: add the events together
                pe, pf, pl, ps = out[key]
                firsts = [x for x in (pf, first) if x]
                out[key] = (pe + events, min(firsts) if firsts else "", max(pl, last), ps or row.get("statuses", ""))
            else:
                out[key] = (events, first, last, row.get("statuses", ""))
    return out


def owner_fields(o):
    o = o or {}
    return {"owner": o.get("owner", ""), "network_range": o.get("network_range", ""),
            "abuse_contact": o.get("abuse_contact", ""), "owner_country": o.get("country", ""),
            "ownership_note": o.get("note", "")}


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("enrichment")
    ap.add_argument("--activity")
    ap.add_argument("--ownership")
    ap.add_argument("--out", default="ranked.csv")
    ap.add_argument("--high", type=float, default=70)
    ap.add_argument("--medium", type=float, default=30)
    ap.add_argument("--act-high", type=int, default=50)
    ap.add_argument("--act-medium", type=int, default=5)
    a = ap.parse_args()

    if a.medium > a.high:
        sys.exit("--medium must not exceed --high")
    with open(a.enrichment) as f:
        data = json.load(f)
    if not isinstance(data, list):
        sys.exit("Enrichment file must be a JSON array of objects.")
    activity = load_activity(a.activity) if a.activity else {}
    owners = {}
    if a.ownership:
        with open(a.ownership) as f:
            for o in json.load(f):
                if isinstance(o, dict) and o.get("ip"):
                    owners[canon(o["ip"])] = o

    rows, seen, normalized, duplicates = [], set(), 0, []
    for item in data:
        if not isinstance(item, dict) or not item.get("ip"):
            sys.exit(f"Every entry needs an 'ip'. Bad entry: {item!r}")
        rec = flatten(item)
        raw_ip = str(rec["ip"]).strip()
        ip = canon(raw_ip)
        if ip != raw_ip:
            normalized += 1
        if ip in seen:
            duplicates.append(raw_ip)
            continue
        seen.add(ip)
        rep, reasons = reputation(rec, a.high, a.medium)
        events, first, last, statuses = activity.get(ip, (None, "", "", "")) if a.activity else (None, "", "", "")
        act = activity_level(events, a.act_high, a.act_medium)
        priority = MATRIX[rep][act]
        notes = []
        if rep == "unknown":
            notes.append("lookup failed or no data" + (f": {rec['error']}" if rec.get("error") else ""))
        if truthy(rec, "is_corporate_gateway") or truthy(rec, "is_relay"):
            notes.append("shared gateway risk: blocking may affect many users")
        if truthy(rec, "is_cloud_provider"):
            name = rec.get("cloud_provider_name") or "cloud provider"
            notes.append(f"cloud hosted ({name}): check whether it is a service you use")
        flags = [k.replace("is_", "") for k in ("is_tor", "is_proxy", "is_residential_proxy", "is_vpn", "is_relay",
                 "is_anonymous", "is_known_attacker", "is_bot", "is_spam", "is_cloud_provider",
                 "is_corporate_gateway") if truthy(rec, k)]
        rows.append({
            "ip": ip, "priority": priority, "reputation": rep, "activity": act,
            "threat_score": "" if number(rec.get("threat_score")) is None else int(number(rec["threat_score"])),
            "flags": ";".join(flags), "country": rec.get("country", ""), "network": rec.get("network", ""),
            "organization": rec.get("organization", ""),
            "events": "" if events is None else events, "statuses": statuses, "first_seen": first, "last_seen": last,
            "reason": "; ".join(reasons), "notes": "; ".join(notes),
            **owner_fields(owners.get(ip)),
        })

    missing = sorted(set(activity) - seen)
    for ip in missing:
        events, first, last, statuses = activity[ip]
        act = activity_level(events, a.act_high, a.act_medium)
        rows.append({"ip": ip, "priority": "unchecked", "reputation": "unknown", "activity": act,
                     "threat_score": "", "flags": "", "country": "", "network": "", "organization": "",
                     "events": events, "statuses": statuses, "first_seen": first, "last_seen": last, "reason": "",
                     "notes": "in activity file but missing from enrichment", **owner_fields(owners.get(ip))})

    rows.sort(key=lambda r: (ORDER[r["priority"]], -(r["events"] if r["events"] != "" else -1),
                             -(r["threat_score"] if r["threat_score"] != "" else -1), r["ip"]))
    cols = ["ip", "priority", "reputation", "activity", "threat_score", "flags", "country", "network",
            "organization", "events", "statuses", "first_seen", "last_seen", "reason", "notes",
            "owner", "network_range", "abuse_contact", "owner_country", "ownership_note"]
    with open(a.out, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
        w.writerows({k: csv_safe(v) for k, v in row.items()} for row in rows)

    counts = {k: 0 for k in ORDER}
    for r in rows:
        counts[r["priority"]] += 1
    print(json.dumps({
        "total": len(rows), "by_priority": counts,
        "cutoffs": {"threat_high": a.high, "threat_medium": a.medium,
                    "activity_high": a.act_high, "activity_medium": a.act_medium},
        "activity_supplied": bool(a.activity), "addresses_normalized": normalized,
        "duplicate_entries_skipped": duplicates, "ownership_entries": len(owners),
        "ownership_not_in_ranking": sorted(set(owners) - seen - set(activity)), "missing_from_enrichment": missing, "output": a.out,
    }, indent=2))


if __name__ == "__main__":
    main()
