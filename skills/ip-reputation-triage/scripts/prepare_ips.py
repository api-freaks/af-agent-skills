#!/usr/bin/env python3
"""Extract, deduplicate and filter IP addresses from a file.

Usage:
  python prepare_ips.py INPUT [--out DIR] [--ip-col NAME] [--time-col NAME] [--status-col NAME]

INPUT is a text file, log file or CSV. For CSV input, --ip-col names the column
that holds the IP. --time-col names an optional timestamp column and --status-col
an optional status or outcome column. Timestamps are compared as text, so ISO 8601
values sort correctly.

An "event" is one line (or CSV row) that mentions the IP. Events are volume only.
They do not say whether a request failed. To help tell failed logins from
ordinary traffic, the script also tallies status codes into a "statuses" column
(for example "401:60 200:2"). In text logs it reads the status code that follows
the quoted request in common and combined log formats. Other formats get a blank
statuses column unless --status-col is used.

Addresses are written in canonical form (IPv6 compressed), the same form
rank_ips.py uses, so both scripts agree on every address.

Writes DIR/ips.csv (ip, events, first_seen, last_seen, statuses), DIR/dropped.csv
(ip, reason, events) and prints a JSON summary. Standard library only.
"""
import argparse
import csv
import ipaddress
import json
import os
import re
import sys

# Order matters. A mixed form such as ::ffff:9.9.9.9 is taken whole before any
# shorter IPv6 match. A colon before an address (client:4.4.4.4) or a port after
# it (8.8.8.8:443) is allowed. Digits or a dot-digit after an address mean it is
# part of something longer, such as a version number, so it is not matched.
CANDIDATE = re.compile(
    r"(?<![\w.])("
    r"(?:[0-9A-Fa-f]{0,4}:){2,6}(?:\d{1,3}\.){3}\d{1,3}(?![\w]|\.\d)"
    r"|(?:\d{1,3}\.){3}\d{1,3}(?![\w]|\.\d)"
    r"|(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?![\w:]|\.\d)"
    r")"
)
TIME_IN_LINE = re.compile(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}")
STATUS_IN_LINE = re.compile(r'"\s*(?:[A-Z]+\s+[^"]*|-)"\s+(\d{3})\b')


def classify(addr):
    """Return None if the address is public, otherwise a reason string."""
    if addr.is_loopback:
        return "loopback"
    if addr.is_private and not addr.is_global:
        return "private or reserved"
    if addr.is_link_local:
        return "link-local"
    if addr.is_multicast:
        return "multicast"
    if addr.is_unspecified:
        return "unspecified"
    if addr.is_reserved:
        return "reserved"
    if not addr.is_global:
        return "not globally routable"
    return None


def normalize(text):
    try:
        addr = ipaddress.ip_address(text.strip())
    except ValueError:
        return None
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
        addr = addr.ipv4_mapped
    return addr


def update(stats, key, stamp, status=""):
    s = stats.setdefault(key, {"events": 0, "first": "", "last": "", "statuses": {}})
    s["events"] += 1
    if status:
        s["statuses"][status] = s["statuses"].get(status, 0) + 1
    if stamp:
        if not s["first"] or stamp < s["first"]:
            s["first"] = stamp
        if not s["last"] or stamp > s["last"]:
            s["last"] = stamp


def read_csv(path, ip_col, time_col, status_col=None):
    stats, malformed = {}, 0
    with open(path, newline="", encoding="utf-8", errors="replace") as f:
        reader = csv.DictReader(f)
        if ip_col not in (reader.fieldnames or []):
            sys.exit(f"Column '{ip_col}' not found. Columns: {reader.fieldnames}")
        if time_col and time_col not in reader.fieldnames:
            sys.exit(f"Column '{time_col}' not found. Columns: {reader.fieldnames}")
        if status_col and status_col not in reader.fieldnames:
            sys.exit(f"Column '{status_col}' not found. Columns: {reader.fieldnames}")
        for row in reader:
            raw = (row.get(ip_col) or "").strip()
            addr = normalize(raw)
            if addr is None:
                malformed += 1
                continue
            update(stats, addr, (row.get(time_col) or "").strip() if time_col else "",
                   (row.get(status_col) or "").strip() if status_col else "")
    return stats, malformed


def read_text(path):
    stats, malformed = {}, 0
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            m_time = TIME_IN_LINE.search(line)
            stamp = m_time.group(0).replace(" ", "T") if m_time else ""
            m_status = STATUS_IN_LINE.search(line)
            status = m_status.group(1) if m_status else ""
            for m in CANDIDATE.finditer(line):
                raw = m.group(1)
                # Times such as 02:00:10 look like short IPv6 text. A real IPv6
                # address has "::", seven colons, or a dotted IPv4 tail.
                if ":" in raw and "." not in raw and "::" not in raw and raw.count(":") < 7:
                    continue
                addr = normalize(raw)
                if addr is None:
                    malformed += 1
                    continue
                update(stats, addr, stamp, status)
    return stats, malformed


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("input")
    ap.add_argument("--out", default="work")
    ap.add_argument("--ip-col")
    ap.add_argument("--time-col")
    ap.add_argument("--status-col")
    args = ap.parse_args()

    if args.ip_col:
        stats, malformed = read_csv(args.input, args.ip_col, args.time_col, args.status_col)
    else:
        stats, malformed = read_text(args.input)

    os.makedirs(args.out, exist_ok=True)
    kept, dropped = [], []
    for addr, s in stats.items():
        reason = classify(addr)
        if reason:
            dropped.append((str(addr), reason, s["events"]))
        else:
            tally = " ".join(f"{k}:{v}" for k, v in sorted(s["statuses"].items(), key=lambda kv: (-kv[1], kv[0])))
            kept.append((str(addr), s["events"], s["first"], s["last"], tally))
    kept.sort(key=lambda r: (-r[1], r[0]))
    dropped.sort(key=lambda r: (-r[2], r[0]))

    with open(os.path.join(args.out, "ips.csv"), "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["ip", "events", "first_seen", "last_seen", "statuses"])
        w.writerows(kept)
    with open(os.path.join(args.out, "dropped.csv"), "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["ip", "reason", "events"])
        w.writerows(dropped)

    summary = {
        "unique_public_ips": len(kept),
        "dropped_unique": len(dropped),
        "dropped_reasons": {},
        "unparseable_values": malformed,
        "total_events_kept": sum(r[1] for r in kept),
        "status_codes_detected": any(r[4] for r in kept),
        "event_definition": "lines or rows that mention the IP; volume only, not failures",
        "files": [os.path.join(args.out, "ips.csv"), os.path.join(args.out, "dropped.csv")],
    }
    for _, reason, _ in dropped:
        summary["dropped_reasons"][reason] = summary["dropped_reasons"].get(reason, 0) + 1
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
