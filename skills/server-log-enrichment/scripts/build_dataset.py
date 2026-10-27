#!/usr/bin/env python3
"""Build the final dataset CSV from extracted indicators and lookup results.

Run it once per indicator class (IPs, hostnames, user agents). It joins what
extract_indicators.py wrote with the results you collected from the lookup tools,
and produces:

  - a CSV with one row per extracted indicator, the indicator in the first
    column, so every row traces back to the log. Rows that were filtered or
    returned nothing stay in the file, marked in enrichment_status.
  - a summary JSON with the exact numbers the report needs: rows per status,
    empty cells per column, and optional group-by totals by request volume.

Results file: JSON Lines, one envelope per looked-up indicator, which you write
from the tool responses:

  {"indicator": "1.2.3.4", "status": "ok", "data": {...response fields...}}
  {"indicator": "5.6.7.8", "status": "not_found"}
  {"indicator": "9.9.9.9", "status": "failed", "error": "reason"}

enrichment_status values: enriched, not_found, lookup_failed, filtered_<reason>
(set with --skip), not_looked_up (no result and not skipped, which usually means
a gap to explain), and local_only when you pass --local-only because no lookups
were run. --local-only needs no results file: it writes the dataset and the exact
log numbers, and group-by can use the log columns such as cdn_edge or public. An empty cell in an enriched row means the field was absent in
that response, and summary.json counts those per column.

Spreadsheet safety: any text cell whose first visible character is =, +, -,
@ or | gets a leading single quote, so a spreadsheet cannot run it as a
formula. Whitespace, NUL, a byte-order mark and bidi controls do not hide that
character.

Nothing here touches the network.

Exit codes: 0 success, 2 bad arguments, 3 a file could not be read or written,
5 --strict and the summary has warnings.
"""

import argparse
import csv
import json
import os
import re
import sys
from collections import OrderedDict

EXIT_USAGE = 2
EXIT_IO = 3
EXIT_STRICT = 5

KEY_FIELDS = ('ip', 'host', 'user_agent')
LOG_COLUMNS = ('requests', 'share', 'first_seen', 'last_seen')
FLAG_COLUMNS = ('public', 'cdn_edge', 'dominant', 'own', 'sources',
                'contains_sensitive')
STATUS_MAP = {'ok': 'enriched', 'not_found': 'not_found', 'failed': 'lookup_failed'}
SKIP_REASONS = ('non_public', 'cdn_edge', 'dominant', 'own')
# Leading tab and CR are in the set because Excel treats them as "starts a
# formula" on their own, not only as camouflage for a later =.
FORMULA_START = ('=', '+', '-', '@', '|', '\t', '\r')
_BIDI = dict.fromkeys(map(ord,
    '\u200e\u200f\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069\ufeff'),
    None)
# Unicode spaces, format characters, and line breaks that spreadsheets treat
# as "not really there" or as a new cell. Includes zero-width and soft-hyphen
# characters that can hide a leading formula marker.
_PAD = ' \t\r\n\x0b\x0c\x85\u00a0\u00ad\u034f\u1680\u180e\u2000\u2001\u2002' \
       '\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a\u200b\u200c\u200d' \
       '\u2028\u2029\u202f\u205f\u2060\u3000'
_BREAKS = re.compile(r'[\t\r\n\x0b\x0c\x85\u2028\u2029]')


def _visible_start(text):
    return text.replace('\x00', '').translate(_BIDI).lstrip(_PAD)[:1]


def safe(value):
    if not isinstance(value, str) or not value:
        return value
    if value[0] in FORMULA_START or value[0] == '\x00':
        return "'" + value
    if _visible_start(value) in FORMULA_START:
        return "'" + value
    # A tab or a unicode line break inside the cell can become the next cell
    # when a spreadsheet splits on it. Prefix when that next piece is a formula.
    for part in _BREAKS.split(value):
        if _visible_start(part) in FORMULA_START:
            return "'" + value
    return value


def flatten(obj, prefix=''):
    out = OrderedDict()
    if isinstance(obj, dict):
        for k, v in obj.items():
            name = '%s.%s' % (prefix, k) if prefix else str(k)
            if isinstance(v, dict):
                out.update(flatten(v, name))
            else:
                out[name] = v
    return out


def cell(value):
    if value is None:
        return ''
    if isinstance(value, bool):
        return 'true' if value else 'false'
    if isinstance(value, (list, tuple)):
        if all(isinstance(x, (str, int, float)) and not isinstance(x, bool) for x in value):
            return ';'.join(str(x) for x in value)
        return json.dumps(value, ensure_ascii=False, separators=(',', ':'))
    return value


def read_jsonl(path, label):
    rows = []
    with open(path, 'r', encoding='utf-8', errors='replace') as fh:
        for n, line in enumerate(fh, start=1):
            s = line.strip()
            if not s:
                continue
            try:
                obj = json.loads(s)
            except ValueError:
                raise ValueError('%s line %d is not valid JSON' % (label, n))
            if isinstance(obj, dict):
                rows.append(obj)
    return rows


def skip_reason(rec, skips):
    for reason in skips:
        if reason == 'non_public' and rec.get('public') is False:
            return reason
        if reason == 'cdn_edge' and rec.get('cdn_edge') == 'yes':
            return reason
        if reason == 'dominant' and rec.get('dominant') is True:
            return reason
        if reason == 'own' and rec.get('own') == 'yes':
            return reason
    return None


def build_parser():
    p = argparse.ArgumentParser(
        prog='build_dataset.py',
        description='Join extracted indicators with lookup results into a '
                    'safe CSV and a summary of exact numbers. Local only.',
        epilog='Examples:\n'
               '  python3 scripts/build_dataset.py --indicators work/ips.jsonl '
               '--results work/ip_results.jsonl --out dataset_ips.csv '
               '--skip non_public,cdn_edge --group-by asn.organization '
               '--total-lines 12598\n'
               '  python3 scripts/build_dataset.py --indicators '
               'work/user_agents.jsonl --results work/ua_results.jsonl '
               '--out dataset_uas.csv --group-by type\n'
               '\n'
               'Group-by names are the flattened result columns, such as '
               'location.country_name, or a log column in local-only mode. '
               'Totals are by request volume among the rows in the group '
               '(enriched rows, or every row with --local-only). '
               'share_of_grouped_requests uses that total. '
               'share_of_listed_requests uses every row in the dataset, '
               'including filtered ones.',
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('--indicators', required=True,
                   help='ips.jsonl, hostnames.jsonl or user_agents.jsonl')
    p.add_argument('--results', action='append', default=[],
                   help='results JSONL, repeatable. Omit if nothing was looked up')
    p.add_argument('--out', required=True, help='dataset CSV to write')
    p.add_argument('--summary', help='summary JSON (default: OUT with .summary.json)')
    p.add_argument('--skip', default='',
                   help='comma list of reasons that were filtered before lookup: '
                        + ', '.join(SKIP_REASONS))
    p.add_argument('--columns', help='keep only these result columns, comma list')
    p.add_argument('--group-by', action='append', default=[],
                   help='result column to total by request volume, repeatable')
    p.add_argument('--top', type=int, default=10, help='groups to list (default 10)')
    p.add_argument('--total-lines', type=int,
                   help='parsed lines in the log, to add share_of_log to groups')
    p.add_argument('--local-only', action='store_true',
                   help='no lookups were run: mark rows local_only, no results file')
    p.add_argument('--strict', action='store_true',
                   help='exit 5 if the summary has warnings')
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    skips = [s.strip() for s in args.skip.split(',') if s.strip()]
    for s in skips:
        if s not in SKIP_REASONS:
            print('error: unknown --skip reason %r; use: %s'
                  % (s, ', '.join(SKIP_REASONS)), file=sys.stderr)
            return EXIT_USAGE
    keep_cols = ([c.strip() for c in args.columns.split(',') if c.strip()]
                 if args.columns else None)
    if args.local_only and args.results:
        print('error: --local-only means no lookups, so do not give --results',
              file=sys.stderr)
        return EXIT_USAGE

    try:
        indicators = read_jsonl(args.indicators, 'indicators')
    except (OSError, ValueError) as exc:
        print('error: cannot read --indicators: %s' % exc, file=sys.stderr)
        return EXIT_IO
    if not indicators:
        print('error: the indicators file has no rows', file=sys.stderr)
        return EXIT_USAGE
    key = next((k for k in KEY_FIELDS if k in indicators[0]), None)
    if key is None:
        print('error: indicators rows need one of: %s' % ', '.join(KEY_FIELDS),
              file=sys.stderr)
        return EXIT_USAGE

    warnings = []
    results = {}
    dupes = bad_status = 0
    for path in args.results:
        try:
            envelopes = read_jsonl(path, path)
        except (OSError, ValueError) as exc:
            print('error: cannot read --results: %s' % exc, file=sys.stderr)
            return EXIT_IO
        for env in envelopes:
            ind = env.get('indicator')
            if not isinstance(ind, str):
                continue
            if env.get('status') not in STATUS_MAP:
                bad_status += 1
                env = dict(env, status='failed')
            if ind in results:
                dupes += 1
            results[ind] = env
    known = {rec[key] for rec in indicators}
    orphans = [i for i in results if i not in known]
    if orphans:
        warnings.append('%d results match no extracted indicator, for example %s'
                        % (len(orphans), orphans[0][:80]))
    if dupes:
        warnings.append('%d indicators had more than one result; the last was used'
                        % dupes)
    if bad_status:
        warnings.append('%d results had a status other than ok, not_found or '
                        'failed and were treated as failed' % bad_status)

    base = ['indicator', 'requests']
    # Every row, not a prefix of the file. A flag that appears only later
    # (contains_sensitive on one user agent) must still become a column.
    present = lambda name: any(name in rec for rec in indicators)  # noqa: E731
    base += [c for c in ('share', 'first_seen', 'last_seen') if present(c)]
    base.append('enrichment_status')
    flags = [c for c in FLAG_COLUMNS if present(c)]

    rows = []
    data_cols = OrderedDict()
    status_counts = {}
    for rec in indicators:
        ind = rec[key]
        env = results.get(ind)
        data = {}
        if env is not None:
            status = STATUS_MAP[env['status']]
            if status == 'enriched' and isinstance(env.get('data'), dict):
                data = flatten(env['data'])
        else:
            reason = skip_reason(rec, skips)
            if args.local_only:
                status = 'local_only'
            else:
                status = 'filtered_' + reason if reason else 'not_looked_up'
        status_counts[status] = status_counts.get(status, 0) + 1
        for name in data:
            if keep_cols is None or name in keep_cols:
                data_cols.setdefault(name, 0)
        rows.append((rec, status, data))
    if keep_cols is not None:
        for c in keep_cols:
            data_cols.setdefault(c, 0)

    if status_counts.get('not_looked_up'):
        warnings.append('%d indicators were neither looked up nor skipped. Explain '
                        'them in the report or add the missing --skip reason.'
                        % status_counts['not_looked_up'])

    header = base + flags
    taken = set(header)
    data_names = {}
    for name in data_cols:
        out_name = name
        n = 2
        while out_name in taken:
            out_name = '%s_%d' % (name, n)
            n += 1
        taken.add(out_name)
        data_names[name] = out_name
        header.append(out_name)

    empty = {name: 0 for name in data_cols}
    enriched_rows = 0
    try:
        os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
        with open(args.out, 'w', encoding='utf-8', newline='') as fh:
            # Quote every text field so a tab or odd line break inside a
            # user agent cannot become a new cell.
            writer = csv.writer(fh, lineterminator='\n',
                                quoting=csv.QUOTE_NONNUMERIC)
            writer.writerow([safe(col) for col in header])
            for rec, status, data in rows:
                line = [safe(rec[key]), rec.get('count')]
                for c in ('share', 'first_seen', 'last_seen'):
                    if c in base:
                        line.append(safe(cell(rec.get(c))))
                line.append(status)
                for c in flags:
                    line.append(safe(cell(rec.get(c))))
                if status == 'enriched':
                    enriched_rows += 1
                for name in data_cols:
                    if name in data:
                        value = cell(data[name])
                        if value == '' and status == 'enriched':
                            empty[name] += 1
                        line.append(safe(value))
                    else:
                        if status == 'enriched':
                            empty[name] += 1
                        line.append('')
                writer.writerow(line)
    except OSError as exc:
        print('error: cannot write %s: %s' % (args.out, exc), file=sys.stderr)
        return EXIT_IO

    total_requests = sum(int(rec.get('count') or 0) for rec, _, _ in rows)
    grouped_requests = sum(int(rec.get('count') or 0) for rec, status, _ in rows
                           if status == 'enriched' or args.local_only)
    groups = {}
    log_cols = set(FLAG_COLUMNS) | {'share', 'first_seen', 'last_seen'}
    for col in args.group_by:
        if col not in data_cols and col not in log_cols:
            warnings.append('--group-by %s is not a result or log column' % col)
            continue
        tally = {}
        for rec, status, data in rows:
            if status != 'enriched' and not args.local_only:
                continue
            value = cell(data.get(col) if col in data_cols else rec.get(col))
            value = '(absent)' if value == '' else str(value)
            t = tally.setdefault(value, [0, 0])
            t[0] += 1
            t[1] += int(rec.get('count') or 0)
        ordered = sorted(tally.items(), key=lambda kv: (-kv[1][1], kv[0]))
        listed = []
        for value, (n_rows, reqs) in ordered[:args.top]:
            item = {'value': value, 'rows': n_rows, 'requests': reqs,
                    'share_of_grouped_requests':
                        round(reqs / grouped_requests, 4) if grouped_requests else 0.0,
                    'share_of_listed_requests':
                        round(reqs / total_requests, 4) if total_requests else 0.0}
            if args.total_lines:
                item['share_of_log'] = round(reqs / args.total_lines, 4)
            listed.append(item)
        groups[col] = {'distinct_values': len(tally),
                       'grouped_requests': grouped_requests, 'top': listed}

    top_rows = []
    for rec, status, _ in sorted(rows, key=lambda r: -int(r[0].get('count') or 0))[:args.top]:
        item = {'indicator': str(rec[key])[:200], 'requests': rec.get('count'),
                'status': status}
        for c in ('share',) + FLAG_COLUMNS:
            if c in rec:
                item[c] = rec[c]
        top_rows.append(item)

    summary = {
        'dataset': args.out,
        'rows': len(rows),
        'enrichment_status': status_counts,
        'listed_requests': total_requests,
        'empty_cells_in_enriched_rows': {
            data_names[n]: c for n, c in empty.items() if c},
        'enriched_rows': enriched_rows,
        'top_rows': top_rows,
        'groups': groups,
        'warnings': warnings,
    }
    summary_path = args.summary or (os.path.splitext(args.out)[0] + '.summary.json')
    try:
        with open(summary_path, 'w', encoding='utf-8') as fh:
            json.dump(summary, fh, indent=2, ensure_ascii=False)
            fh.write('\n')
    except OSError as exc:
        print('error: cannot write %s: %s' % (summary_path, exc), file=sys.stderr)
        return EXIT_IO
    print(json.dumps(summary, indent=2, ensure_ascii=False))
    if warnings and args.strict:
        print('error: %d warnings, see the summary' % len(warnings), file=sys.stderr)
        return EXIT_STRICT
    return 0


if __name__ == '__main__':
    sys.exit(main())
