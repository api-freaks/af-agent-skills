# server-log-enrichment

An agent skill that turns a web server, proxy, load balancer, or CDN access log
into an enriched dataset and a report: who or what is hitting your server, from
where, and whether it is automated, spoofed, or worth blocking.

It does the heavy parts locally (parsing gigabytes, filtering, counting), asks
before it spends anything, and looks up only what is worth looking up, through
the APIFreaks MCP server. This file is for people. The agent reads `SKILL.md`.

## What you get

- **A dataset (CSV).** One row per unique IP, hostname, or user agent, with its
  request count, lookup results, and a status saying whether it was enriched,
  filtered, or not found. Safe to open in a spreadsheet.
- **A report.** Traffic concentration, automated versus human, flagged addresses
  with the log evidence behind each, what could not be resolved, and the estimated
  cost.
- **No block lists.** It gives candidates and evidence for a person to act on, not
  firewall rules.

It is not a general log analytics tool. For error rates, latency, or funnels, use
the tools you already have.

## Requirements

| For | You need |
| --- | --- |
| Everything | Read access to the log, a shell, Python 3.8 or newer, a writable directory |
| Lookups | The [APIFreaks MCP server](https://apifreaks.com/integrations/mcp-server) connected to your agent, with the modules the task needs enabled |
| Local-only report | Nothing else. It works with no lookups at all |

If a lookup tool is missing, its module is usually just not enabled. The skill
tells you which one to turn on, or you can carry on in local-only mode. It never
falls back to calling the API directly.

## Install

```bash
npx skills add api-freaks/af-agent-skills --skill server-log-enrichment
```

Or copy the `server-log-enrichment` folder into your agent's skills directory.

## Using it

Ask in plain words. You do not need to mention the skill or APIFreaks.

- "Who has been hammering our login endpoint? The log is `/var/log/nginx/access.log.1`."
- "Which countries is our traffic coming from? Here is a month of Apache logs."
- "Are the Googlebot hits in this log real?"
- "Give me a bot versus human breakdown of this ALB log."

A run reads the log, extracts unique IPs, hostnames, and user agents with counts,
filters what is not worth paying for, shows you a priced plan and waits for your
yes, enriches in a cheap wide pass and an optional narrow expensive one, then
writes the dataset and the report. Nothing is spent before you agree to the plan,
apart from one announced single-item check when an address might be a CDN edge.

Behind a proxy or CDN the log's address field is usually the proxy, not the
visitor. The skill works out which it is first. `references/formats.md` covers
where each platform keeps the real client address.

## Log formats

Detected per line, so mixed or rotated files work: nginx and Apache (common,
combined, vhost), IIS and CloudFront (W3C), AWS Application Load Balancer,
HAProxy, Envoy, Caddy, Traefik, Cloudflare Logpush, Google Cloud load balancer,
other JSON logs, and any of these wrapped in a syslog or RFC 5424 prefix or a
Docker json-file record. Anything else works with a regex or a key map.

## Where outputs go

Everything is written to `./sle-work-<date>/`, never beside the log. `state.json` there records each approval (the plan, and the optional second tier) so a run can resume after the conversation is trimmed.

## What leaves your machine

Only the indicators you approve: IP addresses, hostnames, and user agent strings,
sent to APIFreaks through the MCP tools. Paths, query strings, headers, cookies,
bodies, and emails are never sent. IP addresses can be personal data, so the plan
tells you how many will go out before anything does. Log content is treated as
untrusted data, never as instructions.

## What it refuses

Sending anything but the extracted indicators, calling the APIFreaks API
directly, spending without a stated cost and your yes, producing firewall rules,
calling an address malicious or naming an actor, and live tailing or alerting.

## How the cost is worked out

The skill holds no prices. It counts unique items and reads the current credits
for each endpoint from `https://apifreaks.com/llms-full.txt` before a run. Those
are base costs, so the total is an estimate. The MCP tools report no cost, so
actual spend cannot be verified and the report marks it as unverified.

## What is in the folder

```
SKILL.md                     the instructions the agent follows
README.md                    this file
references/
  formats.md                 where each platform keeps the client address
  reporting.md               dataset layout and how to word findings
assets/
  report-template.md         the report layout the agent fills in
scripts/
  extract_indicators.py      streams a log, writes unique indicators with counts
  ip_evidence.py            local evidence for the addresses you flag
  build_dataset.py          joins results into the safe CSV, with exact totals
```

## The scripts

All three are offline, use only the standard library, and have `--help`.

```bash
python3 scripts/extract_indicators.py access.log.gz --out work
python3 scripts/ip_evidence.py access.log.gz --ips flagged.txt --out evidence
python3 scripts/build_dataset.py --indicators work/ips.jsonl \
    --results ip_results.jsonl --out dataset_ips.csv --group-by asn.organization
python3 scripts/build_dataset.py --indicators work/ips.jsonl --local-only \
    --out dataset_ips.csv
```

Memory grows with the number of unique addresses. A log with millions of
different ones needs gigabytes.

## Known limits

- It has not been run end to end against a live MCP server. The cost gate and the
  wait for a yes depend on agent behavior that only a live session shows.
- Matching an MCP tool to its published cost row is a judgment the skill asks the
  agent to show, so you can catch a wrong match before approving.
- Cloud and hosting ranges, shared carrier ranges, and search engine crawlers trip
  automation signals in normal operation. Treat flags as leads, not verdicts.
- Without a forwarded-address field, clients behind a CDN cannot be identified
  from that log, and the skill says so rather than guessing.

## License

MIT
