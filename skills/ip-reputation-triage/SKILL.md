---
name: ip-reputation-triage
description: Take IP addresses from a SIEM alert, firewall log, auth failure report or incident, enrich each with location, network owner and threat or anonymizer flags, and rank them by how urgently an analyst should look, with evidence and block, watch or ignore guidance. Use when the user has suspicious IPs to investigate, wants block list candidates, or asks which addresses in a list matter most, even if no provider is named.
license: MIT
compatibility: Requires the APIFreaks MCP server with the IP intelligence module enabled. The WHOIS module is optional and used only for ownership detail. Needs an APIFreaks API key. The bundled scripts need Python 3.8 or newer and use only the standard library.
metadata:
  version: 1.0.0
  homepage: https://apifreaks.com
---

# IP reputation triage

Turn a raw list of IPs into a ranked shortlist with the evidence behind each rank. The agent runs the lookups and judges context. The bundled scripts do the mechanical steps so results are identical on every run.

The "Working with the APIFreaks MCP tools" section below covers setup, credits, volume, results and failures.

Paths below are relative to this skill's folder.

## Inputs

IPs from any source: pasted text, a CSV, an alert export or log lines. For a CSV, ask which column holds the IP and, if there is one, which holds the timestamp. Activity matters as much as reputation, so keep it when the input has it.

An "event" here is one log line or CSV row that mentions the IP. It measures volume only. It does not mean a failed login or an attack. When the log has HTTP status codes, `prepare_ips.py` tallies them per IP in a `statuses` column (for example `401:60 200:2`), and that tally is what shows failures. Without status codes or a state column, say the counts are volume only.

## Steps

1. **Prepare the list.** Run:

   `python scripts/prepare_ips.py <input file> --out work/`

   Add `--ip-col <name>`, `--time-col <name>` and, if the CSV has a status or state column, `--status-col <name>` for CSV input. The script extracts IPv4 and IPv6 addresses (IPv4-mapped forms such as `::ffff:8.8.4.4` count as the IPv4 address), deduplicates them, drops private, loopback, link-local, reserved and other non-public addresses, and writes `work/ips.csv` (ip, events, first_seen, last_seen, statuses), `work/dropped.csv` (ip, reason) and a count summary. Tell the user how many were kept and dropped.

2. **State the cost.** The calls are IP threat lookup and IP geolocation per IP (both in bulk), plus IP WHOIS per IP if ownership is needed. Prices are not stored here because they change. Fetch https://apifreaks.com/llms-full.txt with your web fetch tool (a documentation file, not an API call), read the current credit cost and billing unit of each call, multiply by unique IPs, and agree on scope before a sizeable run. If the file cannot be fetched, say the cost is unknown and ask whether to proceed. The MCP tools return no cost field, so mark actual spend as unverified in the report.

3. **Enrich in bulk.** Run the IP threat lookup and the IP geolocation lookup on `work/ips.csv`, using the bulk tools. The tool description gives the batch size, so split a larger list to fit. The threat response is a list with one entry per IP, each holding the IP and a security object. Count the entries returned against the IPs sent: the documentation does not say how a bad IP inside a bulk request is reported, so retry any that are missing and mark the rest unchecked. Check IPv6 addresses came back too. A response may spell an IPv6 address in long form, such as `2001:4860:4860:0:0:0:0:8888`, while the log used the short form. `rank_ips.py` compares addresses in canonical form, so write the address exactly as the response gave it and do not rewrite it by hand. Save the raw responses to `work/raw/` before doing anything else.

4. **Normalize.** Write `work/enrichment.json` in the format in `references/input-schema.md`. The agent only copies fields across. It never edits values or fills gaps from memory.

5. **Rank.** Run:

   `python scripts/rank_ips.py work/enrichment.json --activity work/ips.csv --out work/ranked.csv`

   The script applies the rules in `references/ranking.md` and writes the ranked CSV and a summary. Do not re-rank by hand. If a rank looks wrong, explain why in the report instead of overriding it silently.

6. **Look up ownership** only if the user wants to report abuse or is deciding on a block range. Run the IP WHOIS lookup for IPs ranked `critical` or `high`, up to 10 unless the user asks for more, and state the credit cost first. Save the raw responses to `work/raw/`, then write `work/ownership.json` in the format in `references/input-schema.md`: owner, network range, abuse contact and country, copied from the WHOIS fields listed there. Where the owner is a privacy service or a hosting reseller, say so in the `note` field, because the abuse report may need to go to the upstream provider. Then run the ranking again with `--ownership work/ownership.json` so the details sit beside each IP in `work/ranked.csv`.

7. **Report** using `assets/report-template.md`.

## What the agent does and does not decide

The scripts rank. The agent explains the ranking and turns it into recommendations the user can accept or reject:

- **Recommend an action** (block, watch, ignore or report) for each IP, following the script's priority and quoting the evidence. A recommendation is not a decision. Say what would change it.
- **Flag, do not judge, context the data cannot settle.** A hosting or cloud address may be a service the user runs or uses, but only the user knows. Name the organization and ask. Several IPs on one network may be a coordinated source or a shared gateway. Report the grouping as an observation and say the data cannot tell which.
- **Retry failed lookups** and mark the rest unchecked.

Never guess a value the tools did not return. Mark it unchecked.

## Interpreting results

- Judge activity from the `statuses` column, not the event count alone. Sixty events with all 401 responses are failed logins. Sixty events with 200 responses are normal traffic.
- A high threat score with high activity is the strongest combination. A high score with one event is a watch item, not a block.
- The threat score runs from 0 to 100. The vendor does not publish band meanings, so the cutoffs in `references/ranking.md` are this skill's defaults. State that in the report and let the user adjust them with `--high` and `--medium`.
- Cloud and hosting addresses are often scanners or compromised servers, and also often legitimate services. Check the organization.
- Corporate gateways, relays and carrier addresses are shared by many users. Do not recommend blocking them without saying so.
- Declared good bots, such as search engine crawlers, are not threats.
- A clean result means no known history, not safe.
- Location is approximate. Do not present it as where an attacker sits.

## Working with the APIFreaks MCP tools

- **Setup:** the tools need an `APIFREAKS_API_KEY` in the MCP client config. If a tool you need is not listed, its module is not enabled. Tell the user to add the module to `ENABLE_MODULES` and restart the client. Do not claim a capability is unavailable because a tool is missing. The `list_modules` tool shows what can be enabled.
- **Credits:** billing is per item, so batching does not save credits. Do not rely on remembered prices. Before a sizeable run, read the current credit costs for the calls you will make from https://apifreaks.com/llms-full.txt, multiply by the number of unique values, and tell the user the total. If the file cannot be fetched, say the cost is unknown and ask before a large run. The tools return no cost field, so mark actual spend as unverified. Failed calls are not billed.
- **Volume:** deduplicate first and drop values that cannot be looked up (malformed, empty, private or reserved). Call once per unique value, use bulk tools where they exist (batch sizes, page sizes, input rules and expiry times are in each tool's description, so read them there and do not rely on remembered limits), and run calls one at a time by default. On a rate limit error, slow down instead of retrying in parallel. Save raw results before transforming them.
- **Reading results:** a negative answer, such as an unregistered domain, is a successful call and not an error. Optional fields are often missing. A privacy service in an ownership field is a placeholder, not the owner. Results can be partial, so report what came back and what did not. Keep the queried value beside each result and mark empty rows instead of dropping them.
- **Failures:** read the error message and report it as written. Do not retry authentication failures. Never echo, hardcode or store the API key.

## Never

- Recommend blocking a shared gateway, relay or carrier address without naming the collateral risk.
- Block ranges on the evidence of a single address.
- Rank by country.
- Drop an IP from the output because its lookup failed. Keep the row and mark it unchecked.
- Present the score cutoffs as vendor definitions.
- Contact abuse desks or send anything yourself. List the contact and the evidence for the user.
- Echo or store the API key.
