# ip-reputation-triage

Takes IPs from a SIEM alert, log or incident, enriches them with APIFreaks IP threat and geolocation data, and ranks them by how urgently an analyst should look. Built for the APIFreaks MCP server.

## Files

| Path | Purpose |
|---|---|
| `SKILL.md` | Instructions the agent follows |
| `references/ranking.md` | Ranking rules and cutoffs |
| `references/input-schema.md` | Formats of enrichment.json, ownership.json and the activity file |
| `scripts/prepare_ips.py` | Extracts, deduplicates and filters IPs, tallies events and status codes |
| `scripts/rank_ips.py` | Joins enrichment and activity (canonical addresses) and ranks |
| `assets/report-template.md` | Layout of the report |
| `examples/` | Sample log and live-like enrichment, plus clearly synthetic fixtures for edge cases |
| `evals/evals.json` | Test prompts with expected behavior |

## Requirements

- APIFreaks MCP server with the IP intelligence module enabled (WHOIS optional) and an `APIFREAKS_API_KEY`
- Python 3.8 or newer, standard library only

## Try the scripts

```
python scripts/prepare_ips.py examples/sample_access.log --out work/
python scripts/rank_ips.py examples/sample_enrichment.json --activity work/ips.csv --out work/ranked.csv
```

The sample is five public resolvers with low threat scores. Expect nothing above medium. 8.8.4.4 is medium only because it has 60 events, all 401 responses, and is cloud hosted. The IPv6 resolver is written in short form in the log and long form in the enrichment, and joins correctly.

`examples/fixture_synthetic.json` with `fixture_activity.csv` uses reserved 198.51.100.x addresses and invented values to exercise the critical, shared gateway, VPN and unchecked paths. It is not real data and must not be presented as a real incident.

## Notes

- An event is one log line or row that mentions the IP. It measures volume, not failures. The `statuses` column shows status codes when the input has them.
- **Prices are read at run time.** The skill does not store credit prices. The agent reads the current costs from https://apifreaks.com/llms-full.txt before a sizeable run. The MCP tools return no cost field, so actual spend cannot be verified and reports mark it as unverified.
- IPv4-mapped IPv6 addresses such as `::ffff:8.8.4.4` are read as the IPv4 address. An IP inside a request URL (for example `GET http://1.1.1.1/`) is also read as a source, so check the context. Text cells that start with `=`, `+`, `-` or `@` get a leading apostrophe in `ranked.csv`, and an unusable threat score (null, text, NaN, out of range) counts as unknown.
- Threat score cutoffs (70 high, 30 medium) are this skill's defaults. The vendor does not publish band meanings.
