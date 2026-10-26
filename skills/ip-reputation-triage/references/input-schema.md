# Enrichment file format

`scripts/rank_ips.py` reads `work/enrichment.json`: a JSON array with one object per unique IP. The agent builds it by copying fields from the raw tool responses. It never changes values.

## Fields

```json
[
  {
    "ip": "203.0.113.7",
    "ok": true,
    "threat_score": 82,
    "is_tor": false,
    "is_proxy": true,
    "is_residential_proxy": false,
    "is_vpn": false,
    "is_relay": false,
    "is_anonymous": true,
    "is_known_attacker": false,
    "is_bot": true,
    "is_known_good_bot": false,
    "bot_type": "brute_force",
    "is_spam": false,
    "is_cloud_provider": true,
    "cloud_provider_name": "Example Hosting",
    "is_corporate_gateway": false,
    "country": "Germany",
    "network": "AS64500",
    "organization": "Example Hosting GmbH",
    "error": ""
  }
]
```

## Rules

- `ip` is required. Every other field is optional.
- Missing booleans count as false. A missing `threat_score` counts as not scored.
- Set `ok` to false and fill `error` when a lookup failed. The script then ranks the IP as unknown reputation.
- If the threat tool returns the nested form `{"ip": "...", "security": {...}}`, the script accepts it as is. The agent can append `country`, `network` and `organization` from the geolocation response beside it.
- Copy `country`, `network` and `organization` as text from the geolocation response. If a value was not returned, leave it out.
- Do not add fields the tools did not return.
- Field names above match the IP security response. If the MCP tool names a field differently, copy the value under the name shown here.

## Where each value comes from

| Our field | Source in the tool response |
|---|---|
| `threat_score`, `is_*` flags, `bot_type`, `cloud_provider_name` | the `security` object of the IP threat lookup |
| `country` | `location.country_name` of the IP geolocation lookup |
| `network` | `asn.as_number` |
| `organization` | `asn.organization` (fall back to `company.name`) |

The threat score is an integer from 0 to 100. The IP threat lookup returns an error for private or reserved addresses, which is why `prepare_ips.py` removes them first.

## Activity file

`work/ips.csv` from `prepare_ips.py` has the columns `ip, events, first_seen, last_seen, statuses`. `events` counts lines or rows that mention the IP, which is volume only. `statuses` is a tally such as `401:60 200:2` and is empty when the input had no status codes. Pass it with `--activity`. Without it, activity is unknown for every IP.

## Ownership file

`work/ownership.json` is optional. It holds WHOIS results for the top candidates only. Pass it with `--ownership`. It is a JSON array, one object per IP:

```json
[
  {
    "ip": "203.0.113.7",
    "owner": "Example Hosting GmbH",
    "network_range": "203.0.113.0/24",
    "abuse_contact": "abuse@example.net",
    "country": "DE",
    "note": "hosting provider, may be a reseller"
  }
]
```

- Copy values as the WHOIS response returns them. Leave out any field it did not return.
- Sources in the IP WHOIS response: `owner` from `organization.name`, `network_range` from the first entry of `inet_nums[].cidr` (or `start_ip` to `end_ip` if no CIDR), `abuse_contact` from `abuse_contacts[].email` (a list, join with commas), `country` from `organization.country` (a list). If there are no abuse contacts, leave `abuse_contact` out and say so in `note`.
- Use `note` for caveats: a privacy service in place of an owner, a reseller, or an upstream provider that should receive the report.
- IPs not listed get blank ownership columns. That is normal, because only the top candidates are looked up.
