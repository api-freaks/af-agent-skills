# IP reputation triage: <incident or source name>

Date: <date>
Input: <file or description>, <unique IPs kept> kept, <dropped> dropped, <failed> lookups failed
Cutoffs used: threat score high <n>, medium <n> (skill defaults unless changed); activity high <n>, medium <n> events

## Summary

<Two or three sentences: what was reviewed, how many fall in each priority, the main finding.>

| Priority | IPs |
|---|---|
| critical | <n> |
| high | <n> |
| medium | <n> |
| low | <n> |
| unchecked | <n> |

## Top candidates

For each critical or high IP, defanged:

- **<ip with dots as [.]>** (<priority>): threat score <n>, <flags>, <country>, <network and organization>, <events> events (<statuses, e.g. 401:60>) from <first_seen> to <last_seen>. <One sentence on why it matters and any caution, such as shared gateway or cloud hosted.>

## Patterns

<Network owners behind several IPs, cloud ranges, anonymizer use, one target path or account hit repeatedly. Write "none noted" if nothing stands out.>

## Recommended actions

- **Block candidates:** <ips, with expiry suggestion>
- **Watch:** <ips, with expiry suggestion>
- **Report to network owner:** <for each IP: owner, network range, abuse contact, any note such as reseller or upstream provider, and the evidence to attach. Only for IPs where ownership was looked up.>
- **Retry or check manually:** <unchecked ips and why>

## Limits

- Threat score cutoffs are defaults chosen for this skill, not vendor definitions.
- Location is approximate.
- A clean result means no known history.
- <Any lookups that failed or fields that were not returned.>

Full ranked table: `<path to ranked.csv>`
