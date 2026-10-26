# Examples

## Real-looking run: `sample_access.log` and `sample_enrichment.json`

The log holds well-known public resolvers plus private and documentation addresses. `sample_enrichment.json` mirrors what the live lookups returned for those resolvers: every threat score is 5 and no anonymizer or bot flags are set. The IPv6 resolver is written in its long form, as the bulk tools returned it, to exercise the address matching.

```
python scripts/prepare_ips.py examples/sample_access.log --out work/
python scripts/rank_ips.py examples/sample_enrichment.json --activity work/ips.csv --out work/ranked.csv
```

Expected: five public IPs, nothing above `medium`, and `8.8.4.4` at `medium` only because it has 60 events. Private and documentation addresses are dropped and counted. No block is recommended. If this run shows a `critical` finding, something is wrong.

## Script test fixture: `fixture_synthetic.json` and `fixture_activity.csv`

**Invented data. Do not present it as a real finding.** It uses reserved documentation addresses and made-up flags so every branch of the ranking can be seen: a critical bot, a shared gateway, a VPN, and a failed lookup that stays `unchecked`.

```
python scripts/rank_ips.py examples/fixture_synthetic.json --activity examples/fixture_activity.csv --out work/fixture_ranked.csv
```

## Edge cases: `sample_edge.log` and `fixture_bad_values.json`

**Invented data.** `sample_edge.log` has addresses with ports, labels glued to an address (`client:4.4.4.4`), a mapped address with a port and a version string that is not an IP. Expect six public IPs and zero unparseable values. `fixture_bad_values.json` has unusable threat scores (null, text, NaN, Infinity, 150), a record with `ok` set to the string `false`, an anonymizer-only record and cells that start with `=` or `@`.

```
python scripts/prepare_ips.py examples/sample_edge.log --out work/edge/
python scripts/rank_ips.py examples/fixture_bad_values.json --out work/bad_ranked.csv
```
