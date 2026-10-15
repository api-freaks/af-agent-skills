# Reporting

Two artifacts. The dataset is the audit trail, the report is what gets read.

## The dataset

One file, one row per unique indicator, written to a path the user can find.
CSV unless they ask otherwise.

Rules:

- **The queried value is the first column**, so every row maps back to the input.
- **One row per unique indicator**, not per log line.
- **Rows that returned nothing stay in the file**, marked. An absent record and a
  failed lookup mean different things, and both look like an empty cell. Use
  distinct markers for: not found, lookup failed, filtered before enrichment, and
  field absent from an otherwise successful response.
- **Column names come from the response schema**, not from invented labels. A
  reader needs to be able to trace a column back to the field that produced it.
- **Keep the raw responses** in a sibling directory. If the dataset needs
  reshaping later, that is a re-read rather than a re-run.

## The report

Lead with what changes a decision. Volume and concentration usually matter more
than any single flagged address.

```markdown
# Log enrichment: [source file], [date range in the log]

## Summary

[Three or four sentences. Lines read, unique indicators found, what was
enriched, credits spent, and the one or two things worth acting on.]

## Scope and filters

| Class | Found | Enriched | Filtered | Reason |

[One line naming anything that was excluded by a judgment call rather than a
rule, so the reader can overrule it.]

## Traffic concentration

[Top sources by request volume, with network operator and location. Include the
share of total traffic each represents. This is the section that is useful even
when nothing is flagged.]

## Automated versus human traffic

[Split by user agent, with the largest automated sources named. Separate
identified crawlers from unidentified automation, since they call for different
responses.]

## Flagged for review

| Indicator | Requests | Signals that fired | Network | Confidence notes |

[One row per item, with the specific fields that fired. Ordered by a stated
criterion, usually volume rather than score, since a high score on two requests
matters less than a moderate score on fifty thousand.]

## Not resolved

[Indicators that failed lookup or returned nothing, with counts and the reason.
Never omit this section, even when it is empty.]

## Cost

[Credits spent per tool and in total, from what the tools reported rather than
the estimate. If a tool reported no cost, say the spend is unverified.]
```

## Wording a finding

- **Report the signal, not a verdict.** "Flagged as a Tor exit node, threat score
  in the high range, 4,812 requests, all to one path" is a finding. "Malicious
  attacker" is not, and the response does not support it.
- **Name the source of every claim.** A field from an enrichment response, a count
  from the log, and your own inference are three different things and should read
  differently. Mark inference as inference.
- **Qualify anything resting on the forwarded chain**, since it is client
  controlled and may be forged.
- **Carry false positive context into the row**, not into a footnote. Cloud and
  hosting ranges, shared carrier ranges, and search engine crawlers all trip
  automation and anonymity signals in normal operation. A reader scanning the
  table should see that on the row.
- **Do not infer a person.** An address is not a user, a country is not an
  intent, and an organisation on a network record is the operator of the network,
  not the sender of the request.
- **Say when the data does not support an answer.** A log with no forwarded chain
  behind a proxy cannot tell you who the clients were. Say that, rather than
  reporting on the proxy.

## What not to produce

- A block list, deny rule, firewall command, or anything else formatted to be
  executed. Candidates with evidence, for a human to action.
- A severity or risk rating of your own invention layered on top of the returned
  scores.
- A finding for every enriched row. Most rows are ordinary traffic and belong in
  the dataset, not the report.
