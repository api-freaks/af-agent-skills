# Reporting

Two artifacts. The dataset is the audit trail, the report is what gets read.

## The dataset

One file, one row per unique indicator, written to a path the user can find.
CSV unless they ask otherwise.

Rules:

- **The queried value is the first column**, so every row maps back to the input.
- **One row per unique indicator**, not per log line.
- **Rows that returned nothing stay in the file**, marked in an
  `enrichment_status` column: `enriched`, `not_found`, `lookup_failed`,
  `filtered_<reason>`, `not_looked_up`, or `local_only` when no lookups were run. An absent record and a failed lookup
  mean different things, so never leave both as a blank row. An empty cell in an
  enriched row means that field was absent from that response, and the dataset
  summary counts those per column.
- **Column names come from the response schema**, not from invented labels. A
  reader needs to be able to trace a column back to the field that produced it.
- **Write it with `scripts/build_dataset.py`.** It enforces the first column, the
  status markers, and the spreadsheet prefix (a leading quote when the first
  visible character could start a formula), and its summary supplies the exact
  counts the report needs. For a group-by, `share_of_grouped_requests` is the
  share among the rows that were totaled and `share_of_listed_requests` is the
  share of every row in the dataset.
- **Keep the raw responses** in a sibling directory. If the dataset needs
  reshaping later, that is a re-read rather than a re-run.

## The report

Lead with what changes a decision. Volume and concentration usually matter more
than any single flagged address.

Use the template in [../assets/report-template.md](../assets/report-template.md).

## Wording a finding

- **Report the signal, not a verdict.** "Flagged as a Tor exit node, threat score
  in the high range, 4,812 requests, all to one path" is a finding. "Malicious
  attacker" is not, and the response does not support it.
- **Back each flagged address with its log evidence**: requests, status mix,
  busiest second, and path shapes from `scripts/ip_evidence.py`.
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

## A local-only report

When no lookups were run, keep the same template but drop what needs them. Say in
the summary that no lookups were run. Keep scope and filters, traffic
concentration by request volume, flagged addresses backed by log evidence, not
resolved, and cost (zero). Leave out network, country, hosting type, and
reputation, and leave out the automated versus human split unless it rests on what
a user agent string claims about itself, labelled that way.
