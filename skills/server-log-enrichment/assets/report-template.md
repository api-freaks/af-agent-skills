# Log enrichment: [source file], [date range in the log]

## Summary

[Three or four sentences. Lines read, unique indicators found, what was
enriched, estimated credits, and the one or two things worth acting on.]

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

[Estimated credits per tool and in total, from the published table. The MCP tools
report no cost, so say that actual spend is unverified.]
