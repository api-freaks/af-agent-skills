# Ranking rules

`scripts/rank_ips.py` applies these rules. This file explains them so the report can justify each rank.

## Threat score

The threat score is an integer from 0 to 100. The vendor does not publish band meanings. These cutoffs are defaults chosen for this skill, and the user can change them:

| Setting | Default | Meaning |
|---|---|---|
| `--high` | 70 | Score at or above this is high reputation risk |
| `--medium` | 30 | Score at or above this is medium reputation risk |

Say in the report that the cutoffs are skill defaults.

## Reputation

Evaluated in this order. The first match wins.

1. **unknown:** no enrichment data for the IP, the lookup failed, or the record has no usable threat score and no reputation flags
2. **low (declared good bot):** `is_known_good_bot` is true and `is_known_attacker` is false
3. **high:** any of: score at or above the high cutoff, `is_tor`, `is_known_attacker`, or an undeclared bot (`is_bot` true and `is_known_good_bot` false)
4. **medium:** any of: score at or above the medium cutoff, `is_vpn`, `is_proxy`, `is_residential_proxy`, `is_spam`, or `is_anonymous`
5. **low:** everything else

`is_cloud_provider` and `is_relay` do not change reputation by themselves. They add notes.

## Activity

From the user's data, using event counts per IP:

| Setting | Default | Meaning |
|---|---|---|
| `--act-high` | 50 | Events at or above this is high activity |
| `--act-medium` | 5 | Events at or above this is medium activity |

Fewer events is low activity. Events are volume only, so read the `statuses` column in the ranked CSV to see whether they were failures. If no activity data was supplied, activity is unknown.

## Priority matrix

| Reputation \ Activity | high | medium | low | unknown |
|---|---|---|---|---|
| high | critical | high | medium | high |
| medium | high | medium | low | medium |
| low | medium | low | low | low |
| unknown | unchecked | unchecked | unchecked | unchecked |

## Notes the script adds

- **shared gateway risk:** `is_corporate_gateway` or `is_relay` is true. Blocking may affect many users.
- **cloud hosted:** `is_cloud_provider` is true. Check whether it is a service the user runs or uses.
- **declared good bot:** `is_known_good_bot` is true.
- **lookup failed:** no enrichment data.

## Action guidance

- `critical` and `high`: block candidates, after the shared gateway check.
- `medium`: watch list. Suggest an expiry date, since addresses get reassigned.
- `low`: no action.
- `unchecked`: the lookup failed or returned nothing, whatever the activity. Retry it before deciding. Never read it as clean. List these IPs with their event counts in the report so a busy one is not missed.
- When many addresses share a network owner, mention it and leave range actions to the user.
- For confirmed abuse, name the network owner and the WHOIS abuse contact, and give the user the evidence to send.
