# Recording lookup results

`scripts/assemble.py` reads `lookups.json`. Store either the flat shape below or the tool's own JSON body. Keys are the values from `prepared.json` `to_lookup`, compared after removing spaces and uppercasing. Do not replace a key with a value the tool echoed back.

## File shape

```json
{
  "ibans": {
    "DE89370400440532013000": {
      "valid": true,
      "sepa": true,
      "bank_name": "Commerzbank",
      "bic": "COBADEFFXXX",
      "bank_code": null,
      "invalid_reason": null,
      "error": null
    }
  },
  "bics": {
    "DEUTDEFF": {
      "found": true,
      "bank_name": "DEUTSCHE BANK AG",
      "note": null,
      "error": null
    }
  }
}
```

## IBAN tool: `financial_iban_validate`

Pass `iban`. A structurally invalid IBAN is still a normal result (`valid: false`), not a failed call. Map the body like this, or paste the body in unchanged:

| `lookups.json` | Tool field |
|---|---|
| `valid` | `valid` |
| `sepa` | `bank_data.sepa` |
| `bank_name` | `bank_data.bank` |
| `bic` | `bank_data.bic` |
| `bank_code` | `bank_data.bank_code` |
| `invalid_reason` | A short sentence from the `validation` flags that are false, only when `valid` is false |

`bank_data.sepa` means the IBAN's country is in SEPA. It does not mean this account can receive a transfer. A published UAE example comes back `false`. Germany, the UK, Switzerland and Norway come back `true`.

`bank_data` is often filled even when `valid` is false. `valid: false` wins. Do not treat that bank block as a pass.

`validation.bban` of `unknown` means that country has no national checksum. `bban` of `invalid` while `valid` is true must not be turned into a rejection: the registry's French example comes back that way and its national key is in fact correct. Use `bban` only to explain a row that is already `valid: false`.

`bank_data.bic` is often a branch. The published UK example returns `NWBKGB2141R` while the head office is `NWBKGB2L`. The script compares the four-letter institution only. A `bank_code` made of digits is a national clearing number, not a BIC. Leave a missing field null. Do not fill it from memory.

A Swiss or Liechtenstein QR-IBAN (IID 30000–31999) comes back `valid: true`. The script flags it. Do not clear that flag.

## BIC tool: `financial_swift_lookup`

Pass `swift_code`. A 200 body looks like this:

| `lookups.json` | Tool field |
|---|---|
| `found` | `true` |
| `bank_name` | `bankName` |

An 8-character code is returned padded to 11 with `XXX` (`DEUTDEFF` comes back as `DEUTDEFFXXX`). Keep the key you sent.

An unknown code is not a 200. The tool errors with text that contains `404` and `No bank found with the provided SWIFT code`. Record that as `found: false` and leave `error` null. The script also treats that text as not-found if it lands in `error`.

For an 11-character code that is not found, and whose last three characters are not `XXX`, retry once with the first 8. If the primary office exists, still record `found: false` under the original 11-character key, and set `note` to say the primary office is listed. Do not record the primary hit as `found: true`. That would hide a branch the directory does not have.

## What counts as `error`

Set `error` only when the call failed: timeout, rate limit, or a server failure. Leave `valid` and `found` out in that case.

Do not retry an authentication or credits problem. Stop and tell the user.

A failed call is never treated as valid or invalid. Rows with an `error`, or with no usable entry, are `LOOKUP_FAILED` for review.
