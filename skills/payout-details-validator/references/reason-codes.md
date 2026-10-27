# Reason codes

A row is **rejected** if any of its codes is a rejection code, **needs review** if it only has review codes, and **clean** if it has none. Clean requires an IBAN that passed the local checks and the lookup. Every review and rejected row carries its codes in `reason_codes` and a plain sentence in `explanation`.

Rejected rows should not be paid until corrected. Review rows might be fine: a person has to look.

## Rejection codes

| Code | Meaning | Usual action |
|---|---|---|
| `MISSING_FIELD` | No IBAN, account number or BIC on the row. | Get the details from the payee. |
| `IBAN_BAD_FORMAT` | Wrong length, characters or national structure for that country. The explanation says which. | Check for truncation or a pasted account number. |
| `IBAN_BAD_CHECKSUM` | The structure is plausible but the check digits fail, which means a typo or transposed digits. | Re-collect the IBAN. A note may offer one guess. It is not a correction. |
| `IBAN_INVALID` | The IBAN tool returns `valid: false`. The explanation carries the tool's reason. | Re-collect the IBAN. |

## Review codes

| Code | Meaning | Usual action |
|---|---|---|
| `BIC_BAD_FORMAT` | The BIC is not 8 or 11 characters in the BIC layout. | Fix or remove it. For SEPA payments the BIC is often optional. |
| `BIC_NOT_FOUND` | A well formed BIC the directory does not know. A note may say the 8-character primary office does exist. | Check for a typo, or confirm with the bank. |
| `COUNTRY_MISMATCH` | The country inside the BIC differs from the IBAN country. | Confirm which of the two is right. |
| `BANK_MISMATCH` | The institution code derived from the IBAN differs from the BIC's first four letters. Branch codes are not compared. | Confirm the bank with the payee. |
| `NON_SEPA` | The IBAN's country is outside SEPA. Only raised in SEPA run mode, otherwise it is a note. This is the country, not proof the account can or cannot be paid. | Use another payment rail. |
| `QR_IBAN` | A Swiss or Liechtenstein QR-IBAN (IID 30000–31999). It is a valid IBAN and cannot receive a normal credit transfer. The lookup does not flag this. | Use a standard IBAN for the payout. |
| `DUPLICATE_ROW` | Same payee and same account on more than one row. | Make sure the payee is not paid twice. |
| `DUPLICATE_IBAN` | One IBAN under several payee names. Can be a shared account, and is also a classic fraud signal. | Confirm the names belong to the same account holder, through a known channel. |
| `MULTIPLE_IBANS_PER_PAYEE` | One payee name with several IBANs in this file. | Confirm which account should be paid. |
| `IBAN_CHANGED` | The same payee name has a different IBAN than in the baseline file. "Acme Ltd" and "Acme Limited" are not matched. | Confirm the change with the payee through a known channel. |
| `NOTHING_TO_VERIFY` | No IBAN, and either only an account number or only a BIC. | Ask for an IBAN, or verify outside this skill. |
| `ACCOUNT_UNCHECKED` | An account number and a BIC, but no IBAN. The account number was not checked. | Do not pay from this row until the account is verified another way. |
| `LOOKUP_FAILED` | A lookup errored, or no usable result was recorded. The data may be fine. | Re-run the lookups for the affected rows. |

## Notes (not reason codes)

The `notes` column does not change the status. It carries:

- Spaces, dots, hyphens or lowercase removed for the check. The original cell is unchanged.
- A single transposition or O/0, I/1, B/8 swap that would pass. One candidate only. It is a guess.
- A BIC country that belongs with the IBAN: French territories (`GF`, `GP`, `MQ`, `RE`, `PF`, `TF`, `YT`, `NC`, `BL`, `MF`, `PM`, `WF`) on an `FR` IBAN, and Guernsey, Jersey or the Isle of Man (`GG`, `JE`, `IM`) on a `GB` IBAN.
- "IBAN country is outside SEPA" when SEPA run mode is off.
- An Excel cell that was stored as a number, so leading zeros may already be gone.
- The primary office, when an 11-character branch BIC was not listed.

## The `checks_performed` column

What actually ran for the row: `iban-format` (the shape failed), `iban-checksum` (the shape passed and the checksum was tested), `iban-lookup`, `bic-format`, `bic-lookup`, `iban-vs-bic`, `duplicates`. A checksum failure is `iban-checksum`, not `iban-format`.
