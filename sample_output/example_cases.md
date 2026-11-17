# Example cases

Three cases taken from a full run (`python code/main.py`), one per outcome.
All people, identifiers and records in the challenge dataset are fictional;
request emails are omitted. The complete result for all 518 cases is
[`../output.csv`](../output.csv) and the console log is [`run_console.txt`](run_console.txt).

## case_33: INCOMPLETE

> Please close my account and process the associated personal-data deletion. Please handle any copies that fall within the scope of the deletion request. Please confirm when the review is complete.

Workflow claimed: `COMPLETE` · audit cutoff: `2026-07-19T13:00:00Z`

The workflow reported **COMPLETE**, but the audit disagrees.

| # | Phase | System | Resource | Operation | State | Evidence |
|---|---|---|---|---|---|---|
| 1 | FINDING | export_service | export_1260 | `REPORT_REMAINING_RECORD` | PRESENT | evidence_23 |
| 2 | FINDING | export_service | export_1842 | `REPORT_REMAINING_RECORD` | PRESENT | evidence_18 |
| 3 | REMEDIATION | export_service | export_1260 | `DELETE_RECORD` | ABSENT |  |
| 4 | REMEDIATION | export_service | export_1842 | `DELETE_RECORD` | ABSENT |  |
| 5 | VERIFICATION | export_service | export_1260 | `VERIFY_RECORD_ABSENT` | ABSENT |  |
| 6 | VERIFICATION | export_service | export_1842 | `VERIFY_RECORD_ABSENT` | ABSENT |  |

## case_46: COMPLETE

> I am requesting deletion of the account registered to this email address. Please follow the applicable retention and deletion requirements for the account. I would appreciate confirmation of the final outcome.

Workflow claimed: `COMPLETE` · audit cutoff: `2026-03-11T08:00:00Z`

Nothing is left to fix, so every step is a verification backed by cited evidence.

| # | Phase | System | Resource | Operation | State | Evidence |
|---|---|---|---|---|---|---|
| 1 | VERIFICATION | account_service | account_6523 | `VERIFY_RECORD_ABSENT` | ABSENT | evidence_67 |
| 2 | VERIFICATION | identity_service | tombstone_17 | `VERIFY_RECORD_REDACTED` | REDACTED | evidence_42 |

## case_539: NOT_APPLICABLE

> Can you tell me what personal information you hold about me? This is an information request, not a request to erase it.

Workflow claimed: `NOT_STARTED` · audit cutoff: `2026-09-25T12:00:00Z`

Not a deletion request, so no audit is run.

`steps_json`: `[]`
