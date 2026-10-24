# Evaluation Report

## Baseline

Split: tuning=['case_01', 'case_03', 'case_05', 'case_07', 'case_09', 'case_11', 'case_13', 'case_15', 'case_17', 'case_19', 'case_21', 'case_23', 'case_25', 'case_27', 'case_29', 'case_31'], held-out=['case_02', 'case_04', 'case_06', 'case_08', 'case_10', 'case_12', 'case_14', 'case_16', 'case_18', 'case_20', 'case_22', 'case_24', 'case_26', 'case_28', 'case_30', 'case_32']


| Set | Status Acc | Precision | Recall | F1 | Exact Seq | Ordering |
|-----|-----------|-----------|--------|-----|-----------|----------|
| All-32 | 0.906 | 0.955 | 0.777 | 0.857 | 0.156 | 1.000 |
| Tuning | 0.938 | 0.987 | 0.806 | 0.888 | 0.188 | 1.000 |
| Held-out | 0.875 | 0.926 | 0.750 | 0.829 | 0.125 | 1.000 |

## Field and Status-Class Metrics

| Set | COMPLETE Acc | INCOMPLETE Acc | NOT_APPLICABLE Acc | State | Evidence ID | Step No |
|-----|--------------|----------------|--------------------|-------|-------------|---------|
| All-32 | 0.700 | 1.000 | n/a | 1.000 | 1.000 | 0.693 |
| Tuning | 0.833 | 1.000 | n/a | 1.000 | 1.000 | 0.733 |
| Held-out | 0.500 | 1.000 | n/a | 1.000 | 1.000 | 0.653 |

## Status Confusion Matrices

Rows are expected statuses; columns are predicted statuses.

### All-32
| Expected \ Predicted | COMPLETE | INCOMPLETE | NOT_APPLICABLE | MISSING |
|---|---:|---:|---:|---:|
| COMPLETE | 7 | 3 | 0 | 0 |
| INCOMPLETE | 0 | 22 | 0 | 0 |
| NOT_APPLICABLE | 0 | 0 | 0 | 0 |
### Tuning
| Expected \ Predicted | COMPLETE | INCOMPLETE | NOT_APPLICABLE | MISSING |
|---|---:|---:|---:|---:|
| COMPLETE | 5 | 1 | 0 | 0 |
| INCOMPLETE | 0 | 10 | 0 | 0 |
| NOT_APPLICABLE | 0 | 0 | 0 | 0 |
### Held-out
| Expected \ Predicted | COMPLETE | INCOMPLETE | NOT_APPLICABLE | MISSING |
|---|---:|---:|---:|---:|
| COMPLETE | 2 | 2 | 0 | 0 |
| INCOMPLETE | 0 | 12 | 0 | 0 |
| NOT_APPLICABLE | 0 | 0 | 0 | 0 |

## Custom Evaluation Cases

| ID | Scenario | Expected behavior |
|----|----------|-------------------|
| custom_01 | Access request | NOT_APPLICABLE |
| custom_02 | Correction request | NOT_APPLICABLE |
| custom_03 | Export/data portability | NOT_APPLICABLE |
| custom_04 | Marketing opt-out | NOT_APPLICABLE |
| custom_05 | German deletion request | Deletion authorized |
| custom_06 | French access request | NOT_APPLICABLE |
| custom_07 | Deletion with anonymous analytics wording | Deletion authorized |
| custom_08 | Deletion mentioning a prior export | Deletion authorized |
| custom_09 | Deletion mentioning correction | Deletion authorized |
| custom_10 | Korean deletion request | Deletion authorized |
| custom_11 | Complaint without deletion | NOT_APPLICABLE |
| custom_12 | Tombstone/redaction request | Deletion authorized |
| custom_13 | SQL replica drift | Present replica drives an incomplete audit |
| custom_14 | Active data flow | Active flow requires disable and verification |
| custom_15 | Restore risk | Restorable backup requires block and verification |
| custom_16 | Account tombstone | Direct identifiers require redaction, stable reference retained |

Definitions for custom_01–custom_12 are in `code/evaluation/custom_cases/custom_cases.json`; custom_13–custom_16 are exercised by the corresponding evidence fixtures and Step D/E reports.


## Failures and Fixes

| Stage | Failure | General fix | Metric change |
|-------|---------|--------------|----------------|
| Baseline | Missing replica, JSON, log, PDF/image records | Generalized evidence parsing and OCR | Status 56.2% -> 75.0% |
| Step B | Active backups/flows treated as compliant; tombstone unmapped; timestamp confusion | State/linking and capture-time fixes | Status 75.0% -> 100.0%; F1 0.697 -> 0.769 |
| Step F | Empty COMPLETE for no-match cases | Strict positive-evidence gate | Status 100.0% -> 90.6%; evidence contract preserved |
| Step G | Snapshot omission rule could convert activity claims into identity links | Rejected unsupported derivation | No metric change |
| Step H | OCR connector state yielded empty COMPLETE | General connector state extraction and validator hardening | Empty COMPLETE count 1 -> 0 |

## Option Tournament

The current implementation was captured as the `baseline` tag before testing the
options. Each option was evaluated from that baseline on the fixed tuning split,
with the held-out split used only for qualification.

| Option | Tuning score | Held-out score | Constraint result | Decision |
|--------|--------------|----------------|-------------------|----------|
| Baseline | 0.913 | 0.852 | Fails zero-empty-INCOMPLETE constraint: 57 | Retained |
| A: absence rule | 0.913 | 0.852 | Not derivable; no user-grounded resource and fails zero-empty-INCOMPLETE | Dropped |
| B: coverage | 0.913 | 0.852 | No evidence-safe generic parser/linking fix; fails zero-empty-INCOMPLETE | Dropped |
| C: ordering | 0.913 | 0.852 | No ordering-only multiset matches; fails zero-empty-INCOMPLETE | Dropped |

Scores are `0.5 * F1 + 0.5 * status_accuracy`. Baseline tuning is
`0.5 * 0.888 + 0.5 * 0.938 = 0.913`; held-out is
`0.5 * 0.829 + 0.5 * 0.875 = 0.852`.

### Option A investigation

The three public cases whose expected output contains only unsupported absence
verification are selected dynamically as expected COMPLETE cases with no
matched record. Their expected evidence is `evidence_54` for the account
resource, and `evidence_56` for the analytics resource in the applicable case.
The failover snapshot is captured before the relevant audit cutoff and does
contain the account table, but the absent resource IDs are not present in the
snapshot and are not connected to the requester by a user ID, email, phone, or
hash. The analytics record has a null identity. The only resource grounding is
an activity claim, which is not absence proof. The proposed rule was therefore
not derivable from participant-visible evidence and was not implemented.

### Option B investigation

The data-derived miss table reported 38 parsing-or-linking differences and 12
rule differences. The largest group includes resource IDs appearing in
activity claims or unsupported sample expectations without a grounded
requester link; converting those claims into evidence-backed records would
violate the evidence rules. No parser change was retained.

### Option C investigation

No public sample had an identity-step multiset that matched exactly while only
the order differed. Consequently, no alternative ordering rule could be
validated on tuning without guessing from mismatched or unsupported steps.

## Final Tournament Housekeeping

- Full output: 518 rows, sorted by `case_id`.
- Status mix: 159 COMPLETE, 340 INCOMPLETE, 19 NOT_APPLICABLE.
- Empty COMPLETE rows: 0.
- Empty INCOMPLETE rows: 57.
- Recomputed no-match population: 57 authorized deletion requests with no
  matched evidence record or grounded activity finding.
- The positive-evidence gate remains enabled.
- No option was merged because none satisfied all hard constraints.
