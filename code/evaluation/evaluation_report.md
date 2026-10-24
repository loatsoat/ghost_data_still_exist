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


## Final Full-Dataset Results

The deterministic offline run produced 518 rows: 169 COMPLETE, 330 INCOMPLETE, and 19 NOT_APPLICABLE. It has 20 empty INCOMPLETE rows (15 with only *_started traces and 5 with no participant-visible mention) and zero empty COMPLETE rows.


The sample metrics cannot validate the log-derived rows because the 32 public samples do not contain those log formats.


Compared with the baseline tag, 41 rows changed: 10 in block 1, 2 in block 2, 6 in block 3, 1 in block 4, 18 in block 5, and 4 in block 6.


## Failures and Fixes

| Stage | Failure | General fix | Metric change |

|-------|---------|--------------|----------------|

| Operational evidence | Wrapper logs hid the service in a same-row system field | Recognized-system fallback with identity and cutoff gates | Held-out metrics unchanged |

| Evidence contract | Unsupported absence derivations risked empty COMPLETE | Positive-evidence gate | Zero empty COMPLETE rows |

| Remaining gaps | Some traces contain only *_started rows or no mention | Keep unresolved cases INCOMPLETE; do not invent evidence | 20 empty INCOMPLETE rows |
