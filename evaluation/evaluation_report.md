# Evaluation Report

## Public-sample metrics

The evaluator was run against all 32 public examples and their supplied
expected outputs. These sample metrics describe only that set; they are not
full-dataset accuracy measurements.

| Set | Cases | Case-level status accuracy | Step precision | Step recall | Step F1 | Exact sequence |
|---|---:|---:|---:|---:|---:|---:|
| All public samples | 32 | 29/32 (90.6%) | 0.955 | 0.777 | 0.857 | 5/32 (15.6%) |
| Tuning split | 16 | 15/16 (93.8%) | 0.987 | 0.806 | 0.888 | 3/16 (18.8%) |
| Held-out split | 16 | 14/16 (87.5%) | 0.926 | 0.750 | 0.829 | 2/16 (12.5%) |

Step precision and recall match multiset step identities on phase, operation,
system, and resource. Matched-step field accuracy on the all-sample set was:

| Field | Correct / evaluated | Accuracy |
|---|---:|---:|
| State | 150/150 | 100.0% |
| Evidence ID | 150/150 | 100.0% |
| Step number | 104/150 | 69.3% |

Matched-step ordering scored 1.000 using normalized Kendall tau. Exact
sequence accuracy is reported separately above.

## Participant-created evaluation cases

The classifier suite exercises 16 custom cases in
`code/evaluation/custom_cases/custom_cases.json`:

| Cases | Scenario | Expected behavior |
|---|---|---|
| custom_01–custom_04 | Access, correction, export, and marketing opt-out | `NOT_APPLICABLE` |
| custom_05–custom_06 | German deletion and French non-deletion | Deletion authorized; `NOT_APPLICABLE` |
| custom_07–custom_09 | Deletion wording includes analytics, export, or correction terms | Deletion authorized |
| custom_10 | Korean deletion request | Deletion authorized |
| custom_11 | Ambiguous complaint without deletion intent | `NOT_APPLICABLE` |
| custom_12 | Tombstone/redaction request | Deletion authorized |
| custom_13–custom_15 | Email change, login recovery, and invoice-copy requests | `NOT_APPLICABLE` |
| custom_16 | Deletion request with policy-required legal retention | Deletion authorized |

The classifier test command passed all 16 custom cases, along with the
previously misclassified public examples.

## Final full-dataset run

The locked full-dataset output contains one row for each of the 518 requests:
169 `COMPLETE`, 330 `INCOMPLETE`, and 19 `NOT_APPLICABLE`. Twenty
`INCOMPLETE` rows have empty `steps_json`; there are no empty `COMPLETE` rows.
Of the empty `INCOMPLETE` rows, 15 have only `*_started` traces and 5 have no
participant-visible identifier mention. Compared with the `baseline` tag, 41
rows changed: 10 in block 1, 2 in block 2, 6 in block 3, 1 in block 4, 18 in
block 5, and 4 in block 6.
These counts are output composition, not ground-truth accuracy: no full
evaluation labels are available in participant-facing data.

The sample metrics cannot validate the log-derived rows; the 32 public
samples do not contain those log formats.

## Log-parser rounds

- **Rounds A–C:** added local PDF/image extraction, fixed status-related
  evidence matching, and validated evaluation diagnostics.
- **Rounds D–E:** compared SQL replicas and reconstructed activity and
  restore timelines using identity-grounded links and audit-time cutoffs.
- **Rounds F–H:** rejected unsupported absence inference, retained the
  positive-evidence gate, and validated citations and output structure.
- **Operational-log parser:** added explicit-state parsing for an additional
  13 downstream-wrapper records, requiring a recognized same-row system,
  resource, resolved identity, and valid capture/record cutoffs. The change
  preserved tuning and held-out metrics and produced zero resource collisions.
- **Rejected suffix extrapolation:** numeric suffixes in identifiers were not
  accepted as identity links. The trial lacked a declared participant-visible
  link, reduced held-out step precision and F1, and changed 58 rows, so it was
  rejected and is not used in the final output.
- **Final limitation review:** retained unresolved cases when the only trace
  was `*_started` or no participant-visible identifier was present, rather
  than inventing evidence.

## Failures and improvements

| Failure found | Improvement |
|---|---|
| PDF and image evidence was not available to the original text-only parser. | Added local PDF extraction and OCR support. |
| SQL replica drift and active sync/restore processes could be missed. | Compared relevant snapshots and added grounded, time-bounded activity timelines. |
| Wrapper logs could hide the underlying service and explicit state. | Added a constrained recognized-system fallback with identity and cutoff checks. |
| Absence inferred from weak or unrelated evidence could falsely mark a case complete. | Kept a positive-evidence gate; only supported, cutoff-valid evidence drives findings and verification. |
| Some cases still have no usable state evidence. | Leave those cases `INCOMPLETE` with no fabricated steps and document the evidence gaps. |
