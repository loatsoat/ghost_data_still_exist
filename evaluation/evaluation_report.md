# Evaluation Report

## Public-sample metrics

The evaluator was run against all 32 public examples and their supplied
expected outputs. These sample metrics describe only that set; they are not
full-dataset accuracy measurements.

| Set | Cases | Case-level status accuracy | Step precision | Step recall | Step F1 | Exact sequence |
|---|---:|---:|---:|---:|---:|---:|
| All public samples | 32 | 29/32 (90.6%) | 0.994 | 0.850 | 0.916 | 10/32 (31.2%) |
| Tuning split | 16 | 15/16 (93.8%) | 0.988 | 0.871 | 0.926 | 6/16 (37.5%) |
| Held-out split | 16 | 14/16 (87.5%) | 1.000 | 0.830 | 0.907 | 4/16 (25.0%) |

Step precision and recall match multiset step identities on phase, operation,
system, and resource. Matched-step field accuracy on the all-sample set was:

| Field | Correct / evaluated | Accuracy |
|---|---:|---:|
| State | 164/164 | 100.0% |
| Evidence ID | 164/164 | 100.0% |
| Step number | 118/164 | 72.0% |

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
155 `COMPLETE`, 344 `INCOMPLETE`, and 19 `NOT_APPLICABLE`. No authorized
row has empty `steps_json`. Compared with the `baseline` tag, 279 rows
differ.
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
- **Log-dialect trace linking:** 18 of 20 empty `INCOMPLETE` rows had log
  evidence naming the subject, on a result row or on the `*_started` row of
  the same trace id. Lambda, syslog, pipe, and bracket logs carry the trace id and event under
  different names or positions, so the result row never inherited the
  subject. Normalizing both, and reading restore-policy, restore-authorization,
  connector-config, and redacted-message results, resolved those 18 rows and
  changed 44 rows in total; public-sample metrics are unchanged.
- **Catalog-linked documents:** a `LINK_RESOURCE_IDENTITY` event names a
  resource, an alias (a file name, a statement number), and the subject. A
  screenshot or PDF captured between the request and the audit that shows the
  alias, or shows the subject inside the link's own system, is now evidence
  for that resource. This resolved the last two empty rows (`case_61`,
  `case_63`) and added one export finding and one tombstone verification.
  The link pattern previously missed 2 of 12 link events.
- **Screenshot attribution:** a console screenshot lists several people's
  rows, and proximity matching tied all of them to the subject. When the
  catalog names the subject's row, the other rows of that screenshot are
  dropped (5 cases). An event name read as a resource id
  (`account_closure_recorded`) and two OCR-damaged ids were also removed; one
  case changed from `INCOMPLETE` to `COMPLETE`.
- **Contact-index rows:** a `contact_query` or `contact_lookup` log result
  reads the contact index, so the row is a secondary identifier (always
  delete), not a support message (redact) or analytics profile (anonymize).
  This corrected two sample cases: precision 0.955 to 0.994, recall 0.777 to
  0.808, exact sequences 5 to 6 of 32. Nine full-dataset rows changed.
- **Retained records:** two causes hid policy-retained audit records. The
  log trace join ignored `subject_ref` and `match_key` on the `*_started`
  row, and a snapshot taken by `audit_at` but exported in a later bundle
  was discarded. Such a snapshot shows the state at `audit_at` but its file
  cannot be cited, so it now adds only uncited verification steps to an
  `INCOMPLETE` case, never a finding and never a step of a `COMPLETE` case.
  Eight sample steps were added, all correct: recall 0.808 to 0.850, exact
  sequences 6 to 10 of 32. 134 full-dataset rows gained steps; no status
  changed and no step cites a file captured after `audit_at`.
- **Self-describing manifest rows:** six JSON files hold rows that name
  their own `record_type`, `system` and `result` (an export manifest, an
  `operational_record_history` collection inside snapshot bundles, and two
  files whose names suggest a single category). Only the `USER_PROFILE`
  rows of the top-level files were read; 196 rows were dropped (162 search,
  audit, support, analytics, data-flow, backup, export and legal-hold rows,
  and 34 account rows inside bundles). All are now read through one
  path, and a bundle row keeps its file's capture time so a late export is
  never cited. Legal-hold records (`retained_order_records`, rule 13) were
  not recognised in any format and are now retained-and-verified. 46 rows
  changed; 11 cases reported `COMPLETE` on the account row alone while the
  same file showed a search document, support message or data flow still
  live at `audit_at`, and are now `INCOMPLETE`.
- **Redacted ticket read as exposed:** a `support_ticket_read_completed`
  log row with `requester_email=null` and only the stable reference was
  reported as exposed PII, because the literal `null` counted as a value.
  It is now `REDACTED`; 11 cases with that single false finding changed
  from `INCOMPLETE` to `COMPLETE`. Public-sample metrics are unchanged by
  both fixes: the samples contain neither pattern.
- **Coverage audit:** every record id written in each text evidence file
  was compared with the ids the parser indexed for that file. Three more
  gaps appeared. SQL inventory tables dropped the account-tombstone
  collection (8 tombstones, 4 still holding a name, email or phone) and the
  ticket-attachment collection (6). Log rows of the form `event=record_lookup
  ... record_type=... result=...` were read only for some categories; 23
  analytics, support, data-flow and backup rows were dropped. One legal-hold
  log result was not tied to the subject on its trace. All four are fixed;
  29 rows changed and 10 cases moved from `COMPLETE` to `INCOMPLETE`, each
  on a finding in a file captured by `audit_at`. After the fix the audit
  finds no unread id except decoys: 300 profile lookups for people with no
  request, one thumbnail error row, and two neighbours in a sample file.
  Public-sample metrics are unchanged.
- **Open items checked, no change made:** (1) Retention conditions: every
  `retention_until` and `retained_until` in the evidence falls in 2031-2034
  and every audit is in 2026, so the retain rules always apply. (2) Step
  numbers: matched steps are in the expected order (ordering 1.000); every
  wrong `step_no` is a shift caused by a missing earlier step. (3) Missing
  account-absent step: the account id appears only in a `DELETE_RECORD`
  activity row that names no subject. One sample file links a search
  document to its account through `source_resource_id`; that column exists
  in no other file and its subject is not in the 518 requests, so it was
  not built. Linking by id numbering or by event time stays rejected.
- **Final limitation review:** three public sample cases still have no
  participant-visible link to their absent account record and stay
  `INCOMPLETE` with no steps, rather than inventing evidence.

## Failures and improvements

| Failure found | Improvement |
|---|---|
| PDF and image evidence was not available to the original text-only parser. | Added local PDF extraction and OCR support. |
| SQL replica drift and active sync/restore processes could be missed. | Compared relevant snapshots and added grounded, time-bounded activity timelines. |
| Wrapper logs could hide the underlying service and explicit state. | Added a constrained recognized-system fallback with identity and cutoff checks. |
| Absence inferred from weak or unrelated evidence could falsely mark a case complete. | Kept a positive-evidence gate; only supported, cutoff-valid evidence drives findings and verification. |
| Result rows in four log dialects were not tied to the subject named on their trace. | Normalized trace id and event across dialects; empty `INCOMPLETE` rows fell from 20 to 2. |
| Resources named only by a catalog link event had no evidence attached. | Joined link events to screenshots and PDFs by alias, inside the request-to-audit window; empty `INCOMPLETE` rows fell from 2 to 0. |
| Console screenshots attributed other people's rows to the subject. | Kept only the row the catalog links to the subject; removed non-resource and OCR-damaged ids. |
| A failed validation left a broken `output.csv` in place. | Write to a temporary file, validate, then replace. |
| Manifest-style JSON rows other than account rows were ignored, and legal holds were unknown to the engine. | One reader for every self-describing row; legal-hold collection mapped to the retain rule; late bundles stay uncitable. |
| A log value of `null` was treated as a present identifier. | Null-cleaned the ticket fields; reference-only tickets are `REDACTED`. |
| Tombstones and ticket attachments in SQL inventory tables, and lookup rows in log form, were not read. | Mapped both collections and routed lookup log rows through the manifest reader; a per-file id coverage audit now shows no unread non-decoy id. |
