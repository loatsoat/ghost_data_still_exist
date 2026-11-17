# Ghost Data Still Exists

Deterministic offline pipeline that audits whether deleted user data actually disappeared from every system — built for GDPR/right-to-be-forgotten compliance.

![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![License: MIT](https://img.shields.io/badge/license-MIT-green)
![Network calls](https://img.shields.io/badge/network%20calls-0-lightgrey)

## Why this exists

Companies tell users "your data has been deleted", and the deletion workflow
says *Complete*. In practice, fragments survive in database replicas, service
logs, support attachments, analytics profiles, exports and backups, and a
running sync or a backup restore can quietly bring them back. This pipeline
checks the actual evidence instead of trusting the workflow status, finds those
ghosts, and writes the ordered steps needed to remove them safely.

Built for the HackerRank Orchestrate challenge
[*Ghost Data Still Exists*](https://www.hackerrank.com/contests/hackerrank-orchestrate-october26/challenges/ghost-data-still-exists)
(October 2026), using its fictional commerce-platform dataset.

## How it works

```
deletion requests ─► 1. load ─► 2. classify ─► 3. resolve identity ─► 4. parse evidence ─► 5. link activity ─► 6. audit ─► output.csv
                                    │
                                    └─ not a deletion request ─► NOT_APPLICABLE
```

1. **Load requests**: read the requests, identity snapshot, identity history,
   system activity stream, deletion policy and evidence manifest.
2. **Classify the request**: decide whether the text (in several languages)
   really asks for deletion. Access, correction, export and marketing opt-out
   requests are `NOT_APPLICABLE`.
3. **Resolve identities across systems**: replay the identity audit log to
   recover every current *and* past email, phone number and email hash, since
   older systems still hold the old values.
4. **Parse evidence**: read SQL replica snapshots, JSON exports, five log
   formats, handover text files, PDFs (pdfplumber) and application screenshots
   (**RapidOCR**, run locally) into one evidence index.
5. **Link surviving activity**: tie sync, export and restore events in the
   global activity stream to the person, and rebuild each data flow's and
   backup's state as of the audit time.
6. **Audit and report**: compare every record's state at the audit cutoff with
   the policy (delete, redact, anonymize, retain, or keep an account
   tombstone). The result is `COMPLETE` with evidence-backed checks, or
   `INCOMPLETE` with findings, an ordered remediation plan and verification
   checks.

## Architecture

```
code/
├── main.py                CLI entry point: runs the six stages and prints a summary
├── data_loader.py         reads the CSV inputs from dataset/
├── request_classifier.py  decides whether a request authorizes deletion (multilingual patterns)
├── identity_resolver.py   maps an email to every current and historical identifier of the user
├── evidence_parser.py     parses SQL, JSON, log, text, PDF and image evidence into one index
├── activity_linker.py     links sync/restore/export activity to a user and builds state timelines
├── audit_engine.py        applies the deletion policy at audit time and builds the ordered steps
├── output_writer.py       writes output.csv and validates its format before replacing the old file
└── evaluation/
    ├── evaluate.py        precision / recall / sequence metrics against the 32 public samples
    ├── test_audit.py      audit-path tests (fail-closed identity, log dialects, ordering)
    ├── test_classifier.py classifier tests, including 16 custom cases
    └── custom_cases/      the custom classifier cases (JSON)
dataset/                   challenge input data (fictional people and records)
evaluation/                evaluation and usage reports
sample_output/             a full run's console log and three annotated example cases
```

## Quick start

Requires Python 3.10 or newer. No API keys, environment variables or network
access are needed. The dataset ships with the repo.

```bash
git clone https://github.com/loatsoat/ghost_data_still_exist.git
cd ghost_data_still_exist
pip install -r requirements.txt
python code/main.py
```

`main.py` takes no arguments: it reads `dataset/` and writes `output.csv` at the
repository root. The first run takes about a minute while screenshots are
OCR'd; later runs use the local cache and finish in a few seconds. Expected
ending:

```
[5/6] Writing output.csv...
  Validation: Valid: 518 rows
[6/6] Summary:
  COMPLETE: 155
  INCOMPLETE: 344
  NOT_APPLICABLE: 19
```

To score the pipeline against the public samples with known answers:

```bash
python code/evaluation/evaluate.py
```

## Design decisions

1. **Deterministic and offline.** The pipeline makes no network calls and no
   LLM calls. The same input always gives the same output, so an audit can be
   re-run and checked by someone else. In a compliance setting, a decision
   you can't reproduce is one you can't defend.
2. **RapidOCR instead of a cloud OCR service.** The screenshots being audited
   contain personal data. Sending them to a third-party API to check whether
   personal data was deleted would itself be a new copy of that data. RapidOCR
   runs on the local machine and its results are cached.
3. **A pipeline of independent stages.** Each stage (classify, resolve, parse,
   link, audit) is a separate module with a narrow input and output, so each
   can be tested on its own. The log-dialect tests, for example, feed
   synthetic log lines straight into the parser without the rest of the
   pipeline.
4. **Claims are not evidence.** "Deletion succeeded" in a workflow log, or a
   reported status of *Complete*, is ignored unless a snapshot shows the
   record's actual state. Evidence captured after the audit cutoff is
   ignored.
5. **Fail closed.** If the person in a deletion request can't be identified,
   the result is `INCOMPLETE`, never "nothing to do".

## Running tests

```bash
pip install pytest
pytest
```

Configuration is in `pyproject.toml`. The same command runs in GitHub Actions
on every push.

## Sample output

One row of `output.csv`, shown as a table. The workflow reported this deletion as
**COMPLETE**, but two old data exports were still downloadable:

| # | Phase | System | Resource | Operation | State | Evidence |
|---|---|---|---|---|---|---|
| 1 | FINDING | export_service | export_1260 | `REPORT_REMAINING_RECORD` | PRESENT | evidence_23 |
| 2 | FINDING | export_service | export_1842 | `REPORT_REMAINING_RECORD` | PRESENT | evidence_18 |
| 3 | REMEDIATION | export_service | export_1260 | `DELETE_RECORD` | ABSENT | |
| 4 | REMEDIATION | export_service | export_1842 | `DELETE_RECORD` | ABSENT | |
| 5 | VERIFICATION | export_service | export_1260 | `VERIFY_RECORD_ABSENT` | ABSENT | |
| 6 | VERIFICATION | export_service | export_1842 | `VERIFY_RECORD_ABSENT` | ABSENT | |

Each finding cites the evidence file that proves it. Remediation and
verification steps describe future work, so they cite nothing. More examples
(a `COMPLETE` and a `NOT_APPLICABLE` case) are in
[`sample_output/example_cases.md`](sample_output/example_cases.md).

On the 32 public sample cases, the pipeline gets 29 statuses right (90.6%),
with step precision 0.994 and recall 0.850. Details are in
[`evaluation/evaluation_report.md`](evaluation/evaluation_report.md).

## Limitations

- **Pattern-based request classification.** Some phrasings slip through. A
  request such as "I would like it permanently deleted … contact me if you
  need information to verify" can be misread as an information request.
- **No guessing.** When no visible evidence ties a record to the person, the
  record isn't reported. Three public sample cases therefore come out
  `INCOMPLETE` with no steps.
- **Formats without labelled examples.** Several log formats in the full
  dataset don't appear in the public samples, so they are covered by
  synthetic unit tests, not measured accuracy.
- **Built for this dataset's systems.** System names, table mappings and log
  formats are specific to the challenge data. A real deployment would need
  adapters for each production system.
- **Batch audits only.** It audits a snapshot of evidence; it doesn't watch
  live systems.
