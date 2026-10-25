# Ghost Data Still Exists

This repository contains a deterministic, offline deletion-audit pipeline for
the HackerRank Orchestrate challenge. It reads participant-facing data from
`dataset/`, reconstructs evidence available at each request's `audit_at`, and
writes the predictions to the repository-root `output.csv`.

## Quick start from an unzipped folder

1. Extract `code.zip` to a folder.
2. Copy the challenge's `dataset/` folder into that same folder, next to
   `README.md` and `code/`.
3. Install Python 3.10 or newer and the local evidence-reader dependencies:

   **Windows**

   ```powershell
   py -3 -m pip install -r requirements.txt
   ```

   **macOS/Linux**

   ```bash
   python3 -m pip install -r requirements.txt
   ```

4. Run the full 518-request audit:

   **Windows**

   ```powershell
   py -3 code/main.py
   ```

   **macOS/Linux**

   ```bash
   python3 code/main.py
   ```

The output is written to `output.csv` beside the README. The run validates the
row count; it does not need credentials or network access.

## Architecture and data flow

The pipeline loads request, identity, audit-history, policy, activity, and
evidence-manifest data. It classifies deletion intent, resolves current and
historical identifiers, parses local evidence, links globally recorded
activity to grounded identities, and applies the deletion rules to construct
ordered findings, remediation, and verification steps. `OutputWriter`
serializes and validates the final CSV.

Key modules:

- `code/main.py` — command-line entry point and orchestration.
- `code/data_loader.py` — participant CSV loading.
- `code/request_classifier.py` — deterministic multilingual request
  classification.
- `code/identity_resolver.py` — current and historical identity lookup.
- `code/evidence_parser.py` — local PDF, image, SQL, JSON, text, and log
  parsing.
- `code/activity_linker.py` — identity-grounded activity and process
  timelines.
- `code/audit_engine.py` — evidence cutoff, policy, and ordered step logic.
- `code/output_writer.py` — CSV serialization and output validation.

## Evidence rules

- Use only participant-facing files under `dataset/`; do not use organizer
  truth or hidden answers.
- Match evidence through resolved current or historical identifiers, resource
  and system IDs, and other explicit links. A manifest entry alone does not
  establish that evidence belongs to a case.
- Honor both evidence capture time and record time. Evidence or events after
  `audit_at` cannot affect that case.
- Treat workflow statuses and operation messages as claims, not proof of
  resulting state. Require evidence for findings and completed-state
  verification.
- Do not infer absence from an unsupported or incomplete log entry. In
  particular, `*_started` traces do not prove a completed operation.
- Apply retention, redaction, anonymization, and tombstone rules instead of
  deleting records indiscriminately.

## Evaluator and tests

The evaluator compares the pipeline with the 32 public sample cases and
prints status, step, field, and sequence metrics:

```powershell
py -3 code/evaluation/evaluate.py
```

```bash
python3 code/evaluation/evaluate.py
```

By default, the evaluator preserves an existing top-level
`evaluation/evaluation_report.md`. It writes the generated sample report there
only if the file does not exist. Pass `--overwrite-report` only when you
intentionally want to replace that final report with sample metrics.

Run the custom request-classifier tests with:

```powershell
py -3 code/evaluation/test_classifier.py
```

```bash
python3 code/evaluation/test_classifier.py
```

Both commands need the `dataset/` folder beside this README. The evaluator
uses `sample_deletion_requests.csv` and `sample_output.csv`; it does not
replace the full-dataset `output.csv`.

## Offline and deterministic operation

No LLM is used. The solution uses explicit, reproducible rules and local
evidence parsing so its outputs are auditable against the supplied records
and time cutoffs. It makes no network calls, reads no API credentials, and
uses zero model calls, tokens, and inference cost. Given the same dataset and
dependency versions, the pipeline produces the same output.

PDF and image extraction use the local packages listed in `requirements.txt`.
Image OCR runs locally with RapidOCR; no remote OCR or hosted inference
service is called.

## AI coding-agent use

An AI coding agent assisted with implementation review, evidence-parser
investigation, tests, documentation, packaging, and output-integrity checks.
The submitted program itself performs no LLM inference; coding-agent
development usage is separate from the zero-call production usage reported
in `evaluation/usage_report.md`.

## Known limitations

The final output contains 20 authorized `INCOMPLETE` rows with empty
`steps_json`: 15 have only non-state `*_started` traces, and 5 have no
participant-visible identifier mention. These cases remain unresolved rather
than inventing a resource match, a state, or a remediation target.

## Package contents

The submission archive contains `README.md`, `requirements.txt`, `code/`, and
the top-level `evaluation/evaluation_report.md` and
`evaluation/usage_report.md`. It excludes `dataset/`, caches, nested
archives, and scratch files. From the repository root, create it on Windows
with:

```powershell
Compress-Archive -Path README.md,requirements.txt,code,evaluation -DestinationPath code.zip -Force
```

On macOS/Linux, use:

```bash
zip -r code.zip README.md requirements.txt code evaluation \
  -x '*/__pycache__/*' '*/.venv/*' '*/venv/*' '*/node_modules/*' '*/.git/*' '*.zip'
```
