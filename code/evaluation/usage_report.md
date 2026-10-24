# Token Usage and Cost Report

## Final full-dataset run

The final run that produced the root-level `output.csv` was the deterministic
offline Python pipeline:

```text
python3 code/main.py
```

The pipeline makes no hosted LLM or VLM calls. It reads only the participant
dataset and local evidence files.

| Provider | Model | Calls | Input tokens | Output tokens | Total tokens | Estimated cost |
|---|---|---:|---:|---:|---:|---:|
| None (offline pipeline) | None | 0 | 0 | 0 | 0 | $0.00 |

| Metric | Value |
|---|---:|
| Requests processed | 518 |
| Total model calls | 0 |
| Total input tokens | 0 |
| Total output tokens | 0 |
| Total tokens | 0 |
| Average tokens per request | 0 |
| Estimated total cost | $0.00 |
| Estimated cost per request | $0.00 |

## Development tools and recorded model identifiers

The append-only development transcript records these coding tools:

- `Kiro`
- `Copilot SDK in VS Code`
- `GitHub Copilot SDK in VS Code`

The transcript records `model=Auto` for these development turns. These are
coding-agent development records, not hosted model calls made by the submitted
pipeline. No provider-specific inference usage, token count, or cost exists to
report for the pipeline, so those values are explicitly zero rather than
estimated.

No API keys, credentials, or sensitive configuration values are included.

## Per-model and overall totals

There were no model-backed requests. The single overall total is therefore:

| Scope | Calls | Input tokens | Output tokens | Total tokens | Estimated cost |
|---|---:|---:|---:|---:|---:|
| Overall | 0 | 0 | 0 | 0 | $0.00 |
