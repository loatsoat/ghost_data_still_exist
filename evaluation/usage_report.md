# Usage Report

## Final full-dataset run

The 518-request `output.csv` was produced by the deterministic local Python
pipeline. The program uses no hosted model or network service.

| Provider | Model | Calls | Input tokens | Output tokens | Total tokens | Estimated cost |
|---|---|---:|---:|---:|---:|---:|
| None | None | 0 | 0 | 0 | 0 | $0.00 |

| Overall metric | Value |
|---|---:|
| Requests processed | 518 |
| Model calls | 0 |
| Input tokens | 0 |
| Output tokens | 0 |
| Total tokens | 0 |
| Average tokens per request | 0 |
| Estimated total cost | $0.00 |
| Estimated cost per request | $0.00 |

## Per-model and overall totals

There are no model-backed requests, so the single per-model and overall
totals are both zero:

| Scope | Provider | Model | Calls | Input tokens | Output tokens | Total tokens | Estimated cost |
|---|---|---|---:|---:|---:|---:|---:|
| Per-model | None | None | 0 | 0 | 0 | 0 | $0.00 |
| Overall | None | None | 0 | 0 | 0 | 0 | $0.00 |

## Offline verification

The production code was searched for LLM and network-library imports. The
import-pattern search returned no matches. Local PDF and OCR dependencies
are used only to parse files included with the dataset; no credentials or
network access are required.
