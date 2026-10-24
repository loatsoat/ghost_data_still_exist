"""Data-derived sample miss classification.

This diagnostic intentionally does not use case IDs or expected-output lists
to assign causes. It classifies resource-level differences from the current
sample run and prints the source evidence and grounded-link summary.
"""

import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from data_loader import DataLoader
from evidence_parser import EvidenceParser
from evaluate import run_pipeline


def _key(step):
    return (
        step.get("phase"),
        step.get("operation"),
        step.get("system_id"),
        step.get("resource_id"),
    )


def main():
    repo_root = Path(__file__).parent.parent.parent
    dataset = repo_root / "dataset"
    loader = DataLoader(dataset)
    requests = loader.load_sample_requests()
    sample_output = loader.load_sample_output()
    expected = {
        row["case_id"]: {
            "status": row["deletion_status"],
            "steps": json.loads(row["steps_json"]),
        }
        for row in sample_output
    }
    manifest = loader.load_evidence_manifest()
    evidence = EvidenceParser(dataset / "evidence").parse_all(manifest)
    actual = run_pipeline(
        requests,
        loader.load_user_identities(),
        loader.load_user_audit_log(),
        loader.load_deletion_rules(),
        loader.load_system_activity(),
        evidence,
    )

    raw_files = [
        (path, path.read_text(encoding="utf-8", errors="replace"))
        for path in dataset.rglob("*")
        if path.is_file()
    ]
    all_differences = []
    for case_id in sorted(expected):
        expected_steps = expected[case_id]["steps"]
        actual_steps = actual[case_id]["steps"]
        expected_counts = Counter(_key(step) for step in expected_steps)
        actual_counts = Counter(_key(step) for step in actual_steps)
        differences = [
            ("missing", step)
            for step in (expected_counts - actual_counts).elements()
        ] + [
            ("extra", step)
            for step in (actual_counts - expected_counts).elements()
        ]
        if not differences:
            continue

        expected_by_resource = defaultdict(set)
        actual_by_resource = defaultdict(set)
        for step in expected_steps:
            expected_by_resource[step["resource_id"]].add(step["operation"])
        for step in actual_steps:
            actual_by_resource[step["resource_id"]].add(step["operation"])

        for kind, step in differences:
            resource_id = step[3]
            has_exact_evidence = any(
                re.search(
                    r"(?<!\w)"
                    + re.escape(resource_id)
                    + r"(?!\w)",
                    text,
                )
                for _, text in raw_files
            )
            same_resource_action_diff = (
                expected_by_resource[resource_id]
                and actual_by_resource[resource_id]
                and expected_by_resource[resource_id]
                != actual_by_resource[resource_id]
            )
            if same_resource_action_diff:
                cause = "rule"
            elif not has_exact_evidence:
                cause = "unrecoverable"
            else:
                cause = "parsing_or_linking"
            all_differences.append((cause, case_id, kind, step))

    counts = Counter(row[0] for row in all_differences)
    print("Data-derived miss counts:", dict(sorted(counts.items())))
    print("Total missing/extra differences:", len(all_differences))
    for cause, case_id, kind, step in all_differences:
        print(
            f"{cause}\t{case_id}\t{kind}\t"
            f"{step[1]}\t{step[2]}\t{step[3]}"
        )


if __name__ == "__main__":
    main()
