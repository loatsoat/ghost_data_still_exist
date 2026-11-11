"""
Output Writer - Writes the final output.csv with proper formatting.
"""

import csv
import json
import re
from pathlib import Path


def case_sort_key(case_id):
    """Natural sort key so case_2 < case_10 < case_100 (not text order)."""
    nums = re.findall(r'\d+', case_id)
    return (tuple(int(n) for n in nums), case_id)


# Problem statement allowed operation/state pairs.
ALLOWED_OPERATION_STATES = {
    'REPORT_REMAINING_RECORD': 'PRESENT',
    'REPORT_EXPOSED_PII': 'PRESENT',
    'REPORT_ACTIVE_DATA_FLOW': 'ACTIVE',
    'REPORT_RESTORE_RISK': 'ACTIVE',
    'DISABLE_DATA_FLOW': 'DISABLED',
    'BLOCK_RESTORE': 'BLOCKED',
    'DELETE_RECORD': 'ABSENT',
    'REDACT_RECORD': 'REDACTED',
    'ANONYMIZE_RECORD': 'ANONYMIZED',
    'VERIFY_RECORD_ABSENT': 'ABSENT',
    'VERIFY_RECORD_PRESENT': 'PRESENT',
    'VERIFY_RECORD_REDACTED': 'REDACTED',
    'VERIFY_RECORD_ANONYMIZED': 'ANONYMIZED',
    'VERIFY_DATA_FLOW_DISABLED': 'DISABLED',
    'VERIFY_RESTORE_BLOCKED': 'BLOCKED',
}

# Problem statement phase order.
PHASE_ORDER = {'FINDING': 0, 'REMEDIATION': 1, 'VERIFICATION': 2}


class OutputWriter:
    def write(self, output_path, results):
        """
        Write results to output.csv.
        results: list of dicts with case_id, deletion_status, steps_json
        """
        output_path = Path(output_path)

        # Sort by case_id (numeric/natural order, not text order)
        results.sort(key=lambda r: case_sort_key(r['case_id']))

        # Fail-closed integrity check: every case_id must be unique.
        seen_ids = set()
        for r in results:
            if r['case_id'] in seen_ids:
                raise ValueError(f"Duplicate case_id in results: {r['case_id']}")
            seen_ids.add(r['case_id'])

        with open(output_path, 'w', encoding='utf-8', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['case_id', 'deletion_status', 'steps_json'])

            for result in results:
                case_id = result['case_id']
                status = result['deletion_status']
                steps = result['steps_json']

                # Serialize steps to JSON
                steps_json = json.dumps(steps, ensure_ascii=False)
                writer.writerow([case_id, status, steps_json])

    def validate(self, output_path, expected_count):
        """Validate the output file has the correct structure."""
        output_path = Path(output_path)
        if not output_path.exists():
            return False, "Output file does not exist"

        with open(output_path, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            rows = list(reader)

        if len(rows) != expected_count:
            return False, f"Expected {expected_count} rows, got {len(rows)}"

        # Check header
        if reader.fieldnames != ['case_id', 'deletion_status', 'steps_json']:
            return False, f"Wrong header: {reader.fieldnames}"

        case_ids = [row['case_id'] for row in rows]
        if case_ids != sorted(case_ids, key=case_sort_key):
            return False, "Rows are not sorted by case_id (numeric order)"

        # Check each row
        for row in rows:
            if row['deletion_status'] not in ('COMPLETE', 'INCOMPLETE', 'NOT_APPLICABLE'):
                return False, f"Invalid status for {row['case_id']}: {row['deletion_status']}"

            try:
                steps = json.loads(row['steps_json'])
                if not isinstance(steps, list):
                    return False, f"steps_json is not a list for {row['case_id']}"

                if row['deletion_status'] == 'NOT_APPLICABLE' and steps:
                    return False, f"NOT_APPLICABLE must have [] for {row['case_id']}"
                if row['deletion_status'] == 'COMPLETE' and not steps:
                    return False, f"COMPLETE must have positive verification steps for {row['case_id']}"

                previous_phase = -1
                # Check step numbering
                for i, step in enumerate(steps, 1):
                    if step.get('step_no') != i:
                        return False, f"Step numbering mismatch for {row['case_id']}: expected {i}, got {step.get('step_no')}"
                    phase = step.get('phase')
                    operation = step.get('operation')
                    if phase not in PHASE_ORDER:
                        return False, f"Invalid phase for {row['case_id']}: {phase}"
                    if PHASE_ORDER[phase] < previous_phase:
                        return False, f"Phase ordering mismatch for {row['case_id']}"
                    previous_phase = PHASE_ORDER[phase]
                    if operation not in ALLOWED_OPERATION_STATES:
                        return False, f"Invalid operation for {row['case_id']}: {operation}"
                    if step.get('state') != ALLOWED_OPERATION_STATES[operation]:
                        return False, f"Invalid state for {row['case_id']} operation {operation}"
                    if not step.get('system_id') or not step.get('resource_id'):
                        return False, f"Missing system/resource for {row['case_id']}"
                    evidence_id = step.get('evidence_id')
                    if not isinstance(evidence_id, str):
                        return False, f"Invalid evidence_id for {row['case_id']}"
                    if row['deletion_status'] == 'COMPLETE' and not evidence_id:
                        return False, f"COMPLETE step lacks evidence_id for {row['case_id']}"
                    if row['deletion_status'] == 'INCOMPLETE' and phase != 'FINDING' and evidence_id:
                        return False, f"Future INCOMPLETE step has evidence_id for {row['case_id']}"

            except json.JSONDecodeError:
                return False, f"Invalid JSON for {row['case_id']}"

        return True, f"Valid: {len(rows)} rows"
