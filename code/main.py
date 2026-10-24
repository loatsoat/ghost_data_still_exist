"""
Ghost Data Still Exists - Deletion Audit Agent
Deterministic pipeline with targeted LLM assist (Option B).

Architecture:
1. Data loading (CSV files)
2. Evidence parsing (SQL, JSON, logs, text files)
3. Identity resolution (email -> user_id + historical identifiers)
4. Request classification (multilingual deletion detection)
5. State reconstruction at audit_at
6. Policy application (deletion_rules.csv)
7. Step generation (ordered findings, remediation, verification)
8. Output writing (output.csv)

Run with:
    python code/main.py
"""

import os
import sys
import time
from pathlib import Path

# Add code directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from data_loader import DataLoader
from evidence_parser import EvidenceParser
from identity_resolver import IdentityResolver
from request_classifier import RequestClassifier
from audit_engine import AuditEngine
from output_writer import OutputWriter


def main():
    # Determine paths
    repo_root = Path(__file__).parent.parent
    dataset_dir = repo_root / "dataset"
    output_path = repo_root / "output.csv"

    print("=" * 60)
    print("Ghost Data Still Exists - Deletion Audit Agent")
    print(f"Repository: {repo_root}")
    print("=" * 60)
    print()

    start_time = time.time()

    # === Step 1: Load CSV data ===
    print("[1/6] Loading CSV data...")
    loader = DataLoader(dataset_dir)
    deletion_requests = loader.load_deletion_requests()
    user_identities = loader.load_user_identities()
    user_audit_log = loader.load_user_audit_log()
    system_activity = loader.load_system_activity()
    deletion_rules = loader.load_deletion_rules()
    evidence_manifest = loader.load_evidence_manifest()

    print(f"  Deletion requests: {len(deletion_requests)}")
    print(f"  User identities: {len(user_identities)}")
    print(f"  Audit log entries: {len(user_audit_log)}")
    print(f"  System activity events: {len(system_activity)}")
    print(f"  Deletion rules: {len(deletion_rules)}")
    print(f"  Evidence files: {len(evidence_manifest)}")
    print()

    # === Step 2: Parse evidence files ===
    print("[2/6] Parsing evidence files...")
    parse_start = time.time()
    parser = EvidenceParser(dataset_dir / "evidence")
    evidence_index = parser.parse_all(evidence_manifest)
    parse_time = time.time() - parse_start
    print(f"  Total records parsed: {len(evidence_index.all_records)}")
    print(f"  Unique resource IDs: {len(evidence_index.records_by_resource)}")
    print(f"  Parse time: {parse_time:.1f}s")
    print()

    # === Step 3: Initialize pipeline components ===
    print("[3/6] Initializing pipeline components...")
    identity_resolver = IdentityResolver(user_identities, user_audit_log)
    request_classifier = RequestClassifier()
    audit_engine = AuditEngine(evidence_index, deletion_rules, system_activity)
    output_writer = OutputWriter()
    print()

    # === Step 4: Process each case ===
    print("[4/6] Processing deletion requests...")
    process_start = time.time()
    results = []
    not_applicable_count = 0
    identity_not_found_count = 0

    for i, request in enumerate(deletion_requests):
        if (i + 1) % 50 == 0:
            print(f"  Processing {i+1}/{len(deletion_requests)}...")

        # 4a: Resolve identity
        identity = identity_resolver.resolve(request['email'])

        # 4b: Classify request
        is_deletion = request_classifier.classify(request.get('request_text', ''))

        if not is_deletion:
            results.append({
                'case_id': request['case_id'],
                'deletion_status': 'NOT_APPLICABLE',
                'steps_json': []
            })
            not_applicable_count += 1
            continue

        if identity is None:
            # Identity not found - can't audit
            identity_not_found_count += 1
            results.append({
                'case_id': request['case_id'],
                'deletion_status': 'NOT_APPLICABLE',
                'steps_json': []
            })
            continue

        # 4c: Audit the deletion
        audit_result = audit_engine.audit(request, identity)
        results.append(audit_result)

    process_time = time.time() - process_start
    print(f"  Processed {len(results)} cases in {process_time:.1f}s")
    print(f"  NOT_APPLICABLE: {not_applicable_count}")
    print(f"  Identity not found: {identity_not_found_count}")
    print()

    # === Step 5: Write output ===
    print("[5/6] Writing output.csv...")
    output_writer.write(output_path, results)
    print(f"  Written to: {output_path}")

    # Validate
    valid, msg = output_writer.validate(output_path, len(deletion_requests))
    if valid:
        print(f"  Validation: {msg}")
    else:
        print(f"  VALIDATION ERROR: {msg}")
    print()

    # === Step 6: Summary ===
    print("[6/6] Summary:")
    status_counts = {}
    for r in results:
        status_counts[r['deletion_status']] = status_counts.get(r['deletion_status'], 0) + 1

    for status in sorted(status_counts.keys()):
        print(f"  {status}: {status_counts[status]}")

    total_time = time.time() - start_time
    print()
    print(f"Total time: {total_time:.1f}s")
    print("Done!")


if __name__ == '__main__':
    main()
