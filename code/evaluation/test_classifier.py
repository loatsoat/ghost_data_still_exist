"""
Test the request classifier against:
1. The 4 previously misclassified sample cases (must now return True).
2. All custom test cases in custom_cases/custom_cases.json.
"""

import sys, os, json
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from request_classifier import RequestClassifier
from data_loader import DataLoader

rc = RequestClassifier()

repo_root   = Path(__file__).parent.parent.parent
dataset_dir = repo_root / "dataset"
loader      = DataLoader(dataset_dir)
sample_reqs = loader.load_sample_requests()

# 4 previously misclassified cases (expected: deletion = True)
PREV_BROKEN = {'case_04', 'case_12', 'case_24', 'case_26'}

print("=" * 65)
print("CLASSIFIER TEST: previously misclassified sample cases")
print("=" * 65)
all_pass = True
for r in sample_reqs:
    if r['case_id'] not in PREV_BROKEN:
        continue
    result = rc.classify(r['request_text'])
    ok = "PASS" if result else "FAIL"
    if not result:
        all_pass = False
    print(f"  {r['case_id']}: {ok}  is_deletion={result}")
    print(f"    text: {r['request_text'][:100]}")

# Custom cases
custom_path = Path(__file__).parent / "custom_cases" / "custom_cases.json"
custom_cases = json.loads(custom_path.read_text(encoding='utf-8'))

print()
print("=" * 65)
print("CLASSIFIER TEST: custom cases")
print("=" * 65)
for c in custom_cases:
    result   = rc.classify(c['request_text'])
    expected = c['expected_authorizes_deletion']
    ok       = "PASS" if result == expected else "FAIL"
    if result != expected:
        all_pass = False
    print(f"  {c['id']} ({c['type']}): {ok}  expected={expected} got={result}")
    if result != expected:
        print(f"    text: {c['request_text'][:100]}")

print()
print("=" * 65)
print(f"Overall: {'ALL PASS' if all_pass else 'SOME FAILURES'}")
print("=" * 65)
sys.exit(0 if all_pass else 1)
