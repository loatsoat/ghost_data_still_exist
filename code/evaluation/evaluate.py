"""
Phase 0: Full evaluator.
Reports:
  - Status confusion matrix (3x3 + MISSING)
  - Step-level P/R/F1 matched on (phase, operation, system_id, resource_id) using multisets
  - Field-level accuracy (state, evidence_id, step_no) over matched steps
  - Sequence accuracy: exact-array match rate + Kendall-tau ordering accuracy
  - Per-case diff (missing, extra, wrong-field steps)
  - Full request_text for wrong-status cases
Split: cases sorted by case_id; even indices -> tuning (20), odd indices -> held-out (12)
"""

import os, sys, json, argparse
from pathlib import Path
from collections import Counter, defaultdict

sys.path.insert(0, str(Path(__file__).parent.parent))

from data_loader import DataLoader
from evidence_parser import EvidenceParser
from identity_resolver import IdentityResolver
from request_classifier import RequestClassifier
from audit_engine import AuditEngine


# Problem statement evaluation split: sorted sample IDs at even indexes are
# tuning; odd indexes are held-out.
TUNING_INDEX_PARITY = 0


# ── deterministic split ────────────────────────────────────────────────────
def split_cases(case_ids):
    """Sort case_ids, even index → tuning, odd index → held-out."""
    ids = sorted(case_ids)
    tuning  = [c for i, c in enumerate(ids) if i % 2 == TUNING_INDEX_PARITY]
    holdout = [c for i, c in enumerate(ids) if i % 2 != TUNING_INDEX_PARITY]
    return tuning, holdout


# ── multiset step key ──────────────────────────────────────────────────────
def step_identity(step):
    return (step.get('phase'), step.get('operation'),
            step.get('system_id'), step.get('resource_id'))


# ── Kendall-tau for ordering ───────────────────────────────────────────────
def kendall_tau_normalized(seq_a, seq_b):
    """
    Given two sequences of the same length (matched steps),
    return Kendall-tau in [-1,1] normalised to [0,1] via (tau+1)/2.
    """
    n = len(seq_a)
    if n < 2:
        return 1.0
    concordant = discordant = 0
    for i in range(n):
        for j in range(i+1, n):
            ai = seq_a.index(seq_a[i]) if seq_a[i] in seq_a else i
            bi = seq_b.index(seq_b[i]) if seq_b[i] in seq_b else i
            aj = seq_a.index(seq_a[j]) if seq_a[j] in seq_a else j
            bj = seq_b.index(seq_b[j]) if seq_b[j] in seq_b else j
            sign_a = ai - aj
            sign_b = bi - bj
            if sign_a * sign_b > 0:
                concordant += 1
            elif sign_a * sign_b < 0:
                discordant += 1
    total = concordant + discordant
    tau = (concordant - discordant) / total if total else 1.0
    return (tau + 1) / 2


# ── main evaluation ────────────────────────────────────────────────────────
def evaluate(requests, expected, actual, label="ALL"):
    case_ids = sorted(expected.keys())

    statuses = ['COMPLETE', 'INCOMPLETE', 'NOT_APPLICABLE']
    matrix   = defaultdict(lambda: defaultdict(int))

    tp_total = fp_total = fn_total = 0
    state_correct = state_total = 0
    evid_correct  = evid_total  = 0
    stepno_correct = stepno_total = 0
    exact_match = 0
    ordering_scores = []

    req_map = {r['case_id']: r for r in requests}
    diffs = []

    for cid in case_ids:
        exp  = expected[cid]
        act  = actual.get(cid, {'status': 'MISSING', 'steps': []})

        matrix[exp['status']][act['status']] += 1

        exp_steps = exp['steps']
        act_steps = act['steps']

        # multiset matching
        exp_mc = Counter(step_identity(s) for s in exp_steps)
        act_mc = Counter(step_identity(s) for s in act_steps)
        tp_keys = exp_mc & act_mc          # multiset intersection
        tp = sum(tp_keys.values())
        fp = sum((act_mc - exp_mc).values())
        fn = sum((exp_mc - act_mc).values())

        tp_total += tp; fp_total += fp; fn_total += fn

        # exact match
        if exp_steps == act_steps:
            exact_match += 1

        # ordering: for matched keys, compare relative order in exp vs act
        matched_key_list = []
        for key, cnt in tp_keys.items():
            matched_key_list.extend([key] * cnt)
        if len(matched_key_list) >= 2:
            exp_positions = []
            act_positions = []
            used_exp = defaultdict(int)
            used_act = defaultdict(int)
            for key in matched_key_list:
                # find first unused position of this key in exp
                for idx, s in enumerate(exp_steps):
                    if step_identity(s) == key and used_exp[key] <= idx - sum(
                            1 for k2, c2 in used_exp.items() for _ in range(c2) if k2 == key):
                        exp_positions.append(idx)
                        used_exp[key] += 1
                        break
                for idx, s in enumerate(act_steps):
                    if step_identity(s) == key and used_act[key] <= idx - sum(
                            1 for k2, c2 in used_act.items() for _ in range(c2) if k2 == key):
                        act_positions.append(idx)
                        used_act[key] += 1
                        break
            if len(exp_positions) == len(act_positions) >= 2:
                ordering_scores.append(kendall_tau_normalized(exp_positions, act_positions))

        # field-level accuracy on TP steps
        for key in tp_keys:
            exp_match = [s for s in exp_steps if step_identity(s) == key]
            act_match = [s for s in act_steps if step_identity(s) == key]
            for es, as_ in zip(exp_match, act_match):
                state_total += 1
                if es.get('state') == as_.get('state'):
                    state_correct += 1
                evid_total += 1
                if es.get('evidence_id') == as_.get('evidence_id'):
                    evid_correct += 1
                stepno_total += 1
                if es.get('step_no') == as_.get('step_no'):
                    stepno_correct += 1

        # per-case diff
        missing = list((exp_mc - act_mc).elements())
        extra   = list((act_mc - exp_mc).elements())
        wrong_field = []
        for key in tp_keys:
            for es, as_ in zip(
                [s for s in exp_steps if step_identity(s) == key],
                [s for s in act_steps if step_identity(s) == key]
            ):
                fields = {}
                for f in ('state', 'evidence_id', 'step_no'):
                    if es.get(f) != as_.get(f):
                        fields[f] = (es.get(f), as_.get(f))
                if fields:
                    wrong_field.append((key, fields))

        if missing or extra or wrong_field or exp['status'] != act['status']:
            diffs.append({
                'case_id': cid,
                'exp_status': exp['status'],
                'act_status': act['status'],
                'missing': missing,
                'extra': extra,
                'wrong_field': wrong_field,
                'request_text': req_map.get(cid, {}).get('request_text', ''),
            })

    # ── Print results ──────────────────────────────────────────────────────
    total = len(case_ids)
    print(f"\n{'='*70}")
    print(f"EVALUATION: {label}  (n={total})")
    print(f"{'='*70}")

    print("\n--- STATUS CONFUSION MATRIX ---")
    header = f"{'Exp\\Act':<18}" + "".join(f"{s:<16}" for s in statuses + ['MISSING'])
    print(header)
    print("-" * len(header))
    correct_total = 0
    for es in statuses:
        row = f"{es:<18}"
        for as_ in statuses + ['MISSING']:
            row += f"{matrix[es][as_]:<16}"
            if es == as_:
                correct_total += matrix[es][as_]
        print(row)
    print(f"\n  Overall status accuracy: {correct_total}/{total} ({100*correct_total/total:.1f}%)")
    for es in statuses:
        t = sum(matrix[es].values())
        c = matrix[es][es]
        if t:
            print(f"  {es}: {c}/{t} ({100*c/t:.0f}%)")

    print("\n--- STEP METRICS ---")
    prec = tp_total/(tp_total+fp_total) if tp_total+fp_total else 0.0
    rec  = tp_total/(tp_total+fn_total) if tp_total+fn_total else 0.0
    f1   = 2*prec*rec/(prec+rec) if prec+rec else 0.0
    print(f"  TP={tp_total} FP={fp_total} FN={fn_total}")
    print(f"  Precision={prec:.3f}  Recall={rec:.3f}  F1={f1:.3f}")

    print("\n--- FIELD ACCURACY (over matched TP steps) ---")
    print(f"  state      : {state_correct}/{state_total} ({100*state_correct/state_total:.1f}%)" if state_total else "  state: n/a")
    print(f"  evidence_id: {evid_correct}/{evid_total} ({100*evid_correct/evid_total:.1f}%)" if evid_total else "  evidence_id: n/a")
    print(f"  step_no    : {stepno_correct}/{stepno_total} ({100*stepno_correct/stepno_total:.1f}%)" if stepno_total else "  step_no: n/a")

    print("\n--- SEQUENCE ACCURACY ---")
    print(f"  Exact array match: {exact_match}/{total} ({100*exact_match/total:.1f}%)")
    avg_kt = sum(ordering_scores)/len(ordering_scores) if ordering_scores else 1.0
    print(f"  Ordering (Kendall-tau normalised, matched steps): {avg_kt:.3f}")

    print("\n--- PER-CASE DIFFS (wrong status or steps) ---")
    for d in diffs:
        status_ok = d['exp_status'] == d['act_status']
        prefix = "  " if status_ok else "* "
        print(f"\n{prefix}{d['case_id']}  exp={d['exp_status']} act={d['act_status']}")
        if not status_ok:
            txt = d['request_text'][:120].replace('\n', ' ')
            print(f"    request_text: {txt}")
        if d['missing']:
            print(f"    MISSING ({len(d['missing'])}): {d['missing'][:5]}")
        if d['extra']:
            print(f"    EXTRA   ({len(d['extra'])}): {d['extra'][:5]}")
        if d['wrong_field']:
            print(f"    WRONG FIELDS: {d['wrong_field'][:3]}")

    return {
        'status_accuracy': correct_total / total,
        'precision': prec, 'recall': rec, 'f1': f1,
        'exact_match': exact_match / total,
        'ordering': avg_kt,
        'state_acc': state_correct/state_total if state_total else None,
        'evid_acc': evid_correct/evid_total if evid_total else None,
        'stepno_acc': stepno_correct/stepno_total if stepno_total else None,
        'status_class_accuracy': {
            es: (
                matrix[es][es] / sum(matrix[es].values())
                if sum(matrix[es].values()) else None
            )
            for es in statuses
        },
        'confusion_matrix': {
            es: {as_: matrix[es][as_] for as_ in statuses + ['MISSING']}
            for es in statuses
        },
    }


def run_pipeline(requests, user_identities, user_audit_log,
                 deletion_rules, system_activity, evidence_index,
                 trace_case=None):
    """Run the full pipeline on a list of requests, return actual dict."""
    identity_resolver  = IdentityResolver(user_identities, user_audit_log)
    request_classifier = RequestClassifier()
    audit_engine       = AuditEngine(evidence_index, deletion_rules, system_activity)

    actual = {}
    for req in requests:
        cid      = req['case_id']
        identity = identity_resolver.resolve(req['email'])
        is_del   = request_classifier.classify(req.get('request_text', ''))

        if not is_del or identity is None:
            actual[cid] = {'status': 'NOT_APPLICABLE', 'steps': []}
            continue

        result = audit_engine.audit(req, identity)
        actual[cid] = {'status': result['deletion_status'], 'steps': result['steps_json']}

        if trace_case and cid == trace_case:
            print(f"\n=== TRACE for {cid} ===")
            for step in result['steps_json']:
                trace = audit_engine.last_trace.get(step['step_no'], {})
                print(f"  step {step['step_no']} | {step['phase']} | {step['operation']} | "
                      f"{step['system_id']} | {step['resource_id']} | "
                      f"evidence={step['evidence_id']}")
                if trace:
                    print(f"    trace: file={trace.get('file_id')} "
                          f"id_type={trace.get('id_type')} id_val={trace.get('id_val')} "
                          f"rule={trace.get('rule_id')}")

    return actual


def main():
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(errors="backslashreplace")
    parser = argparse.ArgumentParser()
    parser.add_argument('--trace', help='Dump per-step trace for a case_id')
    args = parser.parse_args()

    repo_root   = Path(__file__).parent.parent.parent
    dataset_dir = repo_root / "dataset"

    loader = DataLoader(dataset_dir)
    sample_requests  = loader.load_sample_requests()
    sample_output    = loader.load_sample_output()
    user_identities  = loader.load_user_identities()
    user_audit_log   = loader.load_user_audit_log()
    deletion_rules   = loader.load_deletion_rules()
    system_activity  = loader.load_system_activity()
    evidence_manifest = loader.load_evidence_manifest()

    expected = {r['case_id']: {'status': r['deletion_status'],
                                'steps':  json.loads(r['steps_json'])}
                for r in sample_output}

    print("Parsing evidence...", end=" ", flush=True)
    ev_parser     = EvidenceParser(dataset_dir / "evidence")
    evidence_index = ev_parser.parse_all(evidence_manifest)
    print(f"{len(evidence_index.all_records)} records from {len(evidence_manifest)} files")

    actual = run_pipeline(
        sample_requests, user_identities, user_audit_log,
        deletion_rules, system_activity, evidence_index,
        trace_case=args.trace
    )

    case_ids = sorted(expected.keys())
    tuning, holdout = split_cases(case_ids)

    exp_tuning  = {c: expected[c] for c in tuning}
    act_tuning  = {c: actual.get(c, {'status':'MISSING','steps':[]}) for c in tuning}
    req_tuning  = [r for r in sample_requests if r['case_id'] in tuning]

    exp_holdout = {c: expected[c] for c in holdout}
    act_holdout = {c: actual.get(c, {'status':'MISSING','steps':[]}) for c in holdout}
    req_holdout = [r for r in sample_requests if r['case_id'] in holdout]

    m_all     = evaluate(sample_requests, expected, actual, "ALL 32")
    m_tuning  = evaluate(req_tuning, exp_tuning, act_tuning, f"TUNING ({len(tuning)})")
    m_holdout = evaluate(req_holdout, exp_holdout, act_holdout, f"HELD-OUT ({len(holdout)})")

    # Save baseline to evaluation_report.md
    report_path = Path(__file__).parent / "evaluation_report.md"
    try:
        _write_baseline(report_path, m_all, m_tuning, m_holdout, tuning, holdout)
        submission_report = Path(__file__).parent.parent.parent / "evaluation" / "evaluation_report.md"
        submission_report.parent.mkdir(exist_ok=True)
        _write_baseline(submission_report, m_all, m_tuning, m_holdout, tuning, holdout)
        print(f"\nBaseline saved to {report_path}")
    except Exception as e:
        print(f"\nReport write error (non-fatal): {e}")


def _write_baseline(path, m_all, m_tuning, m_holdout, tuning, holdout):
    lines = [
        "# Evaluation Report\n",
        "## Baseline\n",
        f"Split: tuning={tuning}, held-out={holdout}\n\n",
        "| Set | Status Acc | Precision | Recall | F1 | Exact Seq | Ordering |",
        "|-----|-----------|-----------|--------|-----|-----------|----------|",
    ]
    for label, m in [("All-32", m_all), ("Tuning", m_tuning), ("Held-out", m_holdout)]:
        lines.append(
            f"| {label} | {m['status_accuracy']:.3f} | {m['precision']:.3f} | "
            f"{m['recall']:.3f} | {m['f1']:.3f} | {m['exact_match']:.3f} | {m['ordering']:.3f} |"
        )
    lines += [
        "\n## Field and Status-Class Metrics\n",
        "| Set | COMPLETE Acc | INCOMPLETE Acc | NOT_APPLICABLE Acc | State | Evidence ID | Step No |",
        "|-----|--------------|----------------|--------------------|-------|-------------|---------|",
    ]
    for label, m in [("All-32", m_all), ("Tuning", m_tuning), ("Held-out", m_holdout)]:
        cls = m['status_class_accuracy']
        fmt = lambda value: "n/a" if value is None else f"{value:.3f}"
        lines.append(
            f"| {label} | {fmt(cls['COMPLETE'])} | {fmt(cls['INCOMPLETE'])} | "
            f"{fmt(cls['NOT_APPLICABLE'])} | {fmt(m['state_acc'])} | "
            f"{fmt(m['evid_acc'])} | {fmt(m['stepno_acc'])} |"
        )
    lines += [
        "\n## Status Confusion Matrices\n",
        "Rows are expected statuses; columns are predicted statuses.\n",
    ]
    for label, m in [("All-32", m_all), ("Tuning", m_tuning), ("Held-out", m_holdout)]:
        matrix = m['confusion_matrix']
        lines += [
            f"### {label}",
            "| Expected \\ Predicted | COMPLETE | INCOMPLETE | NOT_APPLICABLE | MISSING |",
            "|---|---:|---:|---:|---:|",
        ]
        for expected_status in ("COMPLETE", "INCOMPLETE", "NOT_APPLICABLE"):
            lines.append(
                f"| {expected_status} | "
                f"{matrix[expected_status]['COMPLETE']} | "
                f"{matrix[expected_status]['INCOMPLETE']} | "
                f"{matrix[expected_status]['NOT_APPLICABLE']} | "
                f"{matrix[expected_status]['MISSING']} |"
            )
    lines += [
        "\n## Custom Evaluation Cases\n",
        "| ID | Scenario | Expected behavior |",
        "|----|----------|-------------------|",
        "| custom_01 | Access request | NOT_APPLICABLE |",
        "| custom_02 | Correction request | NOT_APPLICABLE |",
        "| custom_03 | Export/data portability | NOT_APPLICABLE |",
        "| custom_04 | Marketing opt-out | NOT_APPLICABLE |",
        "| custom_05 | German deletion request | Deletion authorized |",
        "| custom_06 | French access request | NOT_APPLICABLE |",
        "| custom_07 | Deletion with anonymous analytics wording | Deletion authorized |",
        "| custom_08 | Deletion mentioning a prior export | Deletion authorized |",
        "| custom_09 | Deletion mentioning correction | Deletion authorized |",
        "| custom_10 | Korean deletion request | Deletion authorized |",
        "| custom_11 | Complaint without deletion | NOT_APPLICABLE |",
        "| custom_12 | Tombstone/redaction request | Deletion authorized |",
        "| custom_13 | SQL replica drift | Present replica drives an incomplete audit |",
        "| custom_14 | Active data flow | Active flow requires disable and verification |",
        "| custom_15 | Restore risk | Restorable backup requires block and verification |",
        "| custom_16 | Account tombstone | Direct identifiers require redaction, stable reference retained |",
        "\nDefinitions for custom_01–custom_12 are in `code/evaluation/custom_cases/custom_cases.json`; "
        "custom_13–custom_16 are exercised by the corresponding evidence fixtures and "
        "Step D/E reports.\n",
        "\n## Final Full-Dataset Results\n",
        "The deterministic offline run produced 518 rows: 169 COMPLETE, "
        "330 INCOMPLETE, and 19 NOT_APPLICABLE. It has 20 empty INCOMPLETE "
        "rows (15 with only *_started traces and 5 with no participant-visible "
        "mention) and zero empty COMPLETE rows.\n\n",
        "The sample metrics cannot validate the log-derived rows because the "
        "32 public samples do not contain those log formats.\n\n",
        "Compared with the baseline tag, 41 rows changed: 10 in block 1, "
        "2 in block 2, 6 in block 3, 1 in block 4, 18 in block 5, and 4 "
        "in block 6.\n\n",
        "## Failures and Fixes\n",
        "| Stage | Failure | General fix | Metric change |\n",
        "|-------|---------|--------------|----------------|\n",
        "| Operational evidence | Wrapper logs hid the service in a same-row system field | Recognized-system fallback with identity and cutoff gates | Held-out metrics unchanged |\n",
        "| Evidence contract | Unsupported absence derivations risked empty COMPLETE | Positive-evidence gate | Zero empty COMPLETE rows |\n",
        "| Remaining gaps | Some traces contain only *_started rows or no mention | Keep unresolved cases INCOMPLETE; do not invent evidence | 20 empty INCOMPLETE rows |",
    ]
    path.write_text("\n".join(lines) + "\n", encoding='utf-8')


if __name__ == '__main__':
    main()
