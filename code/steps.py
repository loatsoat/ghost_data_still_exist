"""Turn findings and compliant records into numbered FINDING/REMEDIATION/VERIFICATION steps."""

from policy import (
    FINDING_ORDER,
    REMEDIATION_ORDER,
    VERIFICATION_ORDER,
    ACTION_TO_VERIFICATION,
    PROCESS_FINDING_TARGET,
    FIX_FOR,
    VERIFY_FOR,
)


def plan_and_verify(findings, compliant):
    """Steps for an INCOMPLETE case: findings, ordered remediation, post-fix checks."""
    findings = sorted(findings, key=lambda f: _order_key(
        FINDING_ORDER, f['operation'], f['system_id'], f['resource_id']))
    targets = [(f, _finding_target(f)) for f in findings]
    remediations = sorted(
        ((f['system_id'], f['resource_id'], *FIX_FOR[t]) for f, t in targets if t),
        key=lambda r: _order_key(REMEDIATION_ORDER, r[2], r[0], r[1]))
    verifications = [(f['system_id'], f['resource_id'], *VERIFY_FOR[t], '')
                     for f, t in targets if t]
    verifications += [(r.system_id, r.resource_id, *VERIFY_FOR[a], '')
                      for r, a in compliant if a in VERIFY_FOR]

    rows = [('FINDING', f['system_id'], f['resource_id'], f['operation'], f['state'],
             f['evidence_id']) for f in findings]
    rows += [('REMEDIATION', *r, '') for r in remediations]
    rows += [('VERIFICATION', *v) for v in _sorted_unique(verifications)]
    return _number(rows)

def verify_complete(compliant):
    """Steps for a COMPLETE case: evidence-backed checks of the current state."""
    verifications = [(r.system_id, r.resource_id, *VERIFY_FOR[a], r.file_id)
                     for r, a in compliant if a in VERIFY_FOR]
    return _number([('VERIFICATION', *v) for v in _sorted_unique(verifications)])


def _order_key(order, operation, system_id, resource_id):
    return (order.index(operation) if operation in order else 99, system_id, resource_id)


def _finding_target(finding):
    """The final-state key (see VERIFY_FOR) that remediating this finding must reach."""
    target = PROCESS_FINDING_TARGET.get(finding['operation'])
    if target:
        return target
    action = finding.get('action')
    return action if action in ACTION_TO_VERIFICATION else None


def _sorted_unique(verifications):
    """Sort (system, resource, operation, state, evidence) rows; keep the first per check."""
    seen, out = set(), []
    for v in sorted(verifications, key=lambda v: _order_key(VERIFICATION_ORDER, v[2], v[0], v[1])):
        if (v[2], v[0], v[1]) not in seen:
            seen.add((v[2], v[0], v[1]))
            out.append(v)
    return out


def _number(rows):
    """(phase, system, resource, operation, state, evidence) rows -> numbered step dicts."""
    keys = ('phase', 'system_id', 'resource_id', 'operation', 'state', 'evidence_id')
    return [{'step_no': i, **dict(zip(keys, row))} for i, row in enumerate(rows, 1)]
