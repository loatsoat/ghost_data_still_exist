"""
Self-checks for the audit path:
1. An unresolved identity fails closed (INCOMPLETE, never NOT_APPLICABLE).
2. Every log dialect yields the trace id and event, so a result row can
   inherit the subject named on its trace's *_started row.
3. The ordering score tells reversed order from same order.
4. Rows sort by case number.
5. Identity-link events are read in every wording; a later successful
   delete supersedes an earlier failure.
6. A linked resource shown in a screenshot counts as evidence only when the
   screenshot was captured between the request and the audit.
"""

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
sys.path.insert(0, str(Path(__file__).parent))
from audit_engine import AuditEngine
from evidence_parser import EvidenceIndex, EvidenceParser

# 1. Unresolved identity
engine = AuditEngine(EvidenceIndex(), [], [])
result = engine.audit({'case_id': 'case_x', 'audit_at': '2026-01-01T00:00:00Z'}, None)
assert result == {'case_id': 'case_x', 'deletion_status': 'INCOMPLETE',
                  'steps_json': []}, result

# 2. Log dialects (fictional subject)
TS = '2026-01-01T00:00:0'
DIALECTS = {
    'kv': [
        TS + '1Z level=DEBUG service=account_service trace_id=tr-1 event=profile_lookup_started lookup_key="a@example.test"',
        TS + '2Z level=INFO service=account_service trace_id=tr-1 resource_id=account_1 event=profile_lookup_completed rows=0 http_status=404',
    ],
    'lambda': [
        TS + '1Z requestId=tr-1 level=DEBUG function=account_service message="event=\\"profile_lookup_started\\" lookup_key=\\"a@example.test\\""',
        TS + '2Z requestId=tr-1 level=INFO function=account_service message="resource_id=\\"account_1\\" event=\\"profile_lookup_completed\\" rows=\\"0\\" http_status=\\"404\\""',
    ],
    'syslog': [
        TS + '1Z <15>1 node-1 account_service tr-1 - - level=DEBUG event="profile_lookup_started" lookup_key="a@example.test"',
        TS + '2Z <14>1 node-1 account_service tr-1 - - level=INFO resource_id="account_1" event="profile_lookup_completed" rows="0" http_status="404"',
    ],
    'pipe': [
        TS + '1Z | DEBUG | account_service | tr-1 | profile_lookup_started | lookup_key="a@example.test"',
        TS + '2Z | INFO | account_service | tr-1 | profile_lookup_completed | resource_id="account_1" rows="0" http_status="404"',
    ],
    'bracket': [
        TS + '1Z [DEBUG] [account_service] [tr-1] profile_lookup_started: lookup_key="a@example.test"',
        TS + '2Z [INFO] [account_service] [tr-1] profile_lookup_completed: resource_id="account_1" rows="0" http_status="404"',
    ],
}

with tempfile.TemporaryDirectory() as tmp:
    evidence_dir = Path(tmp) / 'dataset' / 'evidence'
    evidence_dir.mkdir(parents=True)
    parser = EvidenceParser(evidence_dir)
    for name, lines in DIALECTS.items():
        log = evidence_dir / f'{name}.log'
        log.write_text('\n'.join(lines), encoding='utf-8')
        index = EvidenceIndex()
        parser._parse_log_file(log, 'f1', '2026-01-01T00:00:09Z', index)
        got = [(r.resource_id, r.state, r.identifiers.get('email'))
               for r in index.all_records]
        assert got == [('account_1', 'ABSENT', 'a@example.test')], (name, got)

    # A contact-index row is a secondary identifier (always delete), not a
    # support message (redact).
    log = evidence_dir / 'contact.log'
    log.write_text(
        TS + '1Z level=INFO service=support_replica event=contact_query_completed '
        'resource_id=support_1 lookup_key=a@example.test rows=1', encoding='utf-8')
    index = EvidenceIndex()
    parser._parse_log_file(log, 'f1', '2026-01-01T00:00:09Z', index)
    assert [r.record_type for r in index.all_records] == ['secondary_identifier']

    # A result row inherits a subject named with subject_ref, and a record
    # taken by the audit time inside a later-exported file is found only on
    # request (it shows the state but its file cannot be cited).
    log = evidence_dir / 'audit.log'
    log.write_text('\n'.join([
        TS + '1Z level=DEBUG service=security_service trace_id=tr-2 event=audit_record_query_started subject_ref="user_01"',
        TS + '2Z level=DEBUG service=security_service trace_id=tr-2 resource_id=audit_record_1 event=audit_record_read_completed rows=1',
    ]), encoding='utf-8')
    index = EvidenceIndex()
    parser._parse_log_file(log, 'f1', '2026-01-02T00:00:00Z', index)
    subject = {'user_id': 'user_01', 'emails': set(), 'phones': set(), 'email_hashes': set()}
    assert index.find_matching_records(subject, TS + '9Z') == {}
    assert list(index.find_matching_records(subject, TS + '9Z', by_record_time=True)) == ['audit_record_1']

# 3. Ordering score: reversed order scores 0, same order scores 1
from evaluate import kendall_tau_normalized
assert kendall_tau_normalized([0, 1, 2], [2, 1, 0]) == 0.0
assert kendall_tau_normalized([0, 1, 2], [0, 1, 2]) == 1.0

# 4. Rows sort by case number, not as text
from output_writer import case_sort_key
assert sorted(['case_100', 'case_99'], key=case_sort_key) == ['case_99', 'case_100']

# 5. Identity links: every wording is read, and a later successful delete
#    supersedes an earlier failed one
from activity_linker import SystemActivityLinker


def act(n, time, event, rid, result, details=''):
    return {'activity_id': f'activity_{n}', 'event_time': TS + time,
            'event_type': event, 'resource_id': rid,
            'target_system': 'export_service', 'reported_result': result,
            'details': details}


linker = SystemActivityLinker([
    act(1, '1Z', 'LINK_RESOURCE_IDENTITY', 'export_1', 'SUCCESS',
        'Data catalog linked export_1 (AB-2026-01) to a@example.test and user_01.'),
    act(2, '1Z', 'LINK_RESOURCE_IDENTITY', 'object_2', 'SUCCESS',
        'Attachment catalog confirmed object_2 (f.pdf) belongs only to '
        'a@example.test and user_01; no other subject is linked.'),
    act(3, '2Z', 'DELETE_RECORD', 'export_1', 'FAILED'),
    act(4, '3Z', 'DELETE_RECORD', 'export_1', 'SUCCESS'),
])
subject = {'user_id': 'user_01', 'emails': {'a@example.test'}}
assert linker.resource_matches_user('export_1', subject)
assert linker.resource_matches_user('object_2', subject)
assert not linker.resource_matches_user('export_1', {'user_id': 'user_010', 'emails': set()})
assert linker.get_failed_deletions(subject, TS + '2Z') == [
    ('export_1', 'export_service', 'activity_3')]
assert linker.get_failed_deletions(subject, TS + '9Z') == []

# 6. A linked resource shown under its alias in a screenshot is evidence,
#    but only when the screenshot was captured after the request was made
index = EvidenceIndex()
index.documents.append(('f9', TS + '5Z', 'object_storage', 'Objects f.pdf 12 KB'))
engine = AuditEngine(
    index,
    [{'rule_id': 'r1', 'data_category': 'SUPPORT_ATTACHMENT',
      'condition': '', 'required_action': 'DELETE'}],
    [act(2, '6Z', 'LINK_RESOURCE_IDENTITY', 'object_2', 'SUCCESS',
         'Attachment catalog confirmed object_2 (f.pdf) belongs only to '
         'a@example.test and user_01; no other subject is linked.')])
identity = {'user_id': 'user_01', 'emails': {'a@example.test'}, 'phones': set(),
            'email_hashes': set(), 'name': 'A Person'}
result = engine.audit({'case_id': 'c1', 'requested_at': TS + '0Z',
                       'audit_at': TS + '9Z'}, identity)
first = result['steps_json'][0]
assert (first['operation'], first['resource_id'], first['evidence_id']) == (
    'REPORT_REMAINING_RECORD', 'object_2', 'f9'), first
result = engine.audit({'case_id': 'c2', 'requested_at': TS + '7Z',
                       'audit_at': TS + '9Z'}, identity)
assert result['steps_json'] == [], result

print('ALL PASS')
