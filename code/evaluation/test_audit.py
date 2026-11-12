"""
Self-checks for the audit path:
1. An unresolved identity fails closed (INCOMPLETE, never NOT_APPLICABLE).
2. Every log dialect yields the trace id and event, so a result row can
   inherit the subject named on its trace's *_started row.
"""

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
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

print('ALL PASS')
