import sys, os, json
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from data_loader import DataLoader
from evidence_parser import EvidenceParser
from identity_resolver import IdentityResolver
from request_classifier import RequestClassifier
from audit_engine import AuditEngine

repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
loader = DataLoader(os.path.join(repo, 'dataset'))
sample_reqs = loader.load_sample_requests()
sample_out = loader.load_sample_output()
uids = loader.load_user_identities()
ual = loader.load_user_audit_log()
rules = loader.load_deletion_rules()
acts = loader.load_system_activity()
evm = loader.load_evidence_manifest()
parser = EvidenceParser(os.path.join(repo, 'dataset', 'evidence'))
evi = parser.parse_all(evm)
ir = IdentityResolver(uids, ual)
rc = RequestClassifier()
ae = AuditEngine(evi, rules, acts)

expected = {}
for r in sample_out:
    expected[r['case_id']] = r['deletion_status']

for req in sample_reqs:
    cid = req['case_id']
    ident = ir.resolve(req['email'])
    is_del = rc.classify(req.get('request_text', ''))
    if not is_del or ident is None:
        actual = 'NOT_APPLICABLE'
    else:
        result = ae.audit(req, ident)
        actual = result['deletion_status']
    if actual != expected.get(cid):
        print(f'{cid}: exp={expected.get(cid)} act={actual}  email={req["email"]}')
