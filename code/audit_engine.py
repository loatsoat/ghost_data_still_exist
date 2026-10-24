"""
Audit Engine - Core deletion audit logic.
Derives finding and remediation operations from deletion_rules.csv action.
Tracks data flows and restore risks from system_activity as of audit_at.
Uses a reverse identifier index for matching.
"""

from collections import defaultdict

# Import activity linker for Phase 3/5 data-flow and restore tracking
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from activity_linker import SystemActivityLinker


# Operation order for sorting within each phase
FINDING_ORDER = [
    'REPORT_REMAINING_RECORD',
    'REPORT_EXPOSED_PII',
    'REPORT_ACTIVE_DATA_FLOW',
    'REPORT_RESTORE_RISK',
]

REMEDIATION_ORDER = [
    'DISABLE_DATA_FLOW',
    'BLOCK_RESTORE',
    'DELETE_RECORD',
    'REDACT_RECORD',
    'ANONYMIZE_RECORD',
]

VERIFICATION_ORDER = [
    'VERIFY_RECORD_ABSENT',
    'VERIFY_RECORD_PRESENT',
    'VERIFY_RECORD_REDACTED',
    'VERIFY_RECORD_ANONYMIZED',
    'VERIFY_DATA_FLOW_DISABLED',
    'VERIFY_RESTORE_BLOCKED',
]

# Map record type to data category (from deletion_rules.csv)
RECORD_TYPE_TO_CATEGORY = {
    'customer_profile': 'USER_PROFILE',
    'search_document': 'SEARCH_INDEX_ENTRY',
    'analytics_profile': 'ANALYTICS_PROFILE',
    'support_record': 'SUPPORT_MESSAGE',
    'support_attachment': 'SUPPORT_ATTACHMENT',
    'user_export': 'USER_EXPORT',
    'connector': None,  # Data flows are tracked from system_activity
    'backup': 'BACKUP_ARCHIVE',
    'security_audit': 'SECURITY_AUDIT_LOG',
    'account_tombstone': 'ACCOUNT_TOMBSTONE',
}

# Map rule action to finding operation
ACTION_TO_FINDING = {
    'DELETE': 'REPORT_REMAINING_RECORD',
    'REDACT': 'REPORT_EXPOSED_PII',
    'ANONYMIZE': 'REPORT_EXPOSED_PII',
}

# Map rule action to remediation operation
ACTION_TO_REMEDIATION = {
    'DELETE': 'DELETE_RECORD',
    'REDACT': 'REDACT_RECORD',
    'ANONYMIZE': 'ANONYMIZE_RECORD',
}

# Map rule action to verification operation
ACTION_TO_VERIFICATION = {
    'DELETE': 'VERIFY_RECORD_ABSENT',
    'REDACT': 'VERIFY_RECORD_REDACTED',
    'ANONYMIZE': 'VERIFY_RECORD_ANONYMIZED',
}

# Verification state for each action
ACTION_TO_VERIFICATION_STATE = {
    'DELETE': 'ABSENT',
    'REDACT': 'REDACTED',
    'ANONYMIZE': 'ANONYMIZED',
}

# Remediation state for each action
ACTION_TO_REMEDIATION_STATE = {
    'DELETE': 'ABSENT',
    'REDACT': 'REDACTED',
    'ANONYMIZE': 'ANONYMIZED',
}


class AuditEngine:
    def __init__(self, evidence_index, deletion_rules, system_activity):
        self.evidence_index = evidence_index
        self.deletion_rules = self._parse_rules(deletion_rules)
        self.system_activity = system_activity
        self.linker = SystemActivityLinker(system_activity)
        self._build_activity_index()

    def _parse_rules(self, rules_csv):
        """Parse deletion rules into a lookup dict by data category."""
        rules = {}
        for row in rules_csv:
            rules[row['data_category']] = {
                'rule_id': row['rule_id'],
                'condition': row['condition'],
                'required_action': row['required_action'],
            }
        return rules

    def _build_activity_index(self):
        """Build index of system_activity events for data flow and restore tracking."""
        # Track data flow state changes by resource_id
        self.data_flow_events = defaultdict(list)
        self.restore_events = defaultdict(list)
        self.deletion_events = defaultdict(list)

        for act in self.system_activity:
            event_type = act.get('event_type', '')
            resource_id = act.get('resource_id', '')
            event_time = act.get('event_time', '')
            target_system = act.get('target_system', '')
            source_system = act.get('source_system', '')
            reported_result = act.get('reported_result', '')

            if event_type in ('CHECK_DATA_FLOW', 'DISABLE_DATA_FLOW', 'SYNC_RECORD'):
                if 'data_flow_' in resource_id or 'integration_service' in (source_system, target_system):
                    self.data_flow_events[resource_id].append({
                        'time': event_time,
                        'type': event_type,
                        'result': reported_result,
                        'source': source_system,
                        'target': target_system,
                    })

            if event_type in ('CHECK_RESTORE_ACCESS', 'BLOCK_RESTORE', 'RESTORE_BACKUP'):
                if 'backup_' in resource_id or 'backup_service' in (source_system, target_system):
                    self.restore_events[resource_id].append({
                        'time': event_time,
                        'type': event_type,
                        'result': reported_result,
                    })

            if event_type == 'DELETE_RECORD':
                self.deletion_events[resource_id].append({
                    'time': event_time,
                    'type': event_type,
                    'result': reported_result,
                    'source': source_system,
                    'target': target_system,
                })

    def _get_data_flow_state_at(self, resource_id, audit_at):
        """Determine data flow state at audit_at from system_activity."""
        events = self.data_flow_events.get(resource_id, [])
        # Filter to events at or before audit_at
        valid = [e for e in events if e['time'] <= audit_at]
        if not valid:
            return None  # No activity data

        # Sort by time, get latest
        valid.sort(key=lambda e: e['time'])
        latest = valid[-1]

        # If the latest event is DISABLE_DATA_FLOW with SUCCESS, flow is DISABLED
        if latest['type'] == 'DISABLE_DATA_FLOW' and latest['result'] == 'SUCCESS':
            return 'DISABLED'
        # If the latest event is CHECK_DATA_FLOW with SUCCESS, flow is ACTIVE (remains enabled)
        if latest['type'] == 'CHECK_DATA_FLOW' and latest['result'] == 'SUCCESS':
            return 'ACTIVE'
        # If the latest event is SYNC_RECORD, the flow is still active
        if latest['type'] == 'SYNC_RECORD':
            return 'ACTIVE'

        return None

    def _get_restore_state_at(self, resource_id, audit_at):
        """Determine backup restore state at audit_at from system_activity."""
        events = self.restore_events.get(resource_id, [])
        valid = [e for e in events if e['time'] <= audit_at]
        if not valid:
            return None

        valid.sort(key=lambda e: e['time'])
        latest = valid[-1]

        if latest['type'] == 'BLOCK_RESTORE' and latest['result'] == 'SUCCESS':
            return 'BLOCKED'
        if latest['type'] == 'CHECK_RESTORE_ACCESS' and latest['result'] == 'SUCCESS':
            return 'ACTIVE'  # Restore access confirmed

        return None

    def audit(self, request, identity):
        """Audit a single deletion request."""
        case_id = request['case_id']
        audit_at = request['audit_at']

        if identity is None:
            return {
                'case_id': case_id,
                'deletion_status': 'NOT_APPLICABLE',
                'steps_json': []
            }

        identifiers = {
            'user_id': identity.get('user_id'),
            'emails': identity.get('emails', set()),
            'phones': identity.get('phones', set()),
            'email_hashes': identity.get('email_hashes', set()),
            'name': identity.get('name'),
        }

        # Find all matching evidence records
        matched_records = self.evidence_index.find_matching_records(identifiers, audit_at)
        self.last_trace = {}

        # Also search system_activity for data flows, restore risks, and failed deletions
        activity_findings = self._find_activity_findings(identifiers, audit_at, matched_records)

        if not matched_records and not activity_findings:
            self.last_trace = {}
            return {
                'case_id': case_id,
                'deletion_status': 'INCOMPLETE',
                'steps_json': [],
                'low_confidence': True,
            }

        # Classify each matched record into findings or compliant
        findings = []
        compliant_resources = []  # (record, action) tuples for verification

        for resource_id, record in matched_records.items():
            record_type = record.record_type
            state = record.state

            if state is None:
                continue

            category = RECORD_TYPE_TO_CATEGORY.get(record_type)
            if category is None:
                # Connectors and backups are handled via activity findings
                if record_type == 'connector' and state == 'ACTIVE':
                    findings.append({
                        'system_id': record.system_id,
                        'resource_id': resource_id,
                        'operation': 'REPORT_ACTIVE_DATA_FLOW',
                        'state': 'ACTIVE',
                        'evidence_id': record.file_id,
                        'record_type': record_type,
                        'action': None,
                    })
                elif record_type == 'connector' and state == 'DISABLED':
                    compliant_resources.append((record, 'FLOW_DISABLED'))
                elif record_type == 'backup' and state == 'ACTIVE':
                    findings.append({
                        'system_id': record.system_id,
                        'resource_id': resource_id,
                        'operation': 'REPORT_RESTORE_RISK',
                        'state': 'ACTIVE',
                        'evidence_id': record.file_id,
                        'record_type': record_type,
                        'action': None,
                    })
                elif record_type == 'backup' and state == 'BLOCKED':
                    compliant_resources.append((record, 'RESTORE_BLOCKED'))
                continue

            rule = self.deletion_rules.get(category)
            if not rule:
                continue

            action = rule['required_action']

            # RETAIN means the record should stay - verify it's present
            if action == 'RETAIN':
                if state == 'PRESENT':
                    compliant_resources.append((record, action))
                elif record_type == 'backup' and state == 'BLOCKED':
                    compliant_resources.append((record, 'RESTORE_BLOCKED'))
                elif (record_type == 'backup' and state == 'ACTIVE'):
                    findings.append({
                        'system_id': record.system_id,
                        'resource_id': resource_id,
                        'operation': 'REPORT_RESTORE_RISK',
                        'state': 'ACTIVE',
                        'evidence_id': record.file_id,
                        'record_type': record_type,
                        'action': None,
                    })
                continue

            # For DELETE, REDACT, ANONYMIZE actions
            finding_op = ACTION_TO_FINDING.get(action)
            remediation_op = ACTION_TO_REMEDIATION.get(action)
            verification_op = ACTION_TO_VERIFICATION.get(action)

            if not finding_op:
                continue

            # Determine if this record is a finding (non-compliant) or compliant
            is_violation = False

            if action == 'DELETE':
                # Record should not exist
                if state == 'PRESENT':
                    is_violation = True
                elif state == 'ABSENT':
                    compliant_resources.append((record, action))
                elif state in ('REDACTED', 'ANONYMIZED'):
                    # Record was treated differently than expected - could be compliant or not
                    # For DELETE, a redacted/anonymized record might be acceptable as a tombstone
                    if record_type == 'customer_profile':
                        # Account tombstone: redacted is compliant
                        compliant_resources.append((record, action))
                    else:
                        is_violation = True

            elif action == 'REDACT':
                # Record should have PII removed but record kept
                if state == 'PRESENT':
                    is_violation = True
                elif state == 'REDACTED':
                    compliant_resources.append((record, action))
                elif state == 'ABSENT':
                    # Record was deleted entirely - could be compliant or a violation
                    # For support messages, deletion is more than redaction
                    # Let's treat as compliant since the PII is gone
                    compliant_resources.append((record, action))

            elif action == 'ANONYMIZE':
                # Record should be unlinked from user
                if state == 'PRESENT':
                    is_violation = True
                elif state == 'ANONYMIZED':
                    compliant_resources.append((record, action))
                elif state == 'ABSENT':
                    compliant_resources.append((record, action))

            if is_violation:
                findings.append({
                    'system_id': record.system_id,
                    'resource_id': resource_id,
                    'operation': finding_op,
                    'state': 'PRESENT',
                    'evidence_id': record.file_id,
                    'record_type': record_type,
                    'action': action,
                })

        # Merge activity-based findings (data flows, restore risks)
        findings.extend(activity_findings)

        # Generate steps
        if findings:
            steps = self._generate_incomplete_steps(
                findings, matched_records, compliant_resources, audit_at
            )
            self.last_trace = self._build_trace(steps, matched_records)
            return {
                'case_id': case_id,
                'deletion_status': 'INCOMPLETE',
                'steps_json': steps,
            }
        else:
            steps = self._generate_complete_steps(compliant_resources, matched_records, audit_at)
            self.last_trace = self._build_trace(steps, matched_records)
            return {
                'case_id': case_id,
                'deletion_status': 'COMPLETE',
                'steps_json': steps,
            }

    def _build_trace(self, steps, matched_records):
        traces = {}
        for step in steps:
            record = matched_records.get(step.get('resource_id'))
            if record is None:
                continue
            category = RECORD_TYPE_TO_CATEGORY.get(record.record_type)
            rule = self.deletion_rules.get(category, {})
            identifier = self.evidence_index.last_match_details.get(
                record.resource_id
            )
            traces[step['step_no']] = {
                'file_id': record.file_id,
                'id_type': identifier[0] if identifier else '',
                'id_val': identifier[1] if identifier else '',
                'rule_id': rule.get('rule_id', ''),
            }
        return traces

    def _find_activity_findings(self, identifiers, audit_at, matched_records):
        """
        Phase 3/5: Find data flow, restore risk, and failed-deletion findings
        from system_activity using the SystemActivityLinker.
        Only emits findings for resources grounded to this user.
        """
        findings = []

        # 1. Active data flows linked to this user
        for rid, aid in self.linker.get_active_flows_for_user(identifiers, audit_at):
            # Check if we already have this from evidence
            ev_rec = matched_records.get(rid)
            if ev_rec and ev_rec.state == 'ACTIVE':
                # Update evidence_id to activity_id if available
                ev_rec.file_id = aid or ev_rec.file_id
                continue
            findings.append({
                'system_id': 'integration_service',
                'resource_id': rid,
                'operation': 'REPORT_ACTIVE_DATA_FLOW',
                'state': 'ACTIVE',
                'evidence_id': aid or '',
                'record_type': 'connector',
                'action': None,
            })

        # 2. Active restore risks linked to this user
        for rid, aid in self.linker.get_active_restores_for_user(identifiers, audit_at):
            ev_rec = matched_records.get(rid)
            if ev_rec and ev_rec.state == 'ACTIVE':
                ev_rec.file_id = aid or ev_rec.file_id
                continue
            findings.append({
                'system_id': 'backup_service',
                'resource_id': rid,
                'operation': 'REPORT_RESTORE_RISK',
                'state': 'ACTIVE',
                'evidence_id': aid or '',
                'record_type': 'backup',
                'action': None,
            })

        # 3. Failed deletions linked to this user → these are remaining records
        for rid, tgt_system, aid in self.linker.get_failed_deletions(identifiers, audit_at):
            # Determine system and record type from target_system
            sys_map = {
                'account_service': ('account_service', 'customer_profile'),
                'search_service': ('search_service', 'search_document'),
                'support_platform': ('support_platform', 'support_record'),
                'export_service': ('export_service', 'user_export'),
                'analytics_platform': ('analytics_platform', 'analytics_profile'),
            }
            sys_id, rec_type = sys_map.get(tgt_system, (tgt_system, 'unknown'))

            # Skip if already found in evidence
            if rid in matched_records:
                continue

            category = RECORD_TYPE_TO_CATEGORY.get(rec_type)
            if not category:
                continue
            rule = self.deletion_rules.get(category)
            if not rule:
                continue
            action = rule['required_action']
            finding_op = ACTION_TO_FINDING.get(action)
            if not finding_op:
                continue

            findings.append({
                'system_id': sys_id,
                'resource_id': rid,
                'operation': finding_op,
                'state': 'PRESENT',
                'evidence_id': aid or '',
                'record_type': rec_type,
                'action': action,
            })

        return findings

    def _generate_incomplete_steps(self, findings, matched_records,
                                    compliant_resources, audit_at):
        """Generate steps for an INCOMPLETE case."""
        steps = []
        step_no = 1

        # Sort findings by operation order, then system_id, then resource_id
        sorted_findings = sorted(findings, key=lambda f: (
            FINDING_ORDER.index(f['operation']) if f['operation'] in FINDING_ORDER else 99,
            f['system_id'],
            f['resource_id'],
        ))

        # FINDING phase
        for finding in sorted_findings:
            steps.append({
                'step_no': step_no,
                'phase': 'FINDING',
                'system_id': finding['system_id'],
                'resource_id': finding['resource_id'],
                'operation': finding['operation'],
                'state': finding['state'],
                'evidence_id': finding['evidence_id'],
            })
            step_no += 1

        # REMEDIATION phase - derive from finding action
        remediations = []
        for finding in sorted_findings:
            action = finding.get('action')

            if finding['operation'] == 'REPORT_ACTIVE_DATA_FLOW':
                remediations.append({
                    'system_id': finding['system_id'],
                    'resource_id': finding['resource_id'],
                    'operation': 'DISABLE_DATA_FLOW',
                    'state': 'DISABLED',
                })
            elif finding['operation'] == 'REPORT_RESTORE_RISK':
                remediations.append({
                    'system_id': finding['system_id'],
                    'resource_id': finding['resource_id'],
                    'operation': 'BLOCK_RESTORE',
                    'state': 'BLOCKED',
                })
            elif action and action in ACTION_TO_REMEDIATION:
                remediations.append({
                    'system_id': finding['system_id'],
                    'resource_id': finding['resource_id'],
                    'operation': ACTION_TO_REMEDIATION[action],
                    'state': ACTION_TO_REMEDIATION_STATE[action],
                })

        # Sort remediations
        remediations.sort(key=lambda r: (
            REMEDIATION_ORDER.index(r['operation']) if r['operation'] in REMEDIATION_ORDER else 99,
            r['system_id'],
            r['resource_id'],
        ))

        for rem in remediations:
            steps.append({
                'step_no': step_no,
                'phase': 'REMEDIATION',
                'system_id': rem['system_id'],
                'resource_id': rem['resource_id'],
                'operation': rem['operation'],
                'state': rem['state'],
                'evidence_id': '',
            })
            step_no += 1

        # VERIFICATION phase
        # For each finding, verify the required final state
        # For compliant resources (already correct state), verify them too
        verifications = []

        # Verification for findings (future state after remediation)
        for finding in sorted_findings:
            action = finding.get('action')

            if finding['operation'] == 'REPORT_ACTIVE_DATA_FLOW':
                verifications.append({
                    'system_id': finding['system_id'],
                    'resource_id': finding['resource_id'],
                    'operation': 'VERIFY_DATA_FLOW_DISABLED',
                    'state': 'DISABLED',
                })
            elif finding['operation'] == 'REPORT_RESTORE_RISK':
                verifications.append({
                    'system_id': finding['system_id'],
                    'resource_id': finding['resource_id'],
                    'operation': 'VERIFY_RESTORE_BLOCKED',
                    'state': 'BLOCKED',
                })
            elif action and action in ACTION_TO_VERIFICATION:
                verifications.append({
                    'system_id': finding['system_id'],
                    'resource_id': finding['resource_id'],
                    'operation': ACTION_TO_VERIFICATION[action],
                    'state': ACTION_TO_VERIFICATION_STATE[action],
                })

        # Verification for compliant resources (current state is already correct)
        for record, action in compliant_resources:
            if action == 'RETAIN':
                verifications.append({
                    'system_id': record.system_id,
                    'resource_id': record.resource_id,
                    'operation': 'VERIFY_RECORD_PRESENT',
                    'state': 'PRESENT',
                })
            elif action == 'FLOW_DISABLED':
                verifications.append({
                    'system_id': record.system_id,
                    'resource_id': record.resource_id,
                    'operation': 'VERIFY_DATA_FLOW_DISABLED',
                    'state': 'DISABLED',
                })
            elif action == 'RESTORE_BLOCKED':
                verifications.append({
                    'system_id': record.system_id,
                    'resource_id': record.resource_id,
                    'operation': 'VERIFY_RESTORE_BLOCKED',
                    'state': 'BLOCKED',
                })
            elif action in ACTION_TO_VERIFICATION:
                verifications.append({
                    'system_id': record.system_id,
                    'resource_id': record.resource_id,
                    'operation': ACTION_TO_VERIFICATION[action],
                    'state': ACTION_TO_VERIFICATION_STATE[action],
                })

        # Sort verifications
        verifications.sort(key=lambda v: (
            VERIFICATION_ORDER.index(v['operation']) if v['operation'] in VERIFICATION_ORDER else 99,
            v['system_id'],
            v['resource_id'],
        ))

        # Deduplicate
        seen = set()
        for v in verifications:
            key = (v['operation'], v['system_id'], v['resource_id'])
            if key not in seen:
                seen.add(key)
                steps.append({
                    'step_no': step_no,
                    'phase': 'VERIFICATION',
                    'system_id': v['system_id'],
                    'resource_id': v['resource_id'],
                    'operation': v['operation'],
                    'state': v['state'],
                    'evidence_id': '',
                })
                step_no += 1

        return steps

    def _generate_complete_steps(self, compliant_resources, matched_records, audit_at):
        """Generate verification steps for a COMPLETE case."""
        steps = []

        verifications = []

        for record, action in compliant_resources:
            if action == 'RETAIN':
                verifications.append({
                    'system_id': record.system_id,
                    'resource_id': record.resource_id,
                    'operation': 'VERIFY_RECORD_PRESENT',
                    'state': 'PRESENT',
                    'evidence_id': record.file_id,
                })
            elif action == 'FLOW_DISABLED':
                verifications.append({
                    'system_id': record.system_id,
                    'resource_id': record.resource_id,
                    'operation': 'VERIFY_DATA_FLOW_DISABLED',
                    'state': 'DISABLED',
                    'evidence_id': record.file_id,
                })
            elif action == 'RESTORE_BLOCKED':
                verifications.append({
                    'system_id': record.system_id,
                    'resource_id': record.resource_id,
                    'operation': 'VERIFY_RESTORE_BLOCKED',
                    'state': 'BLOCKED',
                    'evidence_id': record.file_id,
                })
            elif action in ACTION_TO_VERIFICATION:
                verifications.append({
                    'system_id': record.system_id,
                    'resource_id': record.resource_id,
                    'operation': ACTION_TO_VERIFICATION[action],
                    'state': ACTION_TO_VERIFICATION_STATE[action],
                    'evidence_id': record.file_id,
                })

        # Sort verifications
        verifications.sort(key=lambda v: (
            VERIFICATION_ORDER.index(v['operation']) if v['operation'] in VERIFICATION_ORDER else 99,
            v['system_id'],
            v['resource_id'],
        ))

        # Deduplicate
        seen = set()
        for v in verifications:
            key = (v['operation'], v['system_id'], v['resource_id'])
            if key not in seen:
                seen.add(key)
                steps.append({
                    'step_no': len(steps) + 1,
                    'phase': 'VERIFICATION',
                    'system_id': v['system_id'],
                    'resource_id': v['resource_id'],
                    'operation': v['operation'],
                    'state': v['state'],
                    'evidence_id': v['evidence_id'],
                })

        return steps
