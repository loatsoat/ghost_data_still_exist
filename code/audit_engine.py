"""
Audit Engine - Core deletion audit logic.
Derives finding and remediation operations from deletion_rules.csv action.
Tracks data flows and restore risks from system_activity as of audit_at.
Uses a reverse identifier index for matching.
"""

import copy
import re
from collections import defaultdict

from activity_linker import SystemActivityLinker
from evidence import EvidenceParser, EvidenceRecord
from policy import (
    RECORD_TYPE_TO_CATEGORY,
    IDENTIFIER_FREE_STATE,
    ACTION_TO_FINDING,
    COMPLIANT_STATES,
)
from steps import plan_and_verify, verify_complete


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
        """Audit one deletion request: find violations, plan fixes, verify."""
        case_id = request['case_id']
        self.last_trace = {}
        if identity is None:
            # Fail closed: a deletion request whose subject cannot be resolved
            # cannot be proven COMPLETE (NOT_APPLICABLE is for non-deletion requests).
            return {'case_id': case_id, 'deletion_status': 'INCOMPLETE', 'steps_json': []}

        audit_at = request['audit_at']
        identifiers = {
            'user_id': identity.get('user_id'),
            'emails': identity.get('emails', set()),
            'phones': identity.get('phones', set()),
            'email_hashes': identity.get('email_hashes', set()),
            'name': identity.get('name'),
        }
        matched_records, uncitable = self._gather_records(
            identifiers, request.get('requested_at', ''), audit_at)
        activity_findings = self._find_activity_findings(identifiers, audit_at, matched_records)
        if not matched_records and not activity_findings:
            self.last_trace = {}
            return {'case_id': case_id, 'deletion_status': 'INCOMPLETE', 'steps_json': []}

        findings, compliant = self._find(matched_records, uncitable)
        findings.extend(activity_findings)
        if findings:
            status = 'INCOMPLETE'
            steps = plan_and_verify(findings, compliant)
        else:
            # Every step of a COMPLETE case must cite evidence.
            status = 'COMPLETE'
            steps = verify_complete(
                [(r, a) for r, a in compliant if r.resource_id not in uncitable])
        self.last_trace = self._build_trace(steps, matched_records)
        return {'case_id': case_id, 'deletion_status': status, 'steps_json': steps}

    def _gather_records(self, identifiers, requested_at, audit_at):
        """Evidence records for the subject at audit_at, plus the ids that cannot be cited.

        A snapshot taken by audit_at but exported in a later bundle shows the
        state at audit_at, yet its file cannot be cited. Such records only add
        uncited verification steps to an INCOMPLETE case.
        """
        with_late = self.evidence_index.find_matching_records(
            identifiers, audit_at, by_record_time=True)
        matched = self.evidence_index.find_matching_records(identifiers, audit_at)
        uncitable = {rid for rid in with_late if rid not in matched}
        for rid in uncitable:
            matched[rid] = with_late[rid]
        self._add_catalog_linked_records(identifiers, requested_at, audit_at, matched)
        return matched, uncitable

    def _find(self, matched_records, uncitable):
        """Split records into policy violations and compliant (record, action) pairs."""
        findings, compliant = [], []
        for resource_id, record in matched_records.items():
            finding, ok = self._classify_record(resource_id, record)
            # A finding must cite its evidence, so an uncitable record cannot be one.
            if finding and resource_id not in uncitable:
                findings.append(finding)
            if ok:
                compliant.append(ok)
        return findings, compliant

    def _classify_record(self, resource_id, record):
        """Return (finding, compliant): a violation to report or a (record, action) to verify."""
        record_type, state = record.record_type, record.state
        if state is None:
            return None, None

        def finding(operation, action):
            return {
                'system_id': record.system_id, 'resource_id': resource_id,
                'operation': operation,
                'state': 'ACTIVE' if action is None else 'PRESENT',
                'evidence_id': record.file_id, 'record_type': record_type, 'action': action,
            }

        # Connectors have no policy category: an active one is a data flow to stop.
        if record_type == 'connector':
            if state == 'ACTIVE':
                return finding('REPORT_ACTIVE_DATA_FLOW', None), None
            return None, ((record, 'FLOW_DISABLED') if state == 'DISABLED' else None)

        rule = self.deletion_rules.get(RECORD_TYPE_TO_CATEGORY.get(record_type))
        if not rule:
            return None, None
        action = rule['required_action']
        if action == 'RETAIN':
            if state == 'PRESENT':
                return None, (record, action)
            # A retained backup must not be able to restore the deleted data.
            if record_type == 'backup' and state == 'ACTIVE':
                return finding('REPORT_RESTORE_RISK', None), None
            if record_type == 'backup' and state == 'BLOCKED':
                return None, (record, 'RESTORE_BLOCKED')
            return None, None
        if action not in ACTION_TO_FINDING:
            return None, None
        if state == 'PRESENT':
            return finding(ACTION_TO_FINDING[action], action), None
        if state in COMPLIANT_STATES[action]:
            return None, (record, action)
        if action == 'DELETE' and state in ('REDACTED', 'ANONYMIZED'):
            # A redacted account profile is an allowed tombstone; anything else is not deleted.
            if record_type == 'customer_profile':
                return None, (record, action)
            return finding(ACTION_TO_FINDING[action], action), None
        return None, None

    def _add_catalog_linked_records(self, identifiers, requested_at, audit_at,
                                    matched_records):
        """
        A LINK_RESOURCE_IDENTITY event ties a resource and its alias (a file
        name, a statement number) to the subject. A screenshot or PDF that
        shows the resource under that alias, or shows the subject in the
        link's own system, is then evidence of the resource's state even
        though the document never prints the resource id.

        Only documents captured between the request and the audit count: a
        capture from before the request cannot show what the deletion left.
        """
        def has_token(token, text):
            return bool(token) and re.search(
                r'(?<![\w.-])' + re.escape(token.lower()) + r'(?!\w)', text)

        emails = {e.lower() for e in identifiers.get('emails', set()) if e}
        user_id = identifiers.get('user_id') or ''
        name = (identifiers.get('name') or '').lower().strip()

        links = self.linker.get_links_for_user(identifiers, audit_at)

        # A console screenshot lists several people's rows, and the parser
        # ties a row to whichever identifier sits near it. When the catalog
        # names the subject's row, the other rows of that screenshot belong
        # to other people.
        linked = {rid for rid, _, _ in links}
        for rid in linked & matched_records.keys():
            shot = matched_records[rid]
            if shot.source_format != 'image_ocr':
                continue
            for other, record in list(matched_records.items()):
                if (other not in linked and record.file_id == shot.file_id
                        and record.source_format == 'image_ocr'):
                    del matched_records[other]

        for rid, alias, system in links:
            if rid in matched_records:
                continue
            parsed_system, record_type = EvidenceParser._rid_to_system(rid)
            if parsed_system == 'unknown_service':
                continue

            best = None
            for file_id, captured_at, origin, text in self.evidence_index.documents:
                if not requested_at <= captured_at <= audit_at:
                    continue
                if best and captured_at <= best[1]:
                    continue
                text = text.lower()
                # A user reference in the alias slot names the subject, not
                # the resource, so it only counts inside the link's system.
                names_resource = has_token(rid, text) or (
                    alias != user_id and has_token(alias, text))
                shows_subject = origin == system and (
                    has_token(user_id, text) or any(e in text for e in emails))
                if names_resource or shows_subject:
                    best = (file_id, captured_at, text)
            if not best:
                continue

            file_id, captured_at, text = best
            exposed = any(e in text for e in emails) or (name and name in text)
            state = 'PRESENT' if exposed else IDENTIFIER_FREE_STATE.get(
                record_type, 'PRESENT')
            matched_records[rid] = EvidenceRecord(
                file_id, captured_at, system or parsed_system, rid, record_type,
                state, {'customer_reference': user_id}, source_format='document')

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
                if aid:
                    # Copy: evidence records are shared across cases.
                    matched_records[rid] = copy.copy(ev_rec)
                    matched_records[rid].file_id = aid
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
                if aid:
                    # Copy: evidence records are shared across cases.
                    matched_records[rid] = copy.copy(ev_rec)
                    matched_records[rid].file_id = aid
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
