"""Service logs in kv, lambda, syslog, pipe and bracket dialects."""

import hashlib
import json
import os
import re
import sqlite3
from collections import defaultdict
from pathlib import Path

from .records import CAPTURE_CUTOFF_RULE, RECORD_CUTOFF_RULE, EvidenceIndex, EvidenceRecord


class LogParserMixin:
    # ── Log ───────────────────────────────────────────────────────────────
    _KV_RE = re.compile(r'(\w+)=(?:"([^"]*)"|(\S+))')
    _TS_RE = re.compile(r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)')
    _LOG_ID_KEYS = (
        'subject_reference', 'subject_ref', 'lookup_key', 'owner_key',
        'owner_email', 'match_key', 'matched_value', 'correlation_key',
        'scan_key', 'subject_key',
    )

    def _parse_log_file(self, filepath, file_id, captured_at, index):
        try:
            content = filepath.read_text(encoding='utf-8')
        except Exception:
            return

        lines = content.split('\n')
        trace_identifiers = {}
        for line in lines:
            kv = self._log_fields(line)
            trace_id = kv.get('trace_id')
            # Any subject key counts: audit-record traces use subject_ref,
            # search traces use match_key.
            identifier = next(
                (kv[k] for k in self._LOG_ID_KEYS if kv.get(k)), None)
            if trace_id and identifier:
                trace_identifiers[trace_id] = identifier

        for line in lines:
            if not line.strip():
                continue
            ts_m = self._TS_RE.search(line)
            if not ts_m:
                continue
            event_time = ts_m.group(1)

            kv = self._log_fields(line)
            if not any(k in kv for k in ('lookup_key', 'subject_key', 'owner_key',
                                         'matched_value', 'correlation_key',
                                         'subject_reference', 'subject_ref',
                                         'owner_email', 'match_key', 'scan_key')):
                inherited = trace_identifiers.get(kv.get('trace_id'))
                if inherited:
                    kv['lookup_key'] = inherited

            service     = kv.get('service', '')
            if service == 'support_replica':
                service = 'support_platform'
            if service not in {
                'account_service', 'search_service', 'analytics_platform',
                'support_platform', 'security_service', 'export_service',
            }:
                system_service = kv.get('system', '')
                if system_service in {
                    'account_service', 'search_service', 'analytics_platform',
                    'support_platform', 'security_service', 'export_service',
                }:
                    service = system_service
            event       = kv.get('event', '')
            resource_id = kv.get('resource_id')
            if not resource_id:
                continue

            # A lookup row that states its own record_type and result is a
            # manifest row in log form.
            if (str(kv.get('record_type', '')).upper() in self._TYPE_MAP
                    and str(kv.get('result', '')).upper() in self._STATUS_MAP):
                self._add_manifest_rows(
                    [dict(kv, recorded_at=event_time)], file_id, captured_at,
                    index, source_format='log', file_captured_at=captured_at)
                continue

            generic = self._parse_generic_log_record(
                service, kv, resource_id, file_id, captured_at, event_time
            )
            if generic is not None:
                index.add_record(generic)
                continue

            rec = self._log_line_to_record(service, event, kv, resource_id,
                                           file_id, captured_at, event_time)
            if rec:
                index.add_record(rec)

    def _log_fields(self, line):
        """Normalize direct, nested-message, JSON, syslog, and pipe log fields."""
        kv = {
            m.group(1): m.group(2) if m.group(2) is not None else m.group(3)
            for m in self._KV_RE.finditer(line)
        }
        message_match = re.search(r'message="((?:\\.|[^"])*)"', line)
        message = (
            message_match.group(1).replace(r'\"', '"')
            if message_match else kv.get('message')
        )
        if message:
            nested = {}
            nested_re = re.compile(r'(\w+)=(?:"((?:\\.|[^"])*)"|(\S+))')
            for match in nested_re.finditer(message):
                value = match.group(2) if match.group(2) is not None else match.group(3)
                nested[match.group(1)] = value.replace(r'\"', '"')
            kv.update(nested)
        json_start = line.find('{')
        if json_start >= 0:
            try:
                structured = json.loads(line[json_start:])
                if isinstance(structured, dict):
                    kv.update(structured)
            except (TypeError, ValueError):
                pass
        if 'service' not in kv:
            service_match = re.search(
                r'\b(account_service|search_service|search_index_service|'
                r'analytics_platform|support_platform|export_service|'
                r'security_service|integration_service|backup_service|legal_service)\b',
                line,
            )
            if service_match:
                kv['service'] = service_match.group(1)
        if kv.get('service') == 'search_index_service':
            kv['service'] = kv.get('system', 'search_index_service')
        # Pipe dialect: "ts | LEVEL | service | trace | event | k=v ..."
        parts = line.split(' | ')
        if len(parts) >= 6:
            kv.setdefault('level', parts[1].strip())
            kv.setdefault('event', parts[4].strip())
        # Bracket dialect: "ts [LEVEL] [service] [trace] event: k=v ..."
        bracket = re.match(r'\S+ \[(\w+)\] \[\w+\] \[[\w-]+\] (\w+):', line)
        if bracket:
            kv.setdefault('level', bracket.group(1))
            kv.setdefault('event', bracket.group(2))
        # Lambda logs name the trace requestId; syslog and pipe logs carry it
        # positionally. Without it a result row cannot inherit the subject
        # named on its trace's *_started row.
        if not kv.get('trace_id'):
            positional = re.search(r'(?:^|[\s|\[])((?:tr|rb)-\d[\w-]*)', line)
            trace_id = kv.get('requestId') or (positional and positional.group(1))
            if trace_id:
                kv['trace_id'] = trace_id
        return kv

    def _parse_generic_log_record(self, service, kv, resource_id,
                                  file_id, captured_at, event_time):
        """Parse only same-row links with an explicit, supported state signal."""
        link_values = [
            self._clean(kv.get(key)) for key in self._LOG_ID_KEYS
            if self._clean(kv.get(key))
        ]
        if not link_values:
            return None

        event = str(kv.get('event', '')).lower()
        if event.endswith('_started') or event in {
            'profile_lookup_started', 'index_query_started',
            'audit_record_query_started', 'message_scan_started',
            'attachment_scan_started', 'analytics_profile_scan_started',
        }:
            return None

        state = None
        explicit = ' '.join(
            str(kv.get(key, '')).lower()
            for key in ('result', 'reported_result', 'status', 'state', 'rows',
                        'http_status', 'available')
        )
        if re.search(r'\bnot_found\b|\bnot found\b', explicit):
            state = 'ABSENT'
        elif str(kv.get('rows', '')).strip() == '0':
            state = 'ABSENT'
        elif re.search(r'\bfound\b|\bhit\b', explicit):
            state = 'PRESENT'
        elif str(kv.get('rows', '')).strip().isdigit():
            rows = int(str(kv.get('rows')).strip())
            if rows >= 1 and str(kv.get('http_status', '')).strip() == '200':
                state = 'PRESENT'
        elif str(kv.get('available', '')).lower() == 'true':
            state = 'PRESENT'

        pii_warning = (
            ('pii_scan' in event or 'identity_scan' in event)
            and str(kv.get('level', '')).upper() in {'WARN', 'WARNING'}
        )
        if pii_warning:
            state = 'PRESENT'
        if state is None:
            return None

        identifiers = {
            'email': None,
            'phone': None,
            'email_hash': None,
            'customer_reference': None,
        }
        for value in link_values:
            if '@' in value:
                identifiers['email'] = value
            elif re.fullmatch(r'user_[A-Za-z0-9_-]+', value):
                identifiers['customer_reference'] = value
            elif re.fullmatch(r'[0-9a-fA-F]{40,}', value):
                identifiers['email_hash'] = value
            elif re.search(r'\d', value) and (
                value.startswith('+') or re.fullmatch(r'[\d ()-]+', value)
            ):
                identifiers['phone'] = value

        if not any(identifiers.values()):
            return None

        service_map = {
            'account_service': ('account_service', 'customer_profile'),
            'search_service': ('search_service', 'search_document'),
            'analytics_platform': ('analytics_platform', 'analytics_profile'),
            'support_platform': ('support_platform', 'support_record'),
            'security_service': ('security_service', 'security_audit'),
            'export_service': ('export_service', 'user_export'),
        }
        system_id, record_type = service_map.get(service, (None, None))
        if not system_id:
            return None
        if pii_warning and record_type not in {
            'analytics_profile', 'support_record'
        }:
            return None

        return self._make(
            file_id, captured_at, system_id, resource_id, record_type, state,
            identifiers, raw=kv, record_timestamp=event_time,
            source_format='log',
        )

    def _log_line_to_record(self, service, event, kv, resource_id,
                             file_id, captured_at, event_time):
        m = self._make  # shorthand
        if event.endswith('_started'):
            return None  # a started row names the subject, never a result

        if service == 'account_service':
            if 'profile_lookup_completed' in event or 'profile_lookup' in event and 'completed' in event:
                rows = int(kv.get('rows', -1))
                code = kv.get('http_status', '200')
                # The queried identifier: lookup_key or correlation_key
                query_key = kv.get('lookup_key') or kv.get('correlation_key')
                if rows == 0 or code == '404':
                    state = 'ABSENT'
                elif rows > 0:
                    state = 'PRESENT'
                else:
                    return None
                ids = {'email': query_key if query_key and '@' in query_key else None,
                       'customer_reference': query_key if query_key and query_key.startswith('user_') else None}
                return m(file_id, captured_at, 'account_service', resource_id,
                         'customer_profile', state, ids, raw=kv,
                         record_timestamp=event_time, source_format='log')

        elif service == 'search_service':
            if 'index_query_completed' in event:
                result = kv.get('result', '')
                key = (kv.get('match_key') or kv.get('correlation_key')
                       or kv.get('lookup_key'))
                state = 'PRESENT' if result == 'hit' else 'ABSENT'
                ids = {'email': key if key and '@' in key else None}
                return m(file_id, captured_at, 'search_service', resource_id,
                         'search_document', state, ids, raw=kv,
                         record_timestamp=event_time, source_format='log')

        elif service == 'analytics_platform':
            if 'analytics_identity_scan' in event or 'identity_scan' in event:
                val = kv.get('matched_value')
                ids = {'email': val if val and '@' in val else None,
                       'email_hash': val if val and '@' not in val and len(val) > 20 else None}
                if ids.get('email') or ids.get('email_hash'):
                    return m(file_id, captured_at, 'analytics_platform', resource_id,
                             'analytics_profile', 'PRESENT', ids, raw=kv,
                             record_timestamp=event_time, source_format='log')
            elif 'contact_lookup_completed' in event:
                rows = int(kv.get('rows', 0))
                corr = kv.get('correlation_key')
                ids = {'email_hash': corr if corr and '@' not in corr else None}
                # A contact lookup reads the contact index, not a profile:
                # the row is a secondary identifier (rule: always delete).
                state = 'PRESENT' if rows > 0 else 'ABSENT'
                return m(file_id, captured_at, 'analytics_platform', resource_id,
                         'secondary_identifier', state, ids, raw=kv,
                         record_timestamp=event_time, source_format='log')
            elif 'analytics_profile_read' in event:
                # _clean: a literal "null" field is not an identifier.
                ids = {
                    'email': self._clean(kv.get('email') or kv.get('customer_email')),
                    'phone': self._clean(kv.get('phone') or kv.get('customer_phone')),
                    'email_hash': self._clean(kv.get('email_hash')),
                    'customer_reference': self._clean(kv.get('customer_reference')),
                }
                state = 'PRESENT' if any(ids.values()) else 'ANONYMIZED'
                return m(file_id, captured_at, 'analytics_platform', resource_id,
                         'analytics_profile', state, ids, raw=kv,
                         record_timestamp=event_time, source_format='log')

        elif service == 'support_platform':
            if 'contact_query_completed' in event:
                rows = int(kv.get('rows', 0))
                key = kv.get('lookup_key')
                ids = {'email': key if key and '@' in key else None,
                       'phone': key if key and '@' not in key else None}
                if rows > 0:
                    # Contact-index row, not a message: secondary identifier.
                    return m(file_id, captured_at, 'support_platform', resource_id,
                             'secondary_identifier', 'PRESENT', ids, raw=kv,
                             record_timestamp=event_time, source_format='log')
            if 'message_pii_scan' in event or 'attachment_pii_scan' in event:
                val = kv.get('matched_value')
                ids = {'email': val if val and '@' in val else None,
                       'phone': val if val and '@' not in val and '+' in val else None}
                if ids.get('email') or ids.get('phone'):
                    return m(file_id, captured_at, 'support_platform', resource_id,
                             'support_record', 'PRESENT', ids, raw=kv,
                             record_timestamp=event_time, source_format='log')
            if 'message_read' in event and kv.get('message_text') == '[REDACTED]':
                return m(file_id, captured_at, 'support_platform', resource_id,
                         'support_record', 'REDACTED', {}, raw=kv,
                         record_timestamp=event_time, source_format='log')
            if 'support_ticket_read_completed' in event:
                c = self._clean
                ids = {
                    'email': c(kv.get('requester_email')) or c(kv.get('customer_email')),
                    'phone': c(kv.get('requester_phone')) or c(kv.get('customer_phone')),
                    'customer_reference': c(kv.get('customer_reference')),
                }
                if any(ids.values()):
                    # Only the stable reference left means the ticket is redacted.
                    state = 'PRESENT' if (ids['email'] or ids['phone']) else 'REDACTED'
                    return m(file_id, captured_at, 'support_platform', resource_id,
                             'support_record', state, ids, raw=kv,
                             record_timestamp=event_time, source_format='log')

        elif service == 'integration_service':
            if 'connector_heartbeat' in event or 'connector_config_loaded' in event:
                enabled = kv.get('enabled', 'false')
                key = kv.get('subject_key') or kv.get('lookup_key')
                ids = {'email': key if key and '@' in key else None,
                       'customer_reference': key if key and key.startswith('user_') else None}
                state = 'ACTIVE' if enabled == 'true' else 'DISABLED'
                return m(file_id, captured_at, 'integration_service', resource_id,
                         'connector', state, ids, raw=kv,
                         record_timestamp=event_time, source_format='log')
            if 'connector_config_read_completed' in event:
                key = kv.get('customer_email') or kv.get('customer_reference')
                ids = {
                    'email': key if key and '@' in key else None,
                    'customer_reference': key if key and key.startswith('user_') else None,
                }
                enabled = str(kv.get('enabled', 'false')).lower()
                state = 'ACTIVE' if enabled == 'true' else 'DISABLED'
                return m(file_id, captured_at, 'integration_service', resource_id,
                         'connector', state, ids, raw=kv,
                         record_timestamp=event_time, source_format='log')

        elif service == 'backup_service':
            if 'restore_candidate_evaluated' in event:
                block = kv.get('deletion_block', 'false')
                key = kv.get('subject_key') or kv.get('lookup_key')
                ids = {'email': key if key and '@' in key else None,
                       'customer_reference': key if key and key.startswith('user_') else None}
                state = 'BLOCKED' if block == 'true' else 'ACTIVE'
                return m(file_id, captured_at, 'backup_service', resource_id,
                         'backup', state, ids, raw=kv,
                         record_timestamp=event_time, source_format='log')
            state = None
            if 'restore_policy_read_completed' in event:
                state = 'ACTIVE' if kv.get('restore_allowed') == 'true' else 'BLOCKED'
            elif 'restore_authorization_completed' in event:
                state = {'deny': 'BLOCKED', 'allow': 'ACTIVE'}.get(kv.get('decision'))
            if state:
                ids = {'email': self._clean(kv.get('customer_email')),
                       'customer_reference': self._clean(kv.get('customer_reference'))}
                return m(file_id, captured_at, 'backup_service', resource_id,
                         'backup', state, ids, raw=kv,
                         record_timestamp=event_time, source_format='log')

        elif service == 'legal_service':
            if 'retained_order_loaded' in event:
                return m(file_id, captured_at, 'legal_service', resource_id,
                         'legal_hold', 'PRESENT', {}, raw=kv,
                         record_timestamp=event_time, source_format='log')

        elif service == 'security_service':
            if 'audit_record_read_completed' in event:
                rows = int(kv.get('rows', 0))
                subj = (
                    kv.get('subject_reference')
                    or kv.get('subject_ref')
                    or kv.get('correlation_key')
                    or kv.get('lookup_key')
                )
                ids = {'customer_reference': subj if subj and subj.startswith('user_') else None}
                state = 'PRESENT' if rows > 0 else 'ABSENT'
                return m(file_id, captured_at, 'security_service', resource_id,
                         'security_audit', state, ids, raw=kv,
                         record_timestamp=event_time, source_format='log')

        elif service == 'export_service':
            if 'download_check_completed' in event or 'export_download_check_completed' in event:
                avail = kv.get('available', 'false')
                key = kv.get('owner_key')
                ids = {'email': key if key and '@' in key else None}
                state = 'PRESENT' if avail == 'true' else 'ABSENT'
                return m(file_id, captured_at, 'export_service', resource_id,
                         'user_export', state, ids, raw=kv,
                         record_timestamp=event_time, source_format='log')

        return None
