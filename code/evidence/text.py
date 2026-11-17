"""Plain-text handover manifests."""

import hashlib
import json
import os
import re
import sqlite3
from collections import defaultdict
from pathlib import Path

from .records import CAPTURE_CUTOFF_RULE, RECORD_CUTOFF_RULE, EvidenceIndex, EvidenceRecord


class TextParserMixin:
    # ── Text (handover) ───────────────────────────────────────────────────
    _TYPE_MAP = {
        'USER_PROFILE': ('account_service', 'customer_profile'),
        'SEARCH_INDEX_ENTRY': ('search_service', 'search_document'),
        'ANALYTICS_PROFILE': ('analytics_platform', 'analytics_profile'),
        'SUPPORT_MESSAGE': ('support_platform', 'support_record'),
        'SUPPORT_ATTACHMENT': ('support_platform', 'support_attachment'),
        'USER_EXPORT': ('export_service', 'user_export'),
        'DATA_FLOW': ('integration_service', 'connector'),
        'BACKUP_ARCHIVE': ('backup_service', 'backup'),
        'SECURITY_AUDIT_LOG': ('security_service', 'security_audit'),
        'LEGAL_HOLD_RECORD': ('legal_service', 'legal_hold'),
    }
    _STATUS_MAP = {
        'NOT_FOUND': 'ABSENT', 'FOUND': 'PRESENT', 'IDENTIFIABLE': 'PRESENT',
        'ANONYMIZED': 'ANONYMIZED', 'REDACTED': 'REDACTED',
        'ACTIVE': 'ACTIVE', 'DISABLED': 'DISABLED', 'BLOCKED': 'BLOCKED',
    }

    def _add_manifest_rows(self, records, file_id, default_captured_at, index,
                            source_format='json_generic', file_captured_at=None):
        """Rows shaped like an export/audit manifest entry: each names its own
        record_type/system/result rather than belonging to one fixed collection."""
        for d in records:
            if not isinstance(d, dict):
                continue
            rid = d.get('resource_id')
            if not rid:
                continue
            mapping = self._TYPE_MAP.get(str(d.get('record_type', '')).upper())
            if not mapping:
                continue
            sys_id, rec_type = mapping
            sys_id = d.get('system') or sys_id
            slot, val = self._classify_identifier(d.get('subject_reference') or d.get('lookup_value'))
            ids = {slot: val} if slot else {}
            state = self._STATUS_MAP.get(str(d.get('result', '')).upper(), 'PRESENT')
            ts = d.get('recorded_at', default_captured_at)
            index.add_record(self._make(
                file_id, file_captured_at or ts, sys_id, rid, rec_type, state, ids, raw=d,
                record_timestamp=ts, source_format=source_format,
            ))

    def _parse_text_file(self, filepath, file_id, captured_at, index):
        try:
            content = filepath.read_text(encoding='utf-8')
        except Exception:
            return
        if 'SHIFT HANDOVER' not in content and 'data_category' not in content.lower():
            return

        for line in content.split('\n'):
            line = line.strip()
            if not line:
                continue
            if any(x in line for x in ('SHIFT HANDOVER', 'Snapshot:', 'Account and downstream')):
                continue
            if line.startswith('- '):
                line = line[2:]
            parts = [p.strip() for p in line.split('|')]
            if len(parts) < 6:
                continue
            ts, sys_raw, rid, cat, status_raw, identifier = parts[:6]
            sys_id, rec_type = self._TYPE_MAP.get(cat, (sys_raw, cat.lower()))
            state = self._STATUS_MAP.get(status_raw, status_raw)
            ids = {}
            if identifier:
                if identifier.startswith('user_'):
                    ids['customer_reference'] = identifier
                elif '@' in identifier:
                    ids['email'] = identifier
                else:
                    ids['customer_reference'] = identifier
            index.add_record(self._make(
                file_id, captured_at, sys_id, rid, rec_type, state, ids,
                raw={'raw_line': line},
                record_timestamp=ts, source_format='txt_handover',
            ))
