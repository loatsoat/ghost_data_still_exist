"""SQLite snapshot exports (primary, replica, reporting tables)."""

import hashlib
import json
import os
import re
import sqlite3
from collections import defaultdict
from pathlib import Path

from .records import CAPTURE_CUTOFF_RULE, RECORD_CUTOFF_RULE, EvidenceIndex, EvidenceRecord
from .json_files import JsonParserMixin


class SqlParserMixin:
    # ── SQL ───────────────────────────────────────────────────────────────
    _SQL_TABLE_MAP = {
        'customer_profiles': ('account_service', 'customer_profile', {
            'email': 'email', 'phone': 'phone', 'email_hash': 'email_hash',
            'customer_reference': 'customer_reference', 'name': 'full_name',
        }),
        'customer_search_documents': ('search_service', 'search_document', {
            'email': 'email', 'phone': 'phone', 'email_hash': 'email_hash',
            'customer_reference': 'customer_reference',
        }),
        'customer_analytics_profiles': ('analytics_platform', 'analytics_profile', {
            'email': 'email', 'phone': 'phone', 'email_hash': 'email_hash',
            'customer_reference': 'customer_reference',
        }),
        'support_records': ('support_platform', 'support_record', {
            'email': 'requester_email', 'phone': 'requester_phone',
            'customer_reference': 'customer_reference', 'name': 'requester_name',
        }),
        'customer_exports': ('export_service', 'user_export', {
            'email': 'owner_email', 'phone': 'owner_phone',
            'customer_reference': 'customer_reference',
        }),
        'connector_subscriptions': ('integration_service', 'connector', {
            'email': 'customer_email', 'customer_reference': 'customer_reference',
        }),
        'backup_restore_entries': ('backup_service', 'backup', {
            'email': 'customer_email', 'customer_reference': 'customer_reference',
        }),
        'security_audit_records': ('security_service', 'security_audit', {
            'customer_reference': 'subject_reference',
        }),
    }

    def _parse_sql_file(self, filepath, file_id, captured_at, index):
        try:
            sql_content = filepath.read_text(encoding='utf-8')
        except Exception:
            return
        try:
            conn = sqlite3.connect(':memory:')
            conn.executescript(sql_content)
        except Exception:
            return
        cursor = conn.cursor()

        table_names = {
            row[0] for row in cursor.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
        }
        lower_name = filepath.name.lower()
        replica = next((
            label for marker, label in (
                ('failover', 'failover'),
                ('regional', 'regional'),
                ('reporting', 'reporting'),
                ('read_replica', 'read_replica'),
                ('primary', 'primary'),
                ('inventory', 'inventory'),
            ) if marker in lower_name
        ), 'unknown')
        self.sql_metadata[file_id] = {
            'path': str(filepath),
            'replica': replica,
            'tables': sorted(table_names),
            'row_counts': {},
        }
        for table_name in table_names:
            try:
                count = cursor.execute(
                    f"SELECT COUNT(*) FROM [{table_name}]"
                ).fetchone()[0]
                self.sql_metadata[file_id]['row_counts'][table_name] = count
            except sqlite3.Error:
                self.sql_metadata[file_id]['row_counts'][table_name] = None
        for table, (system_id, record_type, id_map) in self._SQL_TABLE_MAP.items():
            matching_tables = [
                name for name in table_names
                if name == table or name.startswith(table + '_')
                or (
                    table == 'customer_profiles'
                    and 'profile' in name and 'customer' in name
                )
                or (
                    table == 'customer_search_documents'
                    and 'search' in name and 'document' in name
                )
            ]
            for actual_table in matching_tables:
                try:
                    cursor.execute(f"SELECT * FROM [{actual_table}]")
                    cols = [d[0] for d in cursor.description]
                    for row in cursor.fetchall():
                        d = dict(zip(cols, row))
                        rid = d.get('resource_id')
                        if not rid:
                            continue
                        ids = self._ids_from_dict(d, id_map)
                        state = self._sql_state(record_type, d, ids)
                        rec_ts = d.get('updated_at', captured_at)
                        index.add_record(self._make(
                            file_id, captured_at, system_id, rid,
                            record_type, state, ids, raw=d,
                            record_timestamp=rec_ts, source_format='sql',
                        ))
                except Exception:
                    continue

        # Inventory/replica snapshots may store heterogeneous records as JSON
        # rows instead of exposing one table per data category.
        for table in table_names:
            try:
                cursor.execute(f"SELECT * FROM [{table}]")
                cols = [d[0] for d in cursor.description]
                if not {'record_json', 'collection_name'}.issubset(cols):
                    continue
                for row in cursor.fetchall():
                    outer = dict(zip(cols, row))
                    try:
                        data = json.loads(outer['record_json'])
                    except (TypeError, ValueError):
                        continue
                    if isinstance(data.get('document'), dict):
                        flattened = dict(data)
                        flattened.update(data['document'])
                        data = flattened
                    collection = outer.get('collection_name', '')
                    mapping = {
                        'customer_profiles': ('account_service', 'customer_profile',
                                              self._SQL_TABLE_MAP['customer_profiles'][2]),
                        'customer_search_documents': ('search_service', 'search_document',
                                                      self._SQL_TABLE_MAP['customer_search_documents'][2]),
                        'customer_analytics_reports': ('analytics_platform', 'analytics_profile',
                                                       self._SQL_TABLE_MAP['customer_analytics_profiles'][2]),
                        'support_conversations': ('support_platform', 'support_record',
                                                  self._SQL_TABLE_MAP['support_records'][2]),
                        'customer_export_jobs': ('export_service', 'user_export',
                                                 self._SQL_TABLE_MAP['customer_exports'][2]),
                        'connector_configurations': ('integration_service', 'connector',
                                                     self._SQL_TABLE_MAP['connector_subscriptions'][2]),
                        'backup_catalog': ('backup_service', 'backup',
                                           self._SQL_TABLE_MAP['backup_restore_entries'][2]),
                        'security_audit_events': ('security_service', 'security_audit',
                                                  self._SQL_TABLE_MAP['security_audit_records'][2]),
                        'retained_order_records': ('legal_service', 'legal_hold',
                                                   {'customer_reference': 'subject_reference'}),
                        'deleted_customer_references': self._SNAPSHOT_COLLECTION_MAP[
                            ('identity_service', 'deleted_customer_references')],
                        'ticket_attachments': self._SNAPSHOT_COLLECTION_MAP[
                            ('support_platform', 'ticket_attachments')],
                    }.get(collection)
                    if not mapping:
                        continue
                    system_id, record_type, id_map = mapping
                    rid = data.get('resource_id')
                    if not rid:
                        continue
                    ids = self._ids_from_dict(data, id_map)
                    index.add_record(self._make(
                        file_id, captured_at, system_id, rid, record_type,
                        self._sql_state(record_type, data, ids), ids, raw=data,
                        record_timestamp=data.get('updated_at', outer.get('updated_at', captured_at)),
                        source_format='sql_inventory',
                    ))
            except Exception:
                continue
        conn.close()

    @staticmethod
    def _sql_state(record_type, d, ids):
        if record_type == 'customer_profile':
            if d.get('account_status') == 'DELETION_PENDING':
                return 'PRESENT'
            if ids.get('email') or ids.get('phone') or ids.get('email_hash'):
                return 'PRESENT'
            if ids.get('customer_reference'):
                return 'REDACTED'
            return 'ABSENT'
        if record_type == 'search_document':
            return 'PRESENT' if (ids.get('email') or ids.get('customer_reference')) else 'ABSENT'
        if record_type == 'analytics_profile':
            return 'PRESENT' if (ids.get('email') or ids.get('phone') or ids.get('email_hash')) else 'ANONYMIZED'
        if record_type == 'support_record':
            if ids.get('email') or ids.get('phone'):
                return 'PRESENT'
            if ids.get('customer_reference'):
                return 'REDACTED'
            return 'ABSENT'
        if record_type == 'user_export':
            return 'PRESENT' if (ids.get('email') or ids.get('phone')) else 'ABSENT'
        if record_type == 'connector':
            enabled = d.get('enabled')
            return 'ACTIVE' if str(enabled) == '1' or str(enabled).lower() == 'true' else 'DISABLED'
        if record_type == 'backup':
            ra = d.get('restore_allowed')
            return 'ACTIVE' if str(ra) == '1' or str(ra).lower() == 'true' else 'BLOCKED'
        if record_type == 'security_audit':
            return 'PRESENT'
        if record_type == 'account_tombstone':
            return JsonParserMixin._json_state(record_type, d, ids)
        return 'PRESENT'
