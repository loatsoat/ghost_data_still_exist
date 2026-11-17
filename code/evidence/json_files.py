"""JSON snapshot bundles and service resource exports."""

import hashlib
import json
import os
import re
import sqlite3
from collections import defaultdict
from pathlib import Path

from .records import CAPTURE_CUTOFF_RULE, RECORD_CUTOFF_RULE, EvidenceIndex, EvidenceRecord


class JsonParserMixin:
    # ── JSON ──────────────────────────────────────────────────────────────
    def _parse_json_file(self, filepath, file_id, captured_at, index):
        try:
            data = json.loads(filepath.read_text(encoding='utf-8'))
        except Exception:
            return
        if 'snapshots' in data:
            self._parse_snapshot_bundle(data, file_id, captured_at, index)
        elif 'service_exports' in data:
            self._parse_service_resource_export(data, file_id, captured_at, index)
        else:
            self._parse_generic_json(data, file_id, captured_at, index)

    _SNAPSHOT_COLLECTION_MAP = {
        ('account_service',    'customer_profiles'):         ('account_service',    'customer_profile',  {'email':'email','phone':'phone','email_hash':'email_hash','customer_reference':'customer_reference','name':'full_name'}),
        ('search_service',     'customer_search_documents'): ('search_service',     'search_document',   {'email':'email','phone':'phone','email_hash':'email_hash','customer_reference':'customer_reference'}),
        ('analytics_platform', 'customer_analytics_reports'):('analytics_platform', 'analytics_profile', {'email':'email','phone':'phone','email_hash':'email_hash','customer_reference':'customer_reference'}),
        ('analytics_platform', 'customer_analytics_profiles'):('analytics_platform','analytics_profile', {'email':'email','phone':'phone','email_hash':'email_hash','customer_reference':'customer_reference'}),
        ('support_platform',   'support_conversations'):     ('support_platform',   'support_record',    {'email':'requester_email','phone':'requester_phone','customer_reference':'customer_reference'}),
        ('export_service',     'customer_export_jobs'):      ('export_service',     'user_export',       {'email':'owner_email','phone':'owner_phone','customer_reference':'customer_reference'}),
        ('integration_service','connector_configurations'):  ('integration_service','connector',         {'email':'customer_email','customer_reference':'customer_reference'}),
        ('backup_service',     'backup_catalog'):            ('backup_service',     'backup',            {'email':'customer_email','customer_reference':'customer_reference'}),
        ('identity_service',   'deleted_customer_references'): ('identity_service', 'account_tombstone', {'email':'email','phone':'phone','email_hash':'email_hash','customer_reference':'subject_reference','name':'name'}),
        ('security_service',   'security_audit_events'):     ('security_service',   'security_audit',    {'customer_reference':'subject_reference'}),
        ('legal_service',      'retained_order_records'):    ('legal_service',      'legal_hold',        {'customer_reference':'subject_reference'}),
        ('support_platform',   'ticket_attachments'):        ('support_platform',   'support_attachment', {'email':'uploaded_by'}),
    }

    def _parse_snapshot_bundle(self, data, file_id, captured_at, index):
        for snap in data.get('snapshots', []):
            ds  = snap.get('data_store', '')
            col = snap.get('collection', '')
            snap_ts = snap.get('captured_at', captured_at)
            mapping = self._SNAPSHOT_COLLECTION_MAP.get((ds, col))
            if not mapping:
                # A collection named only by its wrapper data_store (varies by
                # capture) but whose rows self-describe via record_type, like
                # an export manifest's rows.
                recs = snap.get('records', [])
                if recs and isinstance(recs[0], dict) and 'record_type' in recs[0]:
                    # A bundle exported after audit_at must stay uncitable.
                    self._add_manifest_rows(recs, file_id, snap_ts, index,
                                             source_format='json_snapshot',
                                             file_captured_at=captured_at)
                continue
            system_id, record_type, id_map = mapping
            for d in snap.get('records', []):
                rid = d.get('resource_id')
                if not rid:
                    continue
                ids = self._ids_from_json(d, id_map)
                state = self._json_state(record_type, d, ids, col)
                index.add_record(self._make(
                    file_id, captured_at, system_id, rid,
                    record_type, state, ids, raw=d,
                    record_timestamp=snap_ts, source_format='json_snapshot',
                ))

    def _parse_service_resource_export(self, data, file_id, captured_at, index):
        exported_at = data.get('exported_at', captured_at)
        se = data.get('service_exports', {})

        coll_cfg = {
            'account_service': {
                'profile_lookups': ('account_service', 'customer_profile',
                                    {'email': 'email', 'phone': 'phone',
                                     'email_hash': 'email_hash',
                                     'customer_reference': 'customer_reference'})
            },
            'search_service': {
                'index_queries': ('search_service', 'search_document',
                                  {'email': 'email', 'phone': 'phone',
                                   'email_hash': 'email_hash',
                                   'customer_reference': 'customer_reference'})
            },
            'analytics_platform': {
                'profiles': ('analytics_platform', 'analytics_profile',
                             {'email': 'email', 'phone': 'phone',
                              'email_hash': 'email_hash',
                              'customer_reference': 'customer_reference'})
            },
            'support_platform': {
                'tickets': ('support_platform', 'support_record',
                            {'email': 'requester_email', 'phone': 'requester_phone',
                             'customer_reference': 'customer_reference'})
            },
            'export_service': {
                'exports': ('export_service', 'user_export',
                            {'email': 'owner_email', 'phone': 'owner_phone',
                             'customer_reference': 'customer_reference'})
            },
            'integration_service': {
                'connectors': ('integration_service', 'connector',
                               {'email': 'customer_email',
                                'customer_reference': 'customer_reference'})
            },
            'backup_service': {
                'restore_entries': ('backup_service', 'backup',
                                    {'email': 'customer_email',
                                     'customer_reference': 'customer_reference'})
            },
            'security_service': {
                'audit_records': ('security_service', 'security_audit',
                                  {'customer_reference': 'subject_reference'})
            },
        }

        for svc, colls in coll_cfg.items():
            if svc not in se:
                continue
            for coll, (system_id, record_type, id_map) in colls.items():
                if coll not in se[svc]:
                    continue
                for d in se[svc][coll]:
                    rid = d.get('resource_id')
                    if not rid:
                        continue
                    obs = d.get('observed_at', exported_at)

                    # Profile lookups: state comes from status_code
                    if coll == 'profile_lookups':
                        code    = d.get('status_code', 200)
                        profile = d.get('profile') or {}
                        # The QUERY field carries the email used for lookup
                        query_email = d.get('query_email') or (profile.get('email') if profile else None)
                        ids = self._ids_from_json(profile, id_map)
                        # If 404, we still know the query email → use it as identifier
                        if code == 404 or not profile:
                            state = 'ABSENT'
                            if query_email and not ids.get('email'):
                                ids['email'] = query_email
                        else:
                            state = self._json_state(record_type, profile, ids, coll)
                        index.add_record(self._make(
                            file_id, obs, system_id, rid,
                            record_type, state, ids, raw=d,
                            record_timestamp=obs, source_format='json_svc_export',
                        ))
                        continue

                    # Index queries: state from hits
                    if coll == 'index_queries':
                        hits  = d.get('hits', {})
                        total = hits.get('total', 0)
                        docs  = hits.get('documents', [])
                        state = 'ABSENT' if total == 0 else 'PRESENT'
                        ids_  = self._ids_from_json(docs[0] if docs else {}, id_map)
                        index.add_record(self._make(
                            file_id, obs, system_id, rid,
                            record_type, state, ids_, raw=d,
                            record_timestamp=obs, source_format='json_svc_export',
                        ))
                        continue

                    # Default
                    ids   = self._ids_from_json(d, id_map)
                    state = self._json_state(record_type, d, ids, coll)
                    index.add_record(self._make(
                        file_id, obs, system_id, rid,
                        record_type, state, ids, raw=d,
                        record_timestamp=obs, source_format='json_svc_export',
                    ))

    def _parse_generic_json(self, data, file_id, captured_at, index):
        """Fallback for customer_analytics_report, export_jobs, connector_configs, security_ledger."""
        collection = data.get('collection', '')
        records = data.get('records', [])
        collection_map = {
            'customer_export_jobs': ('export_service', 'user_export', {
                'email': 'owner_email', 'phone': 'owner_phone',
                'customer_reference': 'customer_reference'}),
            'customer_analytics_reports': ('analytics_platform', 'analytics_profile', {
                'email': 'email', 'phone': 'phone', 'email_hash': 'email_hash',
                'customer_reference': 'customer_reference'}),
            'connector_configurations': ('integration_service', 'connector', {
                'email': 'customer_email', 'customer_reference': 'customer_reference'}),
            'backup_catalog': ('backup_service', 'backup', {
                'email': 'customer_email', 'customer_reference': 'customer_reference'}),
        }
        if collection in collection_map:
            system_id, record_type, id_map = collection_map[collection]
            for d in records:
                rid = d.get('resource_id')
                if not rid:
                    continue
                ids = self._ids_from_json(d, id_map)
                state = self._json_state(record_type, d, ids, collection)
                index.add_record(self._make(
                    file_id, d.get('observed_at', captured_at), system_id, rid,
                    record_type, state, ids, raw=d,
                    record_timestamp=d.get('observed_at', captured_at),
                    source_format='json_generic',
                ))

        self._add_manifest_rows(records, file_id, captured_at, index)

        for d in data.get('profiles', []):
            rid = d.get('resource_id')
            if not rid: continue
            ids = {'email': self._clean(d.get('email') or d.get('user_id')),
                   'phone': self._clean(d.get('phone')),
                   'email_hash': self._clean(d.get('email_hash')),
                   'customer_reference': self._clean(d.get('customer_reference') or d.get('user_id'))}
            state = 'PRESENT' if (ids.get('email') or ids.get('phone') or ids.get('email_hash')) else 'ANONYMIZED'
            index.add_record(self._make(file_id, captured_at, 'analytics_platform', rid,
                                        'analytics_profile', state, ids, raw=d,
                                        source_format='json_generic'))

        for d in data.get('exports', []):
            rid = d.get('resource_id')
            if not rid: continue
            ids = {'email': self._clean(d.get('owner_email')),
                   'phone': self._clean(d.get('owner_phone')),
                   'customer_reference': self._clean(d.get('customer_reference'))}
            state = 'PRESENT' if ids.get('email') else 'ABSENT'
            index.add_record(self._make(file_id, captured_at, 'export_service', rid,
                                        'user_export', state, ids, raw=d,
                                        source_format='json_generic'))

        for d in data.get('connectors', []):
            rid = d.get('resource_id')
            if not rid: continue
            ids = {'email': self._clean(d.get('customer_email')),
                   'customer_reference': self._clean(
                       d.get('customer_reference') or d.get('subject_selector'))}
            enabled = d.get('enabled')
            state = 'ACTIVE' if enabled else 'DISABLED'
            index.add_record(self._make(file_id, captured_at, 'integration_service', rid,
                                        'connector', state, ids, raw=d,
                                        source_format='json_generic'))

        for d in data.get('audit_records', []):
            rid = d.get('resource_id')
            if not rid: continue
            ids = {'customer_reference': self._clean(d.get('subject_reference'))}
            index.add_record(self._make(file_id, captured_at, 'security_service', rid,
                                        'security_audit', 'PRESENT', ids, raw=d,
                                        source_format='json_generic'))

    def _ids_from_json(self, d, id_map):
        ids = {}
        for id_type, field in id_map.items():
            # handle nested 'document' sub-dict (search snapshots)
            val = d.get(field)
            if val is None and 'document' in d:
                val = d['document'].get(field)
            ids[id_type] = self._clean(val)
        return ids

    @staticmethod
    def _json_state(record_type, d, ids, collection=''):
        if record_type == 'analytics_profile':
            return 'PRESENT' if (ids.get('email') or ids.get('phone') or ids.get('email_hash')) else 'ANONYMIZED'
        if record_type == 'support_record':
            text = d.get('message_text', '')
            if isinstance(text, str) and text.strip() == '[REDACTED]':
                return 'REDACTED'
            return 'PRESENT' if (ids.get('email') or ids.get('phone')) else (
                'REDACTED' if ids.get('customer_reference') else 'ABSENT')
        if record_type == 'connector':
            e = d.get('enabled')
            return 'ACTIVE' if (e is True or str(e).lower() == 'true') else 'DISABLED'
        if record_type == 'backup':
            ra = d.get('restore_allowed')
            return 'ACTIVE' if (ra is True or str(ra).lower() == 'true') else 'BLOCKED'
        if record_type == 'security_audit':
            return 'PRESENT'
        if record_type == 'customer_profile':
            if d.get('account_status') == 'DELETION_PENDING':
                return 'PRESENT'
            return ('PRESENT' if (ids.get('email') or ids.get('phone') or ids.get('email_hash'))
                    else ('REDACTED' if ids.get('customer_reference') else 'ABSENT'))
        if record_type == 'account_tombstone':
            return ('PRESENT' if (ids.get('email') or ids.get('phone') or
                                  ids.get('email_hash') or ids.get('name'))
                    else ('REDACTED' if ids.get('customer_reference') else 'ABSENT'))
        if record_type == 'search_document':
            return 'PRESENT' if (ids.get('email') or ids.get('customer_reference')) else 'ABSENT'
        if record_type == 'user_export':
            return 'PRESENT' if ids.get('email') else 'ABSENT'
        return 'PRESENT'
