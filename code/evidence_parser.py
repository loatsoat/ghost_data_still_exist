"""
Evidence Parser - Phase 2 enhanced.
Parses SQL, JSON, log, text, PDF, and OCR-readable image evidence into a unified index.
Every record carries: file_id, system_id, resource_id, identifiers
(email, phone, email_hash, customer_reference/user_id, name),
state, record_timestamp (record's own ts, may differ from file captured_at),
captured_at (file-level), source_format.

Key Phase 2 additions:
- PDF parsing via pdfplumber, extracting names/emails/resource_ids.
- Log parser extracts profile_lookup 404s using the queried email as identifier.
- Phone, email_hash, and name fields all used in matching.
- source_format field on every record.
- Cached local OCR for image evidence; no deletion verdict is inferred from OCR.
"""

import json
import hashlib
import os
import re
import sqlite3
from pathlib import Path
from collections import defaultdict


# ── Evidence Record ───────────────────────────────────────────────────────
class EvidenceRecord:
    """A single record extracted from an evidence file."""
    __slots__ = (
        'file_id', 'captured_at', 'record_timestamp',
        'system_id', 'resource_id', 'record_type',
        'state', 'identifiers', 'raw', 'source_format',
        '_trace',
    )

    def __init__(self, file_id, captured_at, system_id, resource_id,
                 record_type, state, identifiers, raw=None,
                 record_timestamp=None, source_format='unknown'):
        self.file_id         = file_id
        self.captured_at     = captured_at
        self.record_timestamp = record_timestamp or captured_at   # record's own ts
        self.system_id       = system_id
        self.resource_id     = resource_id
        self.record_type     = record_type
        self.state           = state
        self.identifiers     = identifiers  # email, phone, email_hash, customer_reference, name
        self.raw             = raw or {}
        self.source_format   = source_format
        self._trace          = {}           # populated by audit engine


# ── Evidence Index ────────────────────────────────────────────────────────
class EvidenceIndex:
    def __init__(self):
        self.records_by_resource = defaultdict(list)
        self.all_records = []
        self.last_match_details = {}

    def add_record(self, record):
        self.records_by_resource[record.resource_id].append(record)
        self.all_records.append(record)

    def get_latest_record(self, resource_id, before_time):
        candidates = [r for r in self.records_by_resource.get(resource_id, [])
                      if r.captured_at <= before_time]
        return max(candidates, key=lambda r: r.record_timestamp, default=None)

    def find_matching_records(self, identifiers, before_time):
        """
        Match records captured at or before before_time against all identifier forms.
        Returns {resource_id: latest_EvidenceRecord}.
        Uses: email (case-insensitive), phone, email_hash, customer_reference, name.
        """
        emails_lower  = {e.lower() for e in identifiers.get('emails', set()) if e}
        phones        = {p for p in identifiers.get('phones', set()) if p}
        email_hashes  = {h for h in identifiers.get('email_hashes', set()) if h}
        user_id       = identifiers.get('user_id')
        name_lower    = (identifiers.get('name') or '').lower().strip()

        matched = {}
        match_details = {}

        for record in self.all_records:
            if record.captured_at > before_time:
                continue

            hit = False
            matched_identifier = None
            ids = record.identifiers

            e = ids.get('email')
            if e and e.lower() in emails_lower:
                hit = True
                matched_identifier = ('email', e)

            if not hit:
                p = ids.get('phone')
                if p and p in phones:
                    hit = True
                    matched_identifier = ('phone', p)

            if not hit:
                h = ids.get('email_hash')
                if h and h in email_hashes:
                    hit = True
                    matched_identifier = ('email_hash', h)

            if not hit:
                ref = ids.get('customer_reference')
                if ref and user_id and ref == user_id:
                    hit = True
                    matched_identifier = ('customer_reference', ref)

            if not hit and name_lower:
                n = (ids.get('name') or '').lower().strip()
                if n and n == name_lower:
                    hit = True
                    matched_identifier = ('name', ids.get('name'))

            if hit:
                existing = matched.get(record.resource_id)
                if existing is None or record.record_timestamp > existing.record_timestamp:
                    matched[record.resource_id] = record
                    match_details[record.resource_id] = matched_identifier

        self.last_match_details = match_details
        return matched


# Problem statement cutoff: file capture and record timestamps must both be
# at or before the request's audit_at.
CAPTURE_CUTOFF_RULE = 'captured_at <= audit_at'
RECORD_CUTOFF_RULE = 'record_timestamp <= audit_at'


# ── Parser ────────────────────────────────────────────────────────────────
class EvidenceParser:
    def __init__(self, evidence_dir):
        self.evidence_dir = Path(evidence_dir)
        self._pdf_cache_dir = self.evidence_dir.parent.parent / ".pdf_cache"
        self._pdf_cache_dir.mkdir(exist_ok=True)
        self.sql_metadata = {}

    def parse_all(self, evidence_manifest):
        index = EvidenceIndex()
        for entry in evidence_manifest:
            file_id    = entry['file_id']
            file_path  = entry['file_path']
            captured_at = entry['captured_at']

            full_path = self.evidence_dir.parent / file_path
            if not full_path.exists():
                full_path = self.evidence_dir / Path(file_path).name
            if not full_path.exists():
                continue

            ext = full_path.suffix.lower()
            if ext == '.sql':
                self._parse_sql_file(full_path, file_id, captured_at, index)
            elif ext == '.json':
                self._parse_json_file(full_path, file_id, captured_at, index)
            elif ext == '.log':
                self._parse_log_file(full_path, file_id, captured_at, index)
            elif ext == '.txt':
                self._parse_text_file(full_path, file_id, captured_at, index)
            elif ext == '.pdf':
                self._parse_pdf_file(full_path, file_id, captured_at, index)
            elif ext == '.png':
                self._parse_image_file(full_path, file_id, captured_at, index)
        return index

    # ── helpers ──────────────────────────────────────────────────────────
    @staticmethod
    def _clean(val):
        if val is None:
            return None
        s = str(val).strip()
        return s if s and s not in ('NULL', 'null', 'None', '[REDACTED]') else None

    def _ids_from_dict(self, d, mapping):
        """Build identifiers dict from a record dict + field-name mapping."""
        ids = {}
        for id_type, field in mapping.items():
            ids[id_type] = self._clean(d.get(field))
        return ids

    @staticmethod
    def _make(file_id, captured_at, system_id, resource_id,
              record_type, state, identifiers, raw=None,
              record_timestamp=None, source_format='unknown'):
        return EvidenceRecord(
            file_id=file_id, captured_at=captured_at,
            system_id=system_id, resource_id=resource_id,
            record_type=record_type, state=state,
            identifiers=identifiers, raw=raw,
            record_timestamp=record_timestamp or captured_at,
            source_format=source_format,
        )

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
        return 'PRESENT'

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
    }

    def _parse_snapshot_bundle(self, data, file_id, captured_at, index):
        for snap in data.get('snapshots', []):
            ds  = snap.get('data_store', '')
            col = snap.get('collection', '')
            snap_ts = snap.get('captured_at', captured_at)
            mapping = self._SNAPSHOT_COLLECTION_MAP.get((ds, col))
            if not mapping:
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

        for d in records:
            rid = d.get('resource_id')
            if not rid:
                continue
            record_type_name = str(d.get('record_type', '')).upper()
            system = d.get('system', '')
            if record_type_name == 'USER_PROFILE' or system == 'account_service':
                record_type = 'customer_profile'
                system_id = 'account_service'
                ids = {
                    'email': self._clean(d.get('subject_reference')),
                    'phone': None,
                    'email_hash': None,
                    'customer_reference': None,
                }
                result = str(d.get('result', '')).upper()
                state = 'ABSENT' if result in ('ABSENT', 'NOT_FOUND') else 'PRESENT'
                index.add_record(self._make(
                    file_id, d.get('recorded_at', captured_at), system_id, rid,
                    record_type, state, ids, raw=d,
                    record_timestamp=d.get('recorded_at', captured_at),
                    source_format='json_generic',
                ))

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
            identifier = (
                kv.get('lookup_key') or kv.get('subject_key') or
                kv.get('owner_key') or kv.get('matched_value') or
                kv.get('correlation_key')
            )
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
                r'security_service|integration_service|backup_service)\b',
                line,
            )
            if service_match:
                kv['service'] = service_match.group(1)
        if kv.get('service') == 'search_index_service':
            kv['service'] = kv.get('system', 'search_index_service')
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
                state = 'PRESENT' if rows > 0 else 'ANONYMIZED'
                return m(file_id, captured_at, 'analytics_platform', resource_id,
                         'analytics_profile', state, ids, raw=kv,
                         record_timestamp=event_time, source_format='log')
            elif 'analytics_profile_read_completed' in event:
                ids = {
                    'email': kv.get('email') or kv.get('customer_email'),
                    'phone': kv.get('phone') or kv.get('customer_phone'),
                    'email_hash': kv.get('email_hash'),
                    'customer_reference': kv.get('customer_reference'),
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
                    return m(file_id, captured_at, 'support_platform', resource_id,
                             'support_record', 'PRESENT', ids, raw=kv,
                             record_timestamp=event_time, source_format='log')
            if 'message_pii_scan' in event or 'attachment_pii_scan' in event:
                val = kv.get('matched_value')
                ids = {'email': val if val and '@' in val else None,
                       'phone': val if val and '@' not in val and '+' in val else None}
                if ids.get('email') or ids.get('phone'):
                    return m(file_id, captured_at, 'support_platform', resource_id,
                             'support_record', 'PRESENT', ids, raw=kv,
                             record_timestamp=event_time, source_format='log')
            if 'support_ticket_read_completed' in event:
                ids = {
                    'email': kv.get('requester_email') or kv.get('customer_email'),
                    'phone': kv.get('requester_phone') or kv.get('customer_phone'),
                    'customer_reference': kv.get('customer_reference'),
                }
                if any(ids.values()):
                    return m(file_id, captured_at, 'support_platform', resource_id,
                             'support_record', 'PRESENT', ids, raw=kv,
                             record_timestamp=event_time, source_format='log')

        elif service == 'integration_service':
            if 'connector_heartbeat' in event:
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
    }
    _STATUS_MAP = {
        'NOT_FOUND': 'ABSENT', 'FOUND': 'PRESENT', 'IDENTIFIABLE': 'PRESENT',
        'ANONYMIZED': 'ANONYMIZED', 'REDACTED': 'REDACTED',
        'ACTIVE': 'ACTIVE', 'DISABLED': 'DISABLED', 'BLOCKED': 'BLOCKED',
    }

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

    # ── PDF ───────────────────────────────────────────────────────────────
    # Regex patterns to extract structured facts from PDF text
    _EMAIL_RE   = re.compile(r'[\w.+-]+@[\w-]+\.[\w.-]+')
    _PHONE_RE   = re.compile(r'(?:\+\d[\d\s\-().]{6,20}\d)')
    _RID_RE     = re.compile(r'\b(account|search|analytics|support|export|data_flow|backup|audit_record|tombstone)_[\w]+\b')
    _USER_RE    = re.compile(r'\buser_\d+\b')

    def _pdf_cache_path(self, filepath):
        h = hashlib.sha256(filepath.read_bytes()).hexdigest()
        return self._pdf_cache_dir / f"{h}.json"

    def _extract_pdf_facts(self, filepath):
        """Extract structured facts from PDF, with disk cache."""
        cp = self._pdf_cache_path(filepath)
        if cp.exists():
            try:
                return json.loads(cp.read_text(encoding='utf-8'))
            except Exception:
                pass

        facts = {'pages': [], 'emails': [], 'phones': [], 'resource_ids': [],
                 'user_refs': [], 'name': None}
        try:
            import pdfplumber
            with pdfplumber.open(str(filepath)) as pdf:
                for page in pdf.pages:
                    text = page.extract_text() or ''
                    facts['pages'].append(text)
                    facts['emails'].extend(self._EMAIL_RE.findall(text))
                    facts['phones'].extend(self._PHONE_RE.findall(text))
                    facts['resource_ids'].extend(self._RID_RE.findall(text))  # prefix list
                    facts['user_refs'].extend(self._USER_RE.findall(text))
        except Exception as e:
            facts['error'] = str(e)
            return facts

        # Deduplicate
        facts['emails']       = list(dict.fromkeys(facts['emails']))
        facts['phones']       = list(dict.fromkeys(facts['phones']))
        facts['resource_ids'] = list(dict.fromkeys(facts['resource_ids']))
        facts['user_refs']    = list(dict.fromkeys(facts['user_refs']))

        # Full text for RID extraction
        full_text = '\n'.join(facts['pages'])
        # Get full resource_ids (prefix_suffix)
        full_rids = list(dict.fromkeys(re.findall(
            r'\b(?:account|search|analytics|support|export|data_flow|backup|audit_record|tombstone)_[\w]+\b',
            full_text)))
        facts['full_resource_ids'] = full_rids

        try:
            cp.write_text(json.dumps(facts), encoding='utf-8')
        except Exception:
            pass
        return facts

    def _parse_pdf_file(self, filepath, file_id, captured_at, index):
        facts = self._extract_pdf_facts(filepath)
        if not facts or 'pages' not in facts:
            return

        full_text = '\n'.join(facts.get('pages', []))
        emails    = facts.get('emails', [])
        phones    = facts.get('phones', [])
        user_refs = facts.get('user_refs', [])
        full_rids = facts.get('full_resource_ids', [])

        for rid in full_rids:
            # Determine system from prefix
            prefix = rid.split('_')[0] + '_' + (rid.split('_')[1] if len(rid.split('_')) > 1 else '')
            system_id, record_type = self._rid_to_system(rid)

            # Build identifiers from emails/phones/user_refs near this rid
            ids = self._ids_near_rid(rid, full_text, emails, phones, user_refs)

            # State: if in PDF and not explicitly marked absent, treat as PRESENT
            # Check for "NOT_FOUND" / "ABSENT" language near the rid
            ctx = self._context(rid, full_text, 200)
            state = 'ABSENT' if re.search(r'\b(not found|absent|deleted|removed|NOT_FOUND)\b', ctx, re.I) else 'PRESENT'

            # For support attachments in PDF, mark as attachment type
            if record_type == 'support_record' and 'attachment' in full_text.lower():
                record_type = 'support_attachment'

            index.add_record(self._make(
                file_id, captured_at, system_id, rid,
                record_type, state, ids, raw={'pdf_context': ctx[:300]},
                record_timestamp=captured_at, source_format='pdf',
            ))

    @staticmethod
    def _rid_to_system(rid):
        p = rid.lower()
        if p.startswith('account_'):    return 'account_service',    'customer_profile'
        if p.startswith('search_'):     return 'search_service',     'search_document'
        if p.startswith('analytics_'):  return 'analytics_platform', 'analytics_profile'
        if p.startswith('support_'):    return 'support_platform',   'support_record'
        if p.startswith('export_'):     return 'export_service',     'user_export'
        if p.startswith('data_flow_'):  return 'integration_service','connector'
        if p.startswith('backup_'):     return 'backup_service',     'backup'
        if p.startswith('audit_record_'): return 'security_service', 'security_audit'
        if p.startswith('tombstone_'):  return 'identity_service',   'account_tombstone'
        return 'unknown_service', rid.split('_')[0]

    @staticmethod
    def _context(term, text, window=300):
        idx = text.find(term)
        if idx < 0:
            return ''
        return text[max(0, idx - window): idx + window]

    def _ids_near_rid(self, rid, full_text, emails, phones, user_refs):
        ctx = self._context(rid, full_text, 300)
        ids = {'email': None, 'phone': None, 'customer_reference': None}
        for e in emails:
            if e in ctx:
                ids['email'] = e
                break
        for p in phones:
            if p in ctx:
                ids['phone'] = p
                break
        for u in user_refs:
            if u in ctx:
                ids['customer_reference'] = u
                break
        return ids

    # ── Image (placeholder) ───────────────────────────────────────────────
    def _parse_image_file(self, filepath, file_id, captured_at, index):
        """Extract structured identifiers and nearby state from a screenshot."""
        cache_path = self._image_cache_path(filepath)
        facts = None
        if cache_path.exists():
            try:
                facts = json.loads(cache_path.read_text(encoding='utf-8'))
            except (OSError, json.JSONDecodeError):
                facts = None

        if facts is None:
            facts = {'text': '', 'error': None}
            try:
                from rapidocr_onnxruntime import RapidOCR
                result, _ = RapidOCR()(str(filepath))
                facts['text'] = ' '.join(
                    str(item[1]) for item in (result or [])
                    if isinstance(item, (list, tuple)) and len(item) > 1
                )
            except ImportError:
                facts['error'] = 'rapidocr_onnxruntime is not installed'
            except (OSError, RuntimeError, ValueError) as exc:
                facts['error'] = f'{type(exc).__name__}: {exc}'
            try:
                cache_path.write_text(json.dumps(facts), encoding='utf-8')
            except OSError:
                pass

        text = facts.get('text', '')
        if not text:
            return

        emails = list(dict.fromkeys(self._EMAIL_RE.findall(text)))
        phones = list(dict.fromkeys(self._PHONE_RE.findall(text)))
        user_refs = list(dict.fromkeys(self._USER_RE.findall(text)))
        resource_ids = list(dict.fromkeys(re.findall(
            r'\b(?:account|search|analytics|support|export|data_flow|backup|'
            r'audit_record|tombstone)_[\w-]+\b', text, re.I)))

        for resource_id in resource_ids:
            system_id, record_type = self._rid_to_system(resource_id)
            context = self._context(resource_id, text, 300)
            identifiers = self._ids_near_rid(
                resource_id, text, emails, phones, user_refs)
            state = (
                'ABSENT' if re.search(
                    r'\b(?:not found|absent|deleted|removed|no longer exists)\b',
                    context, re.I)
                else 'PRESENT'
            )
            if record_type == 'connector':
                if re.search(r'\b(?:disabled|stopped|inactive)\b', context, re.I):
                    state = 'DISABLED'
                elif re.search(
                        r'\b(?:enabled|active|healthy|continuous|running)\b',
                        context, re.I):
                    state = 'ACTIVE'
            index.add_record(self._make(
                file_id, captured_at, system_id, resource_id,
                record_type, state, identifiers,
                raw={'ocr_text': context[:500]},
                record_timestamp=captured_at,
                source_format='image_ocr',
            ))

    def _image_cache_path(self, filepath):
        image_hash = hashlib.sha256(filepath.read_bytes()).hexdigest()
        return self._pdf_cache_dir / f'image_{image_hash}.json'
