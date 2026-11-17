"""Evidence records and the index the audit engine queries."""

import hashlib
import json
import os
import re
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
        # (file_id, captured_at, origin, text) of every PDF and screenshot
        self.documents = []

    def add_record(self, record):
        self.records_by_resource[record.resource_id].append(record)
        self.all_records.append(record)

    def get_latest_record(self, resource_id, before_time):
        # Fail closed: both the file capture time and the record's own timestamp
        # must be at or before audit_at. A row updated after audit_at reflects
        # future state and must not be used.
        candidates = [r for r in self.records_by_resource.get(resource_id, [])
                      if r.captured_at <= before_time
                      and r.record_timestamp <= before_time]
        return max(candidates, key=lambda r: r.record_timestamp, default=None)

    def find_matching_records(self, identifiers, before_time, by_record_time=False):
        """
        Match records captured at or before before_time against all identifier forms.
        Returns {resource_id: latest_EvidenceRecord}.
        Uses: email (case-insensitive), phone, email_hash, customer_reference, name.

        by_record_time=True also accepts a record whose own timestamp is at or
        before before_time inside a file exported later (a bundle of earlier
        snapshots). Such a record shows the state at before_time but its file
        cannot be cited.
        """
        emails_lower  = {e.lower() for e in identifiers.get('emails', set()) if e}
        phones        = {p for p in identifiers.get('phones', set()) if p}
        email_hashes  = {h for h in identifiers.get('email_hashes', set()) if h}
        user_id       = identifiers.get('user_id')
        name_lower    = (identifiers.get('name') or '').lower().strip()

        matched = {}
        match_details = {}

        for record in self.all_records:
            # Fail closed on BOTH timestamps: file capture time and the record's
            # own timestamp must be at or before audit_at.
            if record.captured_at > before_time and not by_record_time:
                continue
            if record.record_timestamp > before_time:
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
