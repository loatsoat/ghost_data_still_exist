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

import hashlib
import json
import os
import re
import sqlite3
from collections import defaultdict
from pathlib import Path

from .records import CAPTURE_CUTOFF_RULE, RECORD_CUTOFF_RULE, EvidenceIndex, EvidenceRecord
from .sql import SqlParserMixin
from .json_files import JsonParserMixin
from .logs import LogParserMixin
from .text import TextParserMixin
from .pdf import PdfParserMixin
from .image import ImageParserMixin


class EvidenceParser(
    SqlParserMixin,
    JsonParserMixin,
    LogParserMixin,
    TextParserMixin,
    PdfParserMixin,
    ImageParserMixin,
):
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
            text = ''
            if ext == '.sql':
                self._parse_sql_file(full_path, file_id, captured_at, index)
            elif ext == '.json':
                self._parse_json_file(full_path, file_id, captured_at, index)
            elif ext == '.log':
                self._parse_log_file(full_path, file_id, captured_at, index)
            elif ext == '.txt':
                self._parse_text_file(full_path, file_id, captured_at, index)
            elif ext == '.pdf':
                text = self._parse_pdf_file(full_path, file_id, captured_at, index)
            elif ext == '.png':
                text = self._parse_image_file(full_path, file_id, captured_at, index)
            if text:
                index.documents.append(
                    (file_id, captured_at, entry.get('origin', ''), text))
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
    def _classify_identifier(val):
        """Classify a raw subject string into an identifier slot."""
        v = (str(val).strip() if val is not None else '')
        if not v or v in ('NULL', 'null', 'None', '[REDACTED]'):
            return None, None
        if '@' in v:
            return 'email', v
        if re.fullmatch(r'user_[A-Za-z0-9_-]+', v):
            return 'customer_reference', v
        if re.fullmatch(r'[0-9a-fA-F]{40,}', v):
            return 'email_hash', v
        if re.fullmatch(r'\+?[\d ()\-]{7,}', v):
            return 'phone', v
        return 'customer_reference', v  # opaque stable reference

    @staticmethod
    def _augment_subject_ids(identifiers, raw):
        """
        Fill empty identifier slots from subject_reference/subject_selector fields.
        Used for backup and connector records, whose state is derived from
        restore_allowed/enabled (never from identifiers), so adding an identifier
        cannot change the record's state. This links restore risks and data flows
        whose subject is stored under subject_reference rather than customer_email.
        """
        ids = dict(identifiers) if identifiers else {}
        # user_id is the link column used by SQL profile/replica tables;
        # the others are the subject fields used by catalogs and bundles.
        # The log keys cover a result row whose subject is named only on its
        # trace's *_started row (inherited as lookup_key by _parse_log_file).
        for field in ('subject_reference', 'subject_selector', 'subject_key',
                      'user_id') + EvidenceParser._LOG_ID_KEYS:
            slot, v = EvidenceParser._classify_identifier(raw.get(field))
            if slot and not ids.get(slot):
                ids[slot] = v
        return ids

    @staticmethod
    def _make(file_id, captured_at, system_id, resource_id,
              record_type, state, identifiers, raw=None,
              record_timestamp=None, source_format='unknown'):
        raw = raw or {}
        # Safe for every record type: `state` has already been computed by the
        # caller, so filling identifier slots here can never change a state.
        # It only lets a record be matched to its subject through whichever
        # field the source used (subject_reference, user_id, ...).
        identifiers = EvidenceParser._augment_subject_ids(identifiers, raw)
        return EvidenceRecord(
            file_id=file_id, captured_at=captured_at,
            system_id=system_id, resource_id=resource_id,
            record_type=record_type, state=state,
            identifiers=identifiers, raw=raw,
            record_timestamp=record_timestamp or captured_at,
            source_format=source_format,
        )
