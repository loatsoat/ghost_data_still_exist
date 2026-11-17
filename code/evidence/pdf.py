"""PDF business documents (invoices, handovers) via pdfplumber."""

import hashlib
import json
import os
import re
import sqlite3
from collections import defaultdict
from pathlib import Path

from .records import CAPTURE_CUTOFF_RULE, RECORD_CUTOFF_RULE, EvidenceIndex, EvidenceRecord


class PdfParserMixin:
    # ── PDF ───────────────────────────────────────────────────────────────
    # Regex patterns to extract structured facts from PDF text
    _EMAIL_RE   = re.compile(r'[\w.+-]+@[\w-]+\.[\w.-]+')
    _PHONE_RE   = re.compile(r'(?:\+\d[\d\s\-().]{6,20}\d)')
    _RID_RE     = re.compile(r'\b(account|search|analytics|support|export|data_flow|backup|audit_record|tombstone|legal_hold)_[\w]+\b')
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
        """Add the PDF's records to the index and return its text."""
        facts = self._extract_pdf_facts(filepath)
        if not facts or 'pages' not in facts:
            return ''

        full_text = '\n'.join(facts.get('pages', []))
        emails    = facts.get('emails', [])
        phones    = facts.get('phones', [])
        user_refs = facts.get('user_refs', [])
        full_rids = facts.get('full_resource_ids', [])

        for rid in full_rids:
            if not re.search(r'_\d+$', rid):
                continue  # an event or field name, not a resource id
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
        return full_text

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
        if p.startswith('object_'):     return 'object_storage',     'support_attachment'
        if p.startswith('marketing_'):  return 'marketing_platform', 'marketing_profile'
        if p.startswith('legal_hold_'): return 'legal_service',      'legal_hold'
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
