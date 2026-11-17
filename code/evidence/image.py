"""Screenshots via local RapidOCR."""

import hashlib
import json
import os
import re
import sqlite3
from collections import defaultdict
from pathlib import Path

from .records import CAPTURE_CUTOFF_RULE, RECORD_CUTOFF_RULE, EvidenceIndex, EvidenceRecord


class ImageParserMixin:
    # ── Image (placeholder) ───────────────────────────────────────────────
    def _parse_image_file(self, filepath, file_id, captured_at, index):
        """Add the screenshot's records to the index and return its OCR text."""
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
            return ''

        emails = list(dict.fromkeys(self._EMAIL_RE.findall(text)))
        phones = list(dict.fromkeys(self._PHONE_RE.findall(text)))
        user_refs = list(dict.fromkeys(self._USER_RE.findall(text)))
        resource_ids = list(dict.fromkeys(re.findall(
            r'\b(?:account|search|analytics|support|export|data_flow|backup|'
            r'audit_record|tombstone)_\w+\b', text, re.I)))
        # OCR reads zeros in a numeric suffix as the letter o ("_oo3").
        resource_ids = list(dict.fromkeys(
            re.sub(r'_[0-9oO]+$', lambda m: m.group(0).lower().replace('o', '0'), rid)
            for rid in resource_ids))
        # A resource id ends in a number; "account_closure_recorded" is an
        # event name that only shares the prefix.
        resource_ids = [rid for rid in resource_ids if re.search(r'_\d+$', rid)]

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
        return text

    def _image_cache_path(self, filepath):
        image_hash = hashlib.sha256(filepath.read_bytes()).hexdigest()
        return self._pdf_cache_dir / f'image_{image_hash}.json'
