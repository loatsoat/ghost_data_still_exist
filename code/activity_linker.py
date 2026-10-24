"""
Phase 3 & 5: SystemActivityLinker
Builds grounded links between resources and users from system_activity,
and derives data-flow / restore state as of audit_at.

Approach:
1. Parse LINK_RESOURCE_IDENTITY events → resource_id to (email, user_id) map.
2. Parse all activity events → track which resource_ids each user has interacted
   with (via details field mentions), but ONLY link if the resource_id appears in
   an activity that itself is linked to the user via a direct identifier match.
3. For data flows: last CHECK_DATA_FLOW or DISABLE_DATA_FLOW at or before audit_at.
4. For backups: last CHECK_RESTORE_ACCESS or BLOCK_RESTORE at or before audit_at.

HARD RULE: never link via activity unless a grounded identifier ties the event to
the user. Details-text mentions alone (without a user link) are not used.
"""

import re
from collections import defaultdict


# Problem statement cutoff: activity links use event_time <= audit_at.
ACTIVITY_CUTOFF_RULE = 'event_time <= audit_at'
from pathlib import Path


_DETAIL_RE = re.compile(
    r'(?:linked|linked\s+\w+\s+\(\w+\)\s+to)\s+([\w.@+-]+)\s+and\s+(user_\d+)',
    re.IGNORECASE
)
_RESOURCE_IN_DETAIL = re.compile(
    r'\b(account|search|analytics|support|export|data_flow|backup|audit_record|tombstone)_[\w]+\b'
)


class SystemActivityLinker:
    """
    Pre-processes system_activity into per-user resource maps
    and data-flow / restore state timelines.
    """

    def __init__(self, system_activity):
        self._activity = system_activity

        # resource_id -> set of (email_lower, user_id, event_time)
        self._rid_to_identifiers: dict[str, set] = defaultdict(set)

        # resource_id -> sorted list of (event_time, event_type, result)
        self._flow_timeline: dict[str, list] = defaultdict(list)
        self._restore_timeline: dict[str, list] = defaultdict(list)

        # activity_id -> row (for evidence citation)
        self._by_activity_id = {}

        self._build()

    def _build(self):
        # First pass: collect LINK_RESOURCE_IDENTITY grounded links
        for act in self._activity:
            aid = act.get('activity_id', '')
            if aid:
                self._by_activity_id[aid] = act

            et   = act.get('event_type', '')
            rid  = act.get('resource_id', '')
            det  = act.get('details', '')
            ts   = act.get('event_time', '')
            res  = act.get('reported_result', '')

            # Grounded identity links from LINK_RESOURCE_IDENTITY
            if et == 'LINK_RESOURCE_IDENTITY':
                m = _DETAIL_RE.search(det)
                if m:
                    email   = m.group(1).lower()
                    user_id = m.group(2)
                    if rid:
                        self._rid_to_identifiers[rid].add((email, user_id, ts))
                    # Also link any OTHER resource_ids mentioned in the detail
                    for other_rid in _RESOURCE_IN_DETAIL.findall(det):
                        full_rid = self._find_full_rid(other_rid, det)
                        if full_rid and full_rid != rid:
                            self._rid_to_identifiers[full_rid].add((email, user_id, ts))

            # Data-flow state events
            if et in ('CHECK_DATA_FLOW', 'DISABLE_DATA_FLOW', 'SYNC_RECORD'):
                if rid and ('data_flow' in rid or 'integration' in act.get('target_system', '')):
                    self._flow_timeline[rid].append((ts, et, res))

            # Restore-risk state events
            if et in ('CHECK_RESTORE_ACCESS', 'BLOCK_RESTORE', 'RESTORE_BACKUP'):
                if rid:
                    self._restore_timeline[rid].append((ts, et, res))

        # Second pass: build cross-links from DELETE / ANONYMIZE / REDACT events.
        # If a DELETE_RECORD was executed for resource R and R already has a
        # grounded user link, we can also link its details-mentioned companion RIDs.
        for act in self._activity:
            et  = act.get('event_type', '')
            rid = act.get('resource_id', '')
            det = act.get('details', '')
            ts  = act.get('event_time', '')
            src = act.get('source_system', '')
            tgt = act.get('target_system', '')

            if et in ('DELETE_RECORD', 'ANONYMIZE_RECORD', 'REDACT_RECORD',
                      'DISABLE_DATA_FLOW', 'BLOCK_RESTORE',
                      'CHECK_DATA_FLOW', 'CHECK_RESTORE_ACCESS') and rid:
                # Look for CHECK_DATA_FLOW "remains enabled" → still ACTIVE
                if et == 'CHECK_DATA_FLOW' and 'remains enabled' in det:
                    self._flow_timeline[rid].append((ts, et, 'ACTIVE_CONFIRMED'))

        # Sort timelines by time
        for rid in self._flow_timeline:
            self._flow_timeline[rid].sort(key=lambda x: x[0])
        for rid in self._restore_timeline:
            self._restore_timeline[rid].sort(key=lambda x: x[0])

    @staticmethod
    def _find_full_rid(prefix, text):
        """Find the full resource_id starting with prefix in text."""
        m = re.search(rf'\b({prefix}_[\w]+)\b', text)
        return m.group(1) if m else None

    # ── Public API ────────────────────────────────────────────────────────

    def get_identifiers_for_resource(self, resource_id, audit_at=None):
        """Return set of (email_lower, user_id) grounded links for a resource_id."""
        links = self._rid_to_identifiers.get(resource_id, set())
        if audit_at is None:
            return links
        return {link for link in links if link[2] <= audit_at}

    def resource_matches_user(self, resource_id, identifiers, audit_at=None):
        """True if resource has a grounded link matching any user identifier."""
        emails_lower = {e.lower() for e in identifiers.get('emails', set()) if e}
        user_id      = identifiers.get('user_id', '')
        for email, uid, event_time in self.get_identifiers_for_resource(resource_id, audit_at):
            if email in emails_lower:
                return True
            if uid and uid == user_id:
                return True
        return False

    def get_data_flow_state_at(self, resource_id, audit_at):
        """
        Derive data-flow state at audit_at from activity timeline.
        Returns: ('ACTIVE', activity_id) | ('DISABLED', activity_id) | (None, None)
        """
        events = [(ts, et, res)
                  for ts, et, res in self._flow_timeline.get(resource_id, [])
                  if ts <= audit_at]
        if not events:
            return None, None

        ts, et, res = events[-1]  # latest event at or before audit_at

        # Find the activity_id for citation
        aid = self._find_activity_id(resource_id, ts, et)

        if et == 'DISABLE_DATA_FLOW' and res == 'SUCCESS':
            return 'DISABLED', aid
        if et == 'CHECK_DATA_FLOW' and ('ACTIVE_CONFIRMED' in res or res == 'SUCCESS'):
            return 'ACTIVE', aid
        if et == 'SYNC_RECORD':
            return 'ACTIVE', aid
        return None, None

    def get_restore_state_at(self, resource_id, audit_at):
        """
        Derive backup restore state at audit_at.
        Returns: ('ACTIVE', activity_id) | ('BLOCKED', activity_id) | (None, None)
        """
        events = [(ts, et, res)
                  for ts, et, res in self._restore_timeline.get(resource_id, [])
                  if ts <= audit_at]
        if not events:
            return None, None

        ts, et, res = events[-1]
        aid = self._find_activity_id(resource_id, ts, et)

        if et == 'BLOCK_RESTORE' and res == 'SUCCESS':
            return 'BLOCKED', aid
        if et == 'CHECK_RESTORE_ACCESS' and res == 'SUCCESS':
            return 'ACTIVE', aid
        return None, None

    def _find_activity_id(self, resource_id, ts, event_type):
        """Find activity_id for a specific event (best-effort)."""
        for aid, act in self._by_activity_id.items():
            if (act.get('resource_id') == resource_id
                    and act.get('event_time') == ts
                    and act.get('event_type') == event_type):
                return aid
        return ''

    def get_failed_deletions(self, identifiers, audit_at):
        """
        Find resource_ids where a deletion was attempted but FAILED before audit_at,
        for resources linked to the user via grounded LINK_RESOURCE_IDENTITY.
        Returns list of (resource_id, system_id, activity_id).
        """
        results = []
        seen = set()
        for act in self._activity:
            ts  = act.get('event_time', '')
            if ts > audit_at:
                continue
            et  = act.get('event_type', '')
            res = act.get('reported_result', '')
            rid = act.get('resource_id', '')
            tgt = act.get('target_system', '')
            aid = act.get('activity_id', '')

            if et not in ('DELETE_RECORD', 'ANONYMIZE_RECORD', 'REDACT_RECORD'):
                continue
            if res not in ('FAILED', 'PARTIAL'):
                continue
            if not rid or rid in seen:
                continue

            # ONLY link via grounded resource link (no text scanning)
            if not self.resource_matches_user(rid, identifiers, audit_at):
                continue

            seen.add(rid)
            results.append((rid, tgt, aid))

        return results

    def get_active_flows_for_user(self, identifiers, audit_at):
        """
        Find data_flow_* resources that are ACTIVE at audit_at and linked to user.
        Returns list of (resource_id, activity_id).
        """
        results = []
        seen = set()
        for rid in self._flow_timeline:
            if rid in seen:
                continue
            if not self.resource_matches_user(rid, identifiers, audit_at):
                continue
            state, aid = self.get_data_flow_state_at(rid, audit_at)
            if state == 'ACTIVE':
                results.append((rid, aid))
                seen.add(rid)

        # Also scan CHECK_DATA_FLOW events matching user identifiers via details
        emails_lower = {e.lower() for e in identifiers.get('emails', set()) if e}
        user_id      = identifiers.get('user_id', '')
        for act in self._activity:
            ts  = act.get('event_time', '')
            if ts > audit_at:
                continue
            et  = act.get('event_type', '')
            rid = act.get('resource_id', '')
            det = act.get('details', '')
            aid = act.get('activity_id', '')
            if et != 'CHECK_DATA_FLOW' or 'remains enabled' not in det:
                continue
            if not rid or rid in seen:
                continue
            det_lower = det.lower()
            linked = (user_id and user_id in det_lower) or any(e in det_lower for e in emails_lower)
            if linked:
                results.append((rid, aid))
                seen.add(rid)
        return results

    def get_active_restores_for_user(self, identifiers, audit_at):
        """
        Find backup_* resources that are ACTIVE (restore possible) at audit_at and linked to user.
        Returns list of (resource_id, activity_id).
        """
        results = []
        seen = set()
        for rid in self._restore_timeline:
            if rid in seen:
                continue
            if not self.resource_matches_user(rid, identifiers, audit_at):
                continue
            state, aid = self.get_restore_state_at(rid, audit_at)
            if state == 'ACTIVE':
                results.append((rid, aid))
                seen.add(rid)

        # Also scan CHECK_RESTORE_ACCESS matching user via details
        emails_lower = {e.lower() for e in identifiers.get('emails', set()) if e}
        user_id      = identifiers.get('user_id', '')
        for act in self._activity:
            ts  = act.get('event_time', '')
            if ts > audit_at:
                continue
            et  = act.get('event_type', '')
            rid = act.get('resource_id', '')
            det = act.get('details', '')
            res = act.get('reported_result', '')
            aid = act.get('activity_id', '')
            if et != 'CHECK_RESTORE_ACCESS' or res != 'SUCCESS':
                continue
            if not rid or rid in seen:
                continue
            # "can still be restored" → active
            if 'can still be restored' not in det:
                continue
            det_lower = det.lower()
            linked = (user_id and user_id in det_lower) or any(e in det_lower for e in emails_lower)
            if linked:
                results.append((rid, aid))
                seen.add(rid)
        return results
