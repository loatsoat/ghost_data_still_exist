"""
Phase 3 & 5: SystemActivityLinker
Builds grounded links between resources and users from system_activity,
and derives data-flow / restore state as of audit_at.

Approach:
1. Parse LINK_RESOURCE_IDENTITY events → resource_id to (email, user_id) map.
2. For data flows: last CHECK_DATA_FLOW or DISABLE_DATA_FLOW at or before audit_at.
3. For backups: last CHECK_RESTORE_ACCESS or BLOCK_RESTORE at or before audit_at.

HARD RULE: never link via activity unless a LINK_RESOURCE_IDENTITY event ties
the resource to the user. No other event's details name a subject.
"""

import re
from collections import defaultdict


# Every link event ends "... to <email> and user_NN"; the words before it vary
# ("linked X (alias) to", "confirmed X (file) belongs only to").
_DETAIL_RE = re.compile(r'\bto\s+([\w.@+-]+)\s+and\s+(user_\d+)', re.IGNORECASE)
# The alias a link event gives its resource: "linked X (alias) to ...".
_ALIAS_RE = re.compile(r'\(([^)]+)\)')
_RESOURCE_IN_DETAIL = re.compile(
    r'\b(?:account|search|analytics|support|export|data_flow|backup|audit_record|tombstone)_\w+\b'
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

        # (resource_id, alias, target_system, email_lower, user_id, event_time)
        self._links = []

        # resource_id -> sorted list of (event_time, event_type, result, activity_id)
        self._flow_timeline: dict[str, list] = defaultdict(list)
        self._restore_timeline: dict[str, list] = defaultdict(list)

        self._build()

    def _build(self):
        for act in self._activity:
            aid  = act.get('activity_id', '')
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
                        alias = _ALIAS_RE.search(det)
                        self._links.append((
                            rid, alias.group(1) if alias else rid,
                            act.get('target_system', ''), email, user_id, ts))
                    # Also link any OTHER resource_ids mentioned in the detail
                    for other_rid in _RESOURCE_IN_DETAIL.findall(det):
                        if other_rid != rid:
                            self._rid_to_identifiers[other_rid].add((email, user_id, ts))

            # Data-flow state events
            if et in ('CHECK_DATA_FLOW', 'DISABLE_DATA_FLOW', 'SYNC_RECORD'):
                if rid and ('data_flow' in rid or 'integration' in act.get('target_system', '')):
                    self._flow_timeline[rid].append((ts, et, res, aid))

            # Restore-risk state events
            if et in ('CHECK_RESTORE_ACCESS', 'BLOCK_RESTORE', 'RESTORE_BACKUP'):
                if rid:
                    self._restore_timeline[rid].append((ts, et, res, aid))

        # Sort timelines by time
        for timeline in (self._flow_timeline, self._restore_timeline):
            for events in timeline.values():
                events.sort(key=lambda x: x[0])

    # ── Public API ────────────────────────────────────────────────────────

    def get_identifiers_for_resource(self, resource_id, audit_at=None):
        """Return set of (email_lower, user_id) grounded links for a resource_id."""
        links = self._rid_to_identifiers.get(resource_id, set())
        if audit_at is None:
            return links
        return {link for link in links if link[2] <= audit_at}

    def get_links_for_user(self, identifiers, audit_at):
        """
        Link events naming this user at or before audit_at.
        Returns list of (resource_id, alias, target_system).
        """
        emails_lower = {e.lower() for e in identifiers.get('emails', set()) if e}
        user_id      = identifiers.get('user_id', '')
        return [(rid, alias, system)
                for rid, alias, system, email, uid, ts in self._links
                if ts <= audit_at and (email in emails_lower or (uid and uid == user_id))]

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
        events = [e for e in self._flow_timeline.get(resource_id, [])
                  if e[0] <= audit_at]
        if not events:
            return None, None

        ts, et, res, aid = events[-1]  # latest event at or before audit_at

        if et == 'DISABLE_DATA_FLOW' and res == 'SUCCESS':
            return 'DISABLED', aid
        if et == 'CHECK_DATA_FLOW' and res == 'SUCCESS':
            return 'ACTIVE', aid
        if et == 'SYNC_RECORD':
            return 'ACTIVE', aid
        return None, None

    def get_restore_state_at(self, resource_id, audit_at):
        """
        Derive backup restore state at audit_at.
        Returns: ('ACTIVE', activity_id) | ('BLOCKED', activity_id) | (None, None)
        """
        events = [e for e in self._restore_timeline.get(resource_id, [])
                  if e[0] <= audit_at]
        if not events:
            return None, None

        ts, et, res, aid = events[-1]

        if et == 'BLOCK_RESTORE' and res == 'SUCCESS':
            return 'BLOCKED', aid
        if et == 'CHECK_RESTORE_ACCESS' and res == 'SUCCESS':
            return 'ACTIVE', aid
        return None, None

    def get_failed_deletions(self, identifiers, audit_at):
        """
        Find resource_ids where a deletion was attempted but FAILED before audit_at,
        for resources linked to the user via grounded LINK_RESOURCE_IDENTITY.
        Returns list of (resource_id, system_id, activity_id).
        """
        ops = ('DELETE_RECORD', 'ANONYMIZE_RECORD', 'REDACT_RECORD')
        # A later successful attempt supersedes an earlier failure.
        last_success = {}
        for act in self._activity:
            ts = act.get('event_time', '')
            if (act.get('event_type') in ops and ts <= audit_at
                    and act.get('reported_result') == 'SUCCESS'):
                rid = act.get('resource_id', '')
                last_success[rid] = max(ts, last_success.get(rid, ''))

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

            if et not in ops:
                continue
            if res not in ('FAILED', 'PARTIAL'):
                continue
            if not rid or rid in seen or last_success.get(rid, '') > ts:
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
        for rid in self._flow_timeline:
            if not self.resource_matches_user(rid, identifiers, audit_at):
                continue
            state, aid = self.get_data_flow_state_at(rid, audit_at)
            if state == 'ACTIVE':
                results.append((rid, aid))
        return results

    def get_active_restores_for_user(self, identifiers, audit_at):
        """
        Find backup_* resources that are ACTIVE (restore possible) at audit_at and linked to user.
        Returns list of (resource_id, activity_id).
        """
        results = []
        for rid in self._restore_timeline:
            if not self.resource_matches_user(rid, identifiers, audit_at):
                continue
            state, aid = self.get_restore_state_at(rid, audit_at)
            if state == 'ACTIVE':
                results.append((rid, aid))
        return results
