"""
Identity Resolver - Resolves request emails to user identities including
current and historical identifiers (emails, phones, email hashes).
"""

from collections import defaultdict


class IdentityResolver:
    def __init__(self, user_identities, user_audit_log):
        self.user_identities = user_identities
        self.user_audit_log = user_audit_log

        # Build email -> user_id mapping (case-insensitive)
        self.email_to_user = {}
        # Build user_id -> set of all known identifiers
        self.user_identifiers = defaultdict(lambda: {
            'user_id': None,
            'emails': set(),
            'phones': set(),
            'email_hashes': set(),
            'name': None,
        })

        self._build_index()

    def _build_index(self):
        # Index current identities
        for ident in self.user_identities:
            uid = ident['user_id']
            email = ident.get('email', '').strip()
            phone = ident.get('phone', '').strip() if ident.get('phone') else ''
            email_hash = ident.get('email_hash', '').strip() if ident.get('email_hash') else ''
            name = ident.get('name', '').strip() if ident.get('name') else ''

            self.user_identifiers[uid]['user_id'] = uid
            if email:
                self.user_identifiers[uid]['emails'].add(email.lower())
                self.email_to_user[email.lower()] = uid
            if phone:
                self.user_identifiers[uid]['phones'].add(phone)
            if email_hash:
                self.user_identifiers[uid]['email_hashes'].add(email_hash)
            if name:
                self.user_identifiers[uid]['name'] = name

        # Index historical changes from audit log
        for entry in self.user_audit_log:
            uid = entry.get('user_id', '').strip()
            if not uid:
                continue
            field = entry.get('field_name', '').strip()
            old_val = entry.get('old_value', '').strip() if entry.get('old_value') else ''
            new_val = entry.get('new_value', '').strip() if entry.get('new_value') else ''

            if field == 'email':
                if old_val:
                    self.user_identifiers[uid]['emails'].add(old_val.lower())
                    self.email_to_user[old_val.lower()] = uid
                if new_val:
                    self.user_identifiers[uid]['emails'].add(new_val.lower())
                    self.email_to_user[new_val.lower()] = uid
            elif field == 'phone':
                if old_val:
                    self.user_identifiers[uid]['phones'].add(old_val)
                if new_val:
                    self.user_identifiers[uid]['phones'].add(new_val)
            elif field == 'email_hash':
                if old_val:
                    self.user_identifiers[uid]['email_hashes'].add(old_val)
                if new_val:
                    self.user_identifiers[uid]['email_hashes'].add(new_val)

    def resolve(self, request_email):
        """
        Resolve a request email to a user identity.
        Returns a dict with user_id, emails, phones, email_hashes, name.
        Returns None if no match found.
        """
        email_lower = request_email.strip().lower()
        uid = self.email_to_user.get(email_lower)

        if uid is None:
            return None

        return {
            'user_id': uid,
            'emails': self.user_identifiers[uid]['emails'],
            'phones': self.user_identifiers[uid]['phones'],
            'email_hashes': self.user_identifiers[uid]['email_hashes'],
            'name': self.user_identifiers[uid]['name'],
        }

    def get_all_identifiers(self, user_id):
        """Get all known identifiers for a user_id."""
        if user_id not in self.user_identifiers:
            return None
        ident = self.user_identifiers[user_id]
        return {
            'user_id': user_id,
            'emails': ident['emails'],
            'phones': ident['phones'],
            'email_hashes': ident['email_hashes'],
            'name': ident['name'],
        }
