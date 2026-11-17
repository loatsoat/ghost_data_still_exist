"""Deletion policy tables: which operation and final state each rule action requires."""

# Operation order for sorting within each phase
FINDING_ORDER = [
    'REPORT_REMAINING_RECORD',
    'REPORT_EXPOSED_PII',
    'REPORT_ACTIVE_DATA_FLOW',
    'REPORT_RESTORE_RISK',
]

REMEDIATION_ORDER = [
    'DISABLE_DATA_FLOW',
    'BLOCK_RESTORE',
    'DELETE_RECORD',
    'REDACT_RECORD',
    'ANONYMIZE_RECORD',
]

VERIFICATION_ORDER = [
    'VERIFY_RECORD_ABSENT',
    'VERIFY_RECORD_PRESENT',
    'VERIFY_RECORD_REDACTED',
    'VERIFY_RECORD_ANONYMIZED',
    'VERIFY_DATA_FLOW_DISABLED',
    'VERIFY_RESTORE_BLOCKED',
]

# Map record type to data category (from deletion_rules.csv)
RECORD_TYPE_TO_CATEGORY = {
    'customer_profile': 'USER_PROFILE',
    'search_document': 'SEARCH_INDEX_ENTRY',
    'analytics_profile': 'ANALYTICS_PROFILE',
    'support_record': 'SUPPORT_MESSAGE',
    'support_attachment': 'SUPPORT_ATTACHMENT',
    'user_export': 'USER_EXPORT',
    'connector': None,  # Data flows are tracked from system_activity
    'backup': 'BACKUP_ARCHIVE',
    'security_audit': 'SECURITY_AUDIT_LOG',
    'account_tombstone': 'ACCOUNT_TOMBSTONE',
    'marketing_profile': 'MARKETING_PROFILE',
    'secondary_identifier': 'SECONDARY_IDENTIFIER',
    'legal_hold': 'LEGAL_HOLD_RECORD',
}

# Record types that may stay once direct identifiers are gone, and the state
# a document showing none of them proves.
IDENTIFIER_FREE_STATE = {
    'account_tombstone': 'REDACTED',
    'analytics_profile': 'ANONYMIZED',
}

# Map rule action to finding operation
ACTION_TO_FINDING = {
    'DELETE': 'REPORT_REMAINING_RECORD',
    'REDACT': 'REPORT_EXPOSED_PII',
    'ANONYMIZE': 'REPORT_EXPOSED_PII',
}

# Map rule action to remediation operation
ACTION_TO_REMEDIATION = {
    'DELETE': 'DELETE_RECORD',
    'REDACT': 'REDACT_RECORD',
    'ANONYMIZE': 'ANONYMIZE_RECORD',
}

# Map rule action to verification operation
ACTION_TO_VERIFICATION = {
    'DELETE': 'VERIFY_RECORD_ABSENT',
    'REDACT': 'VERIFY_RECORD_REDACTED',
    'ANONYMIZE': 'VERIFY_RECORD_ANONYMIZED',
}

# Verification state for each action
ACTION_TO_VERIFICATION_STATE = {
    'DELETE': 'ABSENT',
    'REDACT': 'REDACTED',
    'ANONYMIZE': 'ANONYMIZED',
}

# Remediation state for each action
ACTION_TO_REMEDIATION_STATE = {
    'DELETE': 'ABSENT',
    'REDACT': 'REDACTED',
    'ANONYMIZE': 'ANONYMIZED',
}

# States in which a record already satisfies each policy action.
COMPLIANT_STATES = {
    'DELETE': {'ABSENT'},
    'REDACT': {'REDACTED', 'ABSENT'},
    'ANONYMIZE': {'ANONYMIZED', 'ABSENT'},
}

# Process findings are fixed the same way whatever the record policy says.
PROCESS_FINDING_TARGET = {
    'REPORT_ACTIVE_DATA_FLOW': 'FLOW_DISABLED',
    'REPORT_RESTORE_RISK': 'RESTORE_BLOCKED',
}

# Final-state key -> (remediation operation, state) and (verification operation, state).
FIX_FOR = {
    'FLOW_DISABLED': ('DISABLE_DATA_FLOW', 'DISABLED'),
    'RESTORE_BLOCKED': ('BLOCK_RESTORE', 'BLOCKED'),
    **{a: (ACTION_TO_REMEDIATION[a], ACTION_TO_REMEDIATION_STATE[a]) for a in ACTION_TO_REMEDIATION},
}
VERIFY_FOR = {
    'RETAIN': ('VERIFY_RECORD_PRESENT', 'PRESENT'),
    'FLOW_DISABLED': ('VERIFY_DATA_FLOW_DISABLED', 'DISABLED'),
    'RESTORE_BLOCKED': ('VERIFY_RESTORE_BLOCKED', 'BLOCKED'),
    **{a: (ACTION_TO_VERIFICATION[a], ACTION_TO_VERIFICATION_STATE[a]) for a in ACTION_TO_VERIFICATION},
}
