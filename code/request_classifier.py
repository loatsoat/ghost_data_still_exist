"""
Request Classifier - Phase 1 rewrite.
Intent-first: explicit deletion intent wins unless the WHOLE request is
clearly about access, correction, export, or marketing opt-out only.
Deterministic classification with a deletion-safe fallback.
"""

import re


# ── Pure-access / pure-non-deletion phrases ───────────────────────────────
# These fire on the WHOLE text when there is no deletion-strong match.
# They must be strong evidence of a NON-deletion-only request.
NON_DELETION_SOLE_PATTERNS = [
    # Explicit negation of deletion intent takes precedence over nearby
    # service-request wording such as "close the account".
    r"\b(?:do\s+not|don't|do\s+not|not)\s+(?:delete|erase|remove|close|wipe|purge)\b",
    r"\bnot\s+(?:a\s+)?request\s+to\s+(?:delete|erase|remove)\b",
    r"\bwithout\s+(?:deleting|erasing|removing|closing)\b",
    # Access/subject-access requests: "access my data", "copy of my records"
    # Require the WHOLE text to be about access without any deletion word.
    r"^\s*(?:I\s+(?:would\s+like\s+to|want\s+to|am\s+requesting\s+to|request\s+to)\s+)?access\s+(?:all\s+)?(?:the\s+)?(?:personal\s+)?(?:data|records|information)\b(?:.*\b(?:article|gdpr|ccpa|dsar|subject\s+access)\b)?[^a-z]*$",
    r"^\s*(?:please\s+)?send\s+me\s+(?:a\s+)?(?:full\s+)?copy\s+of\s+my\s+(?:personal\s+)?(?:data|records|information)\b",
    r"^\s*I\s+(?:would\s+like|want)\s+(?:a\s+)?(?:full\s+)?copy\s+of\s+(?:my|all)\s+(?:personal\s+)?(?:data|records|information)\b",
    # Export/data-portability requests (no deletion)
    # Only matches when the WHOLE request is about exporting with no deletion words
    r"^(?:(?!delete|erase|remove|wipe|purge|close\s+account|delet).)*\b(?:export|download|data\s+portability)\b(?:(?!delete|erase|remove|wipe|purge|close\s+account|delet).)*$",
    r"^\s*I\s+want\s+(?:a\s+)?(?:machine.readable\s+)?(?:copy|download|export)\s+of\s+(?:everything|all|my)(?!.*\b(?:delete|erase|remove|wipe|purge)\b)",
    # Correction/rectification — no delete word anywhere
    r"^\s*(?:please\s+)?(?:correct|rectify|fix|update)\s+(?:the\s+|my\s+)?(?:incorrect|wrong|inaccurate|outdated\s+)?(?:personal\s+)?(?:information|data|details|name|address|date\s+of\s+birth)\b(?!.*\b(?:delete|erase|remove|close|wipe|purge)\b)",
    r"\bmy\s+(?:date\s+of\s+birth|name|address|email|phone)\s+(?:on\s+file\s+)?is\s+(?:incorrect|wrong|outdated)\b(?!.*\b(?:delete|erase|remove|close|wipe|purge)\b)",
    # Marketing opt-out
    r"\b(?:unsubscribe|opt[\s-]?out)\b(?!.*\b(?:delete|erase|remove|close|wipe|purge)\b)",
    r"\bstop\s+(?:sending\s+)?(?:me\s+)?(?:marketing|promotional|newsletter|advertising)\b(?!.*\b(?:delete|erase|remove|close|wipe|purge)\b)",
    r"\bno\s+(?:more\s+)?(?:marketing|promotional|newsletter)\s+(?:emails?|communications?|messages?)\b(?!.*\b(?:delete|erase|remove|close|wipe|purge)\b)",
    # Other explicit non-deletion account-service requests
    r"^\s*(?:please\s+)?(?:change|update|replace)\s+(?:the\s+|my\s+)?(?:email|e-mail|phone|mobile|telephone|address|name)\b(?:\s+address)?(?!.*\b(?:delete|erase|remove|close|wipe|purge)\b)",
    r"\b(?:correct|fix|update|replace)\b.{0,50}\b(?:surname|last\s+name|mobile\s+number|phone\s+number|email\s+address)\b(?!.*\b(?:delete|erase|remove|close|wipe|purge)\b)",
    r"\b(?:reset|recover|unlock)\s+(?:my\s+)?(?:login|password|account\s+access|access)\b(?!.*\b(?:delete|erase|remove|close|wipe|purge)\b)",
    r"^\s*(?:please\s+)?(?:send|provide|give)\s+me\s+(?:a\s+)?(?:copy|record|invoice|invoices|information|details)\b(?!.*\b(?:delete|erase|remove|close|wipe|purge)\b)",
    r"\b(?:need|want|would like|could you send|can you send|please send)\b.{0,35}\b(?:copy|information|invoices?|records?)\b(?!.*\b(?:delete|erase|remove|close|wipe|purge)\b)",
    r"\b(?:information|data|records?)\s+request\b(?!.*\b(?:delete|erase|remove|close|wipe|purge)\b)",
    r"\bwhat\s+(?:personal\s+)?(?:information|data|records?)\s+(?:do\s+you\s+hold|you\s+hold)\b(?!.*\b(?:delete|erase|remove|close|wipe|purge)\b)",
    r"\b(?:remove me from|stop)\b.{0,30}\b(?:marketing|promotional|newsletter)\b(?!.*\b(?:delete|erase|remove|close|wipe|purge)\b)",
    r"\b(?:my\s+)?(?:surname|last\s+name|mobile\s+number|phone\s+number|email\s+address)\b.{0,35}\b(?:misspelled|incorrect|outdated|out\s+of\s+date|wrong)\b(?!.*\b(?:delete|erase|remove|close|wipe|purge)\b)",
    r"\b(?:can't|cannot|can not|unable to)\s+(?:access|log\s*in)\b(?!.*\b(?:delete|erase|remove|close|wipe|purge)\b)",
    # Complaint only — no delete intent
    r"^\s*I\s+(?:am|want\s+to\s+make)\s+(?:a\s+)?(?:formal\s+)?complaint\b(?!.*\b(?:delete|erase|remove|close|wipe|purge)\b)",
    r"^(?:(?!delete|erase|remove|wipe|purge|close\s+my\s+account|delet).)*\b(?:formal\s+)?complaint\b(?:(?!delete|erase|remove|wipe|purge|close\s+my\s+account|delet).)*$",
    # French access request
    r"\bdonner[- ]moi\s+acc[eè]s\b(?!.*\b(?:supprimer|effacer|supprimi|fermer|clôtur)\b)",
    r"\bcopie\s+de\s+(?:mes|toutes\s+mes)\s+donn[eé]es\b(?!.*\b(?:supprimer|effacer|supprimi|fermer|clôtur)\b)",
    r"\bje\s+souhaite\s+recevoir\s+une\s+copie\b",
]

# ── Strong deletion-intent patterns (multilingual) ───────────────────────
DELETION_STRONG = [
    # English
    r"\b(permanently\s+)?(delete|erase|remove|wipe|purge)\b.{0,60}\b(account|profile|data|personal.information|records)\b",
    r"\b(account|profile|data|personal.information|records)\b.{0,60}\b(permanently\s+)?(delete|erase|remove|wipe|purge)\b",
    r"\b(close|terminate|deactivate)\b.{0,60}\b(account|profile)\b.{0,60}\b(delet|eras|remov|wip|purg)",
    r"\bdeletion\s+(request|of\s+(my|the)\s+(account|data|profile))\b",
    r"\brequest.{0,20}\bdeletion\b",
    r"\bprocess.{0,20}\bdeletion\b",
    r"\bpermanent(ly)?\s+(account.deletion|delete|erase|removal)\b",
    r"\bI\s+(want|would\s+like|am\s+requesting|request|ask)\s+(you\s+to\s+)?(permanently\s+)?(delete|erase|remove|close|terminate)\b",
    r"\b(close|delete|erase|remove)\s+(and\s+\w+\s+)?my\s+account\b",
    r"\bpersonal.data.deletion\b",
    r"\bI\s+(am\s+)?(deleting|closing)\s+my\s+account\b",
    r"\bmy\s+account.{0,30}\b(closed|deleted|erased|removed)\b",
    r"\bthen\s+delete\s+everything\b",
    r"\bdelete\s+everything\s+else\b",
    r"\berased?\b.{0,30}\b(permanently|everything|all|records)\b",
    # Spanish
    r"\b(eliminar|borrar|suprimir|cerrar|cancelar)\b.{0,60}\b(cuenta|datos\s+personales|perfil)\b",
    r"\bexclusi[oó]n\s+permanente\b",
    r"\beliminaci[oó]n\s+permanente\b",
    r"\bsolicito\b.{0,60}\b(eliminar|borrar|suprimir|exclusi[oó]n|eliminaci[oó]n)\b",
    # French
    r"\b(supprimer|effacer|fermer|clôturer|résilier)\b.{0,60}\b(compte|données\s+personnelles|profil)\b",
    r"\bsuppression\s+définitive\b",
    r"\bje\s+demande\b.{0,60}\b(suppression|supprim|effac)\b",
    # Portuguese
    r"\b(excluir|apagar|deletar|remover|fechar)\b.{0,60}\b(conta|dados\s+pessoais|perfil)\b",
    r"\bexclus[ãa]o\s+permanente\b",
    r"\bsolicito\b.{0,60}\b(excluir|apagar|exclus[ãa]o|eliminac)\b",
    # Korean
    r"[영구\s]*삭제",
    r"계정.{0,20}삭제",
    r"삭제.{0,20}요청",
    r"개인정보.{0,30}삭제",
    # Japanese
    r"完全な削除",
    r"アカウント.{0,20}削除",
    r"削除.{0,20}依頼",
    r"個人情報.{0,20}削除",
    # German
    r"\b(löschen|entfernen|schließen)\b.{0,60}\b(konto|profil|daten)\b",
    r"\bDatens[ck]hutz.{0,30}(löschen|entfernen)\b",
]

# Pre-compile
_NON_DEL_SOLE_RE = [re.compile(p, re.IGNORECASE | re.DOTALL) for p in NON_DELETION_SOLE_PATTERNS]
_DEL_STRONG_RE   = [re.compile(p, re.IGNORECASE | re.DOTALL) for p in DELETION_STRONG]
_EXPLICIT_NON_DEL_RE = [
    re.compile(p, re.IGNORECASE | re.DOTALL)
    for p in NON_DELETION_SOLE_PATTERNS[:3]
]

class RequestClassifier:
    def classify(self, request_text):
        """
        Returns True if the request authorizes deletion, False otherwise.
        Strategy (in order):
          1. Strong deletion intent → True immediately.
          2. No deletion intent AND sole non-deletion pattern matches → False.
          3. Deterministic safe default: True.
        """
        if not request_text:
            return False

        text = request_text.strip()

        # Explicit negation must win over a nearby phrase such as
        # "close the account".
        for pat in _EXPLICIT_NON_DEL_RE:
            if pat.search(text):
                return False

        # 1. Strong deletion intent wins unconditionally
        for pat in _DEL_STRONG_RE:
            if pat.search(text):
                return True

        # 2. Non-deletion sole patterns — only fire when deletion intent absent
        for pat in _NON_DEL_SOLE_RE:
            if pat.search(text):
                return False

        # Safe default: treat as deletion so we never silently zero a case
        return True
