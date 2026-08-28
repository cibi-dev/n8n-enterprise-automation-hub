"""PII and Sensitive Data Sanitizer.

Conforms to Canonical Security Standard #15 (strict sanitization & ReDoS defense).
"""

from __future__ import annotations

import re
from typing import Dict, Tuple

# Precompiled linear-time regex patterns (ReDoS safe)
EMAIL_PATTERN = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
IPV4_PATTERN = re.compile(r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b")
IPV6_PATTERN = re.compile(r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b")
PHONE_PATTERN = re.compile(r"(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b")
CREDIT_CARD_PATTERN = re.compile(r"\b(?:\d{4}[-\s]?){3}\d{4}\b")
SSN_PATTERN = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
SECRET_PATTERN = re.compile(r"(?i)\b(?:bearer\s+[a-zA-Z0-9_\-\.]{16,}|api[_\-\s]?key[\s:=]+[a-zA-Z0-9_\-]{16,}|password[\s:=]+\S+)\b")


def sanitize_pii(text: str) -> Tuple[str, Dict[str, int]]:
    """Sanitize all personally identifiable information (PII) and secrets from text.

    Args:
        text: Raw incident narrative text.

    Returns:
        (sanitized_text, redacted_counts_dict)
    """
    if not text:
        return "", {}

    counts: Dict[str, int] = {
        "email": 0,
        "ipv4": 0,
        "ipv6": 0,
        "phone": 0,
        "credit_card": 0,
        "ssn": 0,
        "secret": 0,
    }

    sanitized = text

    # 1. Redact Secrets / Tokens / Passwords
    def repl_secret(m: re.Match) -> str:
        counts["secret"] += 1
        return "[REDACTED_SECRET]"
    sanitized = SECRET_PATTERN.sub(repl_secret, sanitized)

    # 2. Redact Emails
    def repl_email(m: re.Match) -> str:
        counts["email"] += 1
        return "[REDACTED_EMAIL]"
    sanitized = EMAIL_PATTERN.sub(repl_email, sanitized)

    # 3. Redact Credit Cards
    def repl_card(m: re.Match) -> str:
        counts["credit_card"] += 1
        return "[REDACTED_CARD]"
    sanitized = CREDIT_CARD_PATTERN.sub(repl_card, sanitized)

    # 4. Redact SSN
    def repl_ssn(m: re.Match) -> str:
        counts["ssn"] += 1
        return "[REDACTED_ID]"
    sanitized = SSN_PATTERN.sub(repl_ssn, sanitized)

    # 5. Redact Phones
    def repl_phone(m: re.Match) -> str:
        counts["phone"] += 1
        return "[REDACTED_PHONE]"
    sanitized = PHONE_PATTERN.sub(repl_phone, sanitized)

    # 6. Redact IPv4
    def repl_ipv4(m: re.Match) -> str:
        counts["ipv4"] += 1
        return "[REDACTED_IP]"
    sanitized = IPV4_PATTERN.sub(repl_ipv4, sanitized)

    # 7. Redact IPv6
    def repl_ipv6(m: re.Match) -> str:
        counts["ipv6"] += 1
        return "[REDACTED_IP]"
    sanitized = IPV6_PATTERN.sub(repl_ipv6, sanitized)

    # Filter non-zero counts
    active_counts = {k: v for k, v in counts.items() if v > 0}
    return sanitized, active_counts
