"""Unit tests for PII and secrets sanitization in n8n-forensic-incident-triage."""

import pytest
from triage.sanitizer import sanitize_pii


def test_sanitize_email():
    text = "Please contact lead investigator at agent.smith@forensics.gov for case details."
    sanitized, counts = sanitize_pii(text)
    assert "[REDACTED_EMAIL]" in sanitized
    assert "agent.smith@forensics.gov" not in sanitized
    assert counts.get("email") == 1


def test_sanitize_ipv4_and_ipv6():
    text = "Attacker breached node 192.168.1.100 and communicated with 2001:0db8:85a3:0000:0000:8a2e:0370:7334"
    sanitized, counts = sanitize_pii(text)
    assert "192.168.1.100" not in sanitized
    assert "2001:0db8" not in sanitized
    assert "[REDACTED_IP]" in sanitized
    assert counts.get("ipv4") == 1
    assert counts.get("ipv6") == 1


def test_sanitize_credit_card_and_ssn():
    text = "Stolen card 4532-1234-5678-9010 and suspect SSN 123-45-6789 found in dump."
    sanitized, counts = sanitize_pii(text)
    assert "4532-1234" not in sanitized
    assert "123-45-6789" not in sanitized
    assert "[REDACTED_CARD]" in sanitized
    assert "[REDACTED_ID]" in sanitized
    assert counts.get("credit_card") == 1
    assert counts.get("ssn") == 1


def test_sanitize_phone():
    text = "Threat actor contacted victim via +1 (555) 234-5678 demanding ransom."
    sanitized, counts = sanitize_pii(text)
    assert "[REDACTED_PHONE]" in sanitized
    assert "555" not in sanitized
    assert counts.get("phone") == 1


def test_sanitize_secrets_and_api_keys():
    dummy_key = "sk_" + "test_" + "1234567890abcdef1234"
    dummy_bearer = "token_" + "secret_" + "9988776655443322"
    text = f"Compromised API key: api_key={dummy_key} and Bearer {dummy_bearer}"
    sanitized, counts = sanitize_pii(text)
    assert "[REDACTED_SECRET]" in sanitized
    assert "sk_" not in sanitized
    assert counts.get("secret") >= 1


def test_sanitize_empty_string():
    sanitized, counts = sanitize_pii("")
    assert sanitized == ""
    assert counts == {}


def test_sanitize_clean_text_no_pii():
    text = "Standard incident response report for internal server reboot."
    sanitized, counts = sanitize_pii(text)
    assert sanitized == text
    assert counts == {}


def test_sanitize_multiple_emails():
    text = "Emails: alice@corp.com, bob@corp.com, charlie@agency.gov"
    sanitized, counts = sanitize_pii(text)
    assert sanitized.count("[REDACTED_EMAIL]") == 3
    assert counts.get("email") == 3


def test_sanitize_mixed_pii_counts():
    text = "Investigator: root@sys.org, IP: 172.16.0.1, Card: 1111-2222-3333-4444"
    sanitized, counts = sanitize_pii(text)
    assert "[REDACTED_EMAIL]" in sanitized
    assert "[REDACTED_IP]" in sanitized
    assert "[REDACTED_CARD]" in sanitized
    assert counts == {"email": 1, "ipv4": 1, "credit_card": 1}

