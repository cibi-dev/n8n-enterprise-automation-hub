"""Unit tests for cryptographic and anti-SSRF verification in n8n-devsecops-audit-bridge."""

import hashlib
import hmac
import ipaddress
import pytest

from bridge.verifier import (
    is_ip_blocked,
    validate_webhook_url,
    verify_hmac_signature,
)


def test_verify_hmac_signature_valid():
    secret = "super-secret-key-1234"
    payload = b'{"status": "ok", "run_id": 100}'
    sig = hmac.new(secret.encode("utf-8"), payload, hashlib.sha256).hexdigest()

    assert verify_hmac_signature(payload, sig, secret) is True
    assert verify_hmac_signature(payload, f"sha256={sig}", secret) is True
    assert verify_hmac_signature(payload, f"SHA256={sig.upper()}", secret) is True


def test_verify_hmac_signature_tampered_payload():
    secret = "super-secret-key-1234"
    payload = b'{"status": "ok"}'
    sig = hmac.new(secret.encode("utf-8"), payload, hashlib.sha256).hexdigest()

    tampered = b'{"status": "tampered"}'
    assert verify_hmac_signature(tampered, sig, secret) is False


def test_verify_hmac_signature_wrong_secret():
    secret = "secret-1"
    payload = b'{"test": 1}'
    sig = hmac.new(secret.encode("utf-8"), payload, hashlib.sha256).hexdigest()

    assert verify_hmac_signature(payload, sig, "wrong-secret") is False


def test_verify_hmac_signature_empty_or_invalid_format():
    assert verify_hmac_signature(b"data", "", "secret") is False
    assert verify_hmac_signature(b"data", "short", "secret") is False
    assert verify_hmac_signature(b"data", "a" * 64, "") is False


def test_is_ip_blocked_private_ranges():
    # Loopback
    assert is_ip_blocked(ipaddress.ip_address("127.0.0.1")) is True
    assert is_ip_blocked(ipaddress.ip_address("127.0.0.254")) is True
    assert is_ip_blocked(ipaddress.ip_address("::1")) is True

    # Private RFC1918
    assert is_ip_blocked(ipaddress.ip_address("10.0.0.1")) is True
    assert is_ip_blocked(ipaddress.ip_address("172.16.0.5")) is True
    assert is_ip_blocked(ipaddress.ip_address("192.168.1.1")) is True

    # Cloud metadata link-local
    assert is_ip_blocked(ipaddress.ip_address("169.254.169.254")) is True

    # Public IP should not be blocked
    assert is_ip_blocked(ipaddress.ip_address("8.8.8.8")) is False
    assert is_ip_blocked(ipaddress.ip_address("1.1.1.1")) is False


def test_validate_webhook_url_allowed():
    # Public IP without active DNS lookup
    allowed, reason = validate_webhook_url("https://8.8.8.8/webhook", resolve_dns=False)
    assert allowed is True
    assert "Valid" in reason


def test_validate_webhook_url_blocked_schemes():
    allowed, reason = validate_webhook_url("file:///etc/passwd", resolve_dns=False)
    assert allowed is False
    assert "Disallowed URL scheme" in reason

    allowed, _ = validate_webhook_url("ftp://server/file", resolve_dns=False)
    assert allowed is False


def test_validate_webhook_url_blocked_internal_hostnames():
    bad_urls = [
        "http://localhost:8080/hook",
        "https://127.0.0.1:9000/api",
        "http://169.254.169.254/latest/meta-data/",
        "http://10.0.0.15/internal",
        "http://192.168.0.1/admin",
        "http://metadata.google.internal/computeMetadata/v1/",
    ]
    for url in bad_urls:
        allowed, reason = validate_webhook_url(url, resolve_dns=False)
        assert allowed is False, f"Expected {url} to be blocked"
        assert "SSRF" in reason or "blocked" in reason or "internal" in reason


def test_validate_webhook_url_invalid_syntax():
    allowed, reason = validate_webhook_url("", resolve_dns=False)
    assert allowed is False

    allowed, reason = validate_webhook_url("http://", resolve_dns=False)
    assert allowed is False

    allowed, reason = validate_webhook_url("not_a_valid_url", resolve_dns=False)
    assert allowed is False


def test_validate_webhook_url_with_dns_resolution(monkeypatch):
    import socket

    # Simulate resolved to loopback
    def mock_getaddrinfo_private(host, port):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 80))]

    monkeypatch.setattr(socket, "getaddrinfo", mock_getaddrinfo_private)
    allowed, reason = validate_webhook_url("http://evil-dns.com/hook", resolve_dns=True)
    assert allowed is False
    assert "blocked internal network" in reason

    # Simulate resolved to public IP
    def mock_getaddrinfo_public(host, port):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 80))]

    monkeypatch.setattr(socket, "getaddrinfo", mock_getaddrinfo_public)
    allowed, reason = validate_webhook_url("http://example.com/hook", resolve_dns=True)
    assert allowed is True

    # Simulate DNS failure
    def mock_getaddrinfo_fail(host, port):
        raise socket.gaierror("Name not known")

    monkeypatch.setattr(socket, "getaddrinfo", mock_getaddrinfo_fail)
    allowed, reason = validate_webhook_url("http://invalid-host-dns.com/hook", resolve_dns=True)
    assert allowed is False
    assert "DNS resolution failed" in reason
