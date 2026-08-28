"""Cryptographic and Network Verification Engine.

Implements:
- Standard #9 & CWE-208: Constant-time HMAC-SHA256 signature verification.
- Standard #14 & CWE-918: Strict anti-SSRF outbound webhook validation.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import socket
from urllib.parse import urlparse


def verify_hmac_signature(
    payload_bytes: bytes,
    signature_header: str,
    secret_key: str,
) -> bool:
    """Verify webhook payload signature using constant-time HMAC-SHA256.

    Args:
        payload_bytes: Raw received HTTP request body bytes.
        signature_header: Received signature header (e.g. 'sha256=abcdef...' or 'abcdef...').
        secret_key: Shared webhook secret key.

    Returns:
        True if signature is valid and matches; False otherwise.
    """
    if not signature_header or not secret_key:
        return False

    # Extract hex digest if prefixed with algorithm (e.g. sha256=...)
    sig = signature_header.strip()
    if "=" in sig:
        _, sig = sig.split("=", 1)
    sig = sig.strip().lower()

    if len(sig) != 64:
        return False

    computed = hmac.new(
        secret_key.encode("utf-8"),
        msg=payload_bytes,
        digestmod=hashlib.sha256,
    ).hexdigest().lower()

    # Constant-time comparison to prevent side-channel timing attacks (CWE-208)
    return hmac.compare_digest(computed, sig)


# Private, loopback, link-local and cloud metadata CIDR ranges (CWE-918 SSRF defense)
BLOCKED_IP_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),  # AWS/GCP/Azure link-local metadata (169.254.169.254)
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.0.0.0/24"),
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("198.18.0.0/15"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("240.0.0.0/4"),
    ipaddress.ip_network("255.255.255.255/32"),
    # IPv6 ranges
    ipaddress.ip_network("::/128"),
    ipaddress.ip_network("::1/128"),          # Loopback
    ipaddress.ip_network("fc00::/7"),         # Unique local
    ipaddress.ip_network("fe80::/10"),        # Link local
    ipaddress.ip_network("ff00::/8"),         # Multicast
]


def is_ip_blocked(ip_addr: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Check if an IP address belongs to any blocked/private/internal network."""
    if ip_addr.is_private or ip_addr.is_loopback or ip_addr.is_link_local or ip_addr.is_multicast or ip_addr.is_reserved:
        return True
    for net in BLOCKED_IP_NETWORKS:
        if ip_addr in net:
            return True
    return False


def validate_webhook_url(url: str, resolve_dns: bool = True) -> tuple[bool, str]:
    """Validate destination webhook URL against SSRF attacks (Guardrail #14).

    Args:
        url: URL string to inspect.
        resolve_dns: Whether to perform DNS resolution to verify target IP address.

    Returns:
        (is_allowed, reason_message)
    """
    if not url or not isinstance(url, str):
        return False, "URL cannot be empty"

    try:
        parsed = urlparse(url.strip())
    except Exception as e:
        return False, f"Malformed URL syntax: {e}"

    if parsed.scheme not in ("http", "https"):
        return False, f"Disallowed URL scheme: '{parsed.scheme}'. Only HTTP/HTTPS permitted."

    hostname = parsed.hostname
    if not hostname:
        return False, "URL missing valid hostname"

    # Check literal blocked hostnames
    if hostname.lower() in ("localhost", "127.0.0.1", "::1", "metadata.google.internal", "instance-data"):
        return False, f"Direct access to internal hostname '{hostname}' blocked (SSRF defense)"

    # Validate IP address if hostname is an IP
    try:
        ip_obj = ipaddress.ip_address(hostname)
        if is_ip_blocked(ip_obj):
            return False, f"Target IP {hostname} is in private/internal range (SSRF blocked)"
        return True, "Valid public IP destination"
    except ValueError:
        # Hostname is a domain name
        pass

    if resolve_dns:
        try:
            addr_info = socket.getaddrinfo(hostname, parsed.port or (443 if parsed.scheme == "https" else 80))
            for item in addr_info:
                sockaddr = item[4]
                resolved_ip_str = sockaddr[0]
                ip_obj = ipaddress.ip_address(resolved_ip_str)
                if is_ip_blocked(ip_obj):
                    return False, f"Resolved IP {resolved_ip_str} for host '{hostname}' is in blocked internal network"
        except socket.gaierror as e:
            return False, f"DNS resolution failed for hostname '{hostname}': {e}"

    return True, "Valid external webhook URL"
