"""Penal Classification and ISO/IEC 27037 Evidence Custody Engine."""

from __future__ import annotations

import hashlib
import json
import re
from typing import List, Tuple

from triage.models import CrimeCategory, IncidentPriority, SanitizedIncidentReport, utcnow_iso
from triage.sanitizer import sanitize_pii

# Heuristic penal classification keyword tables
CATEGORY_KEYWORDS = {
    CrimeCategory.RANSOMWARE_EXTORTION: [
        "ransomware", "encrypt", "extortion", "bitcoin", "decryptor", "lockbit",
        "ransom", "payment demand", "blackcat", "akira", "darkside", "cifrado", "rescate"
    ],
    CrimeCategory.DATA_THEFT: [
        "exfiltration", "data breach", "stolen records", "database dump", "leak",
        "confidential", "exfiltrated", "filtración", "robo de datos"
    ],
    CrimeCategory.UNAUTHORIZED_ACCESS: [
        "unauthorized access", "compromised credentials", "ssh brute force",
        "privilege escalation", "lateral movement", "backdoor", "webshell", "acceso no autorizado"
    ],
    CrimeCategory.FINANCIAL_SCAM: [
        "wire fraud", "phishing", "bec", "ceo fraud", "fake invoice",
        "stolen funds", "fraude", "estafa", "transferencia fraudulenta"
    ],
    CrimeCategory.DOS_ATTACK: [
        "ddos", "denial of service", "syn flood", "botnet", "amplification",
        "service unavailable", "ataque ddos", "denegación de servicio"
    ],
    CrimeCategory.IDENTITY_FRAUD: [
        "identity theft", "cloned account", "impersonation", "fake profile",
        "suplantación de identidad"
    ],
    CrimeCategory.MALWARE_DISTRIBUTION: [
        "trojan", "malware", "payload", "c2", "command and control", "dropper",
        "keylogger", "spyware"
    ],
}


def classify_crime_category(text: str) -> Tuple[CrimeCategory, IncidentPriority]:
    """Classify incident narrative into penal category and priority level."""
    lower_text = text.lower()

    scores: dict[CrimeCategory, int] = {cat: 0 for cat in CrimeCategory}

    for cat, keywords in CATEGORY_KEYWORDS.items():
        for kw in keywords:
            if kw in lower_text:
                scores[cat] += 1

    # Find highest scoring category
    best_cat = max(scores, key=scores.get)  # type: ignore
    if scores[best_cat] == 0:
        best_cat = CrimeCategory.OTHER

    # Determine priority
    if best_cat in (CrimeCategory.RANSOMWARE_EXTORTION, CrimeCategory.DATA_THEFT):
        priority = IncidentPriority.CRITICAL
    elif best_cat in (CrimeCategory.UNAUTHORIZED_ACCESS, CrimeCategory.FINANCIAL_SCAM, CrimeCategory.DOS_ATTACK):
        priority = IncidentPriority.HIGH
    elif best_cat in (CrimeCategory.IDENTITY_FRAUD, CrimeCategory.MALWARE_DISTRIBUTION):
        priority = IncidentPriority.MEDIUM
    else:
        priority = IncidentPriority.LOW

    return best_cat, priority


def extract_assets_and_indicators(text: str) -> Tuple[List[str], List[str]]:
    """Extract affected infrastructure hostnames and threat actor handles from text."""
    # Find domain names or service names
    assets = re.findall(r"\b(?:[a-zA-Z0-9\-]+\.)+(?:com|org|net|internal|corp|local|io)\b", text, re.IGNORECASE)
    # Find Telegram/Discord handles (@handle)
    iocs = re.findall(r"@[a-zA-Z0-9_]{3,30}\b", text)

    return sorted(list(set(assets))), sorted(list(set(iocs)))


def compute_custody_hash(raw_text: str, incident_id: str, reported_at: str) -> str:
    """Compute ISO/IEC 27037 digital evidence custody hash with domain separator."""
    hasher = hashlib.sha256()
    hasher.update(b"\x07")  # Forensic evidence domain separator (Standard #9)
    hasher.update(f"{incident_id}|{reported_at}|{raw_text}".encode("utf-8"))
    return hasher.hexdigest().lower()


def process_incident_triage(
    raw_text: str,
    incident_id: str,
    title: str = "Cybercrime Triage Report",
    reported_at: str | None = None,
) -> SanitizedIncidentReport:
    """Execute complete forensic triage pipeline: sanitize PII, classify and seal custody."""
    t_stamp = reported_at or utcnow_iso()
    sanitized_text, pii_counts = sanitize_pii(raw_text)
    category, priority = classify_crime_category(sanitized_text)
    assets, indicators = extract_assets_and_indicators(sanitized_text)
    custody_digest = compute_custody_hash(raw_text, incident_id, t_stamp)

    return SanitizedIncidentReport(
        incident_id=incident_id,
        title=title,
        sanitized_text=sanitized_text,
        redacted_pii_counts=pii_counts,
        crime_category=category,
        priority=priority,
        custody_sha256=custody_digest,
        affected_assets=assets,
        suspect_indicators=indicators,
        reported_at=t_stamp,
    )
