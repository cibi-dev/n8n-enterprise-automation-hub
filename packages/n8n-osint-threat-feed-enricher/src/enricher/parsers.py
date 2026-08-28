"""Feed Parsers for CISA KEV, NVD CVE and Generic Threat Intelligence Streams."""

from __future__ import annotations

import hashlib
import json
from typing import Any, Dict, List, Union

from enricher.models import ThreatAdvisory, ThreatFeedSource, utcnow_iso


def compute_content_hash(title: str, description: str, cve_id: str | None = None) -> str:
    """Compute deterministic SHA-256 digest over normalized advisory content."""
    canonical = f"{cve_id or ''}|{title.strip().lower()}|{description.strip().lower()}"
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def parse_cisa_kev_catalog(raw_data: Union[str, Dict[str, Any]]) -> List[ThreatAdvisory]:
    """Parse official CISA Known Exploited Vulnerabilities (KEV) JSON document.

    Args:
        raw_data: CISA KEV JSON string or parsed dictionary.

    Returns:
        List of normalized ThreatAdvisory models.
    """
    if isinstance(raw_data, str):
        try:
            data = json.loads(raw_data)
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid CISA KEV JSON syntax: {e}") from e
    else:
        data = raw_data

    if not isinstance(data, dict):
        raise ValueError("CISA KEV document must be a JSON object")

    vulnerabilities = data.get("vulnerabilities", [])
    if not isinstance(vulnerabilities, list):
        return []

    advisories: List[ThreatAdvisory] = []

    for v in vulnerabilities:
        if not isinstance(v, dict):
            continue

        cve_id = v.get("cveID") or ""
        v_name = v.get("vulnerabilityName") or v.get("shortDescription") or f"Exploited Advisory {cve_id}"
        desc = v.get("shortDescription") or v.get("vulnerabilityName") or "No description provided"
        pub_date = v.get("dateAdded") or utcnow_iso()
        ransomware = v.get("knownRansomwareCampaignUse")
        ransomware_str = str(ransomware) if ransomware and ransomware != "Unknown" else None

        raw_h = compute_content_hash(v_name, desc, cve_id)

        advisories.append(
            ThreatAdvisory(
                id=cve_id or raw_h[:16],
                title=str(v_name),
                description=str(desc),
                source_feed=ThreatFeedSource.CISA_KEV,
                cve_id=cve_id if cve_id.startswith("CVE-") else None,
                cvss_score=9.8 if ransomware_str else 8.5,  # Known exploited defaults to high/critical
                is_known_exploited=True,
                ransomware_campaign=ransomware_str,
                published_at=str(pub_date),
                reference_urls=[f"https://nvd.nist.gov/vuln/detail/{cve_id}"] if cve_id else [],
                raw_hash=raw_h,
            )
        )

    return advisories


def parse_nvd_cve_feed(raw_data: Union[str, Dict[str, Any]]) -> List[ThreatAdvisory]:
    """Parse NVD 2.0 API JSON vulnerability response.

    Args:
        raw_data: NVD 2.0 JSON string or parsed dictionary.

    Returns:
        List of normalized ThreatAdvisory models.
    """
    if isinstance(raw_data, str):
        try:
            data = json.loads(raw_data)
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid NVD JSON syntax: {e}") from e
    else:
        data = raw_data

    if not isinstance(data, dict):
        raise ValueError("NVD document must be a JSON object")

    vulnerabilities = data.get("vulnerabilities", [])
    if not isinstance(vulnerabilities, list):
        return []

    advisories: List[ThreatAdvisory] = []

    for item in vulnerabilities:
        if not isinstance(item, dict):
            continue

        cve_obj = item.get("cve", {})
        if not isinstance(cve_obj, dict):
            continue

        cve_id = cve_obj.get("id") or ""
        descriptions = cve_obj.get("descriptions", [])
        desc_text = "No English description available"
        for d in descriptions:
            if isinstance(d, dict) and d.get("lang") == "en":
                desc_text = d.get("value", desc_text)
                break

        title = f"{cve_id}: {desc_text[:90]}..." if len(desc_text) > 90 else f"{cve_id}: {desc_text}"

        # Extract CVSS score
        cvss_val: float | None = None
        metrics = cve_obj.get("metrics", {})
        cvss_v31 = metrics.get("cvssMetricV31", [])
        if cvss_v31 and isinstance(cvss_v31, list) and isinstance(cvss_v31[0], dict):
            cvss_data = cvss_v31[0].get("cvssData", {})
            cvss_val = cvss_data.get("baseScore")

        pub_date = cve_obj.get("published") or utcnow_iso()

        # Extract references
        refs: List[str] = []
        raw_refs = cve_obj.get("references", [])
        if isinstance(raw_refs, list):
            for r in raw_refs:
                if isinstance(r, dict) and "url" in r:
                    refs.append(str(r["url"]))

        raw_h = compute_content_hash(title, desc_text, cve_id)

        advisories.append(
            ThreatAdvisory(
                id=cve_id or raw_h[:16],
                title=title,
                description=desc_text,
                source_feed=ThreatFeedSource.NVD_CVE,
                cve_id=cve_id if cve_id.startswith("CVE-") else None,
                cvss_score=float(cvss_val) if cvss_val is not None else None,
                is_known_exploited=False,
                published_at=str(pub_date),
                reference_urls=refs[:5],  # Top 5 references
                raw_hash=raw_h,
            )
        )

    return advisories
