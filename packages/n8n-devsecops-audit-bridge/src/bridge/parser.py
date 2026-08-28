"""SARIF (Static Analysis Results Interchange Format) and CycloneDX SBOM Parsers.

Converts raw scanner outputs into normalized, immutable domain models.
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional, Union

from bridge.models import AuditFinding, SBOMComponent, SeverityLevel


def parse_sarif_report(sarif_data: Union[str, Dict[str, Any]]) -> List[AuditFinding]:
    """Parse a SARIF v2.1.0 JSON payload or string into normalized AuditFindings.

    Args:
        sarif_data: Raw SARIF dictionary or JSON string.

    Returns:
        List of parsed AuditFinding models.
    """
    if isinstance(sarif_data, str):
        try:
            sarif_dict = json.loads(sarif_data)
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid SARIF JSON syntax: {e}") from e
    else:
        sarif_dict = sarif_data

    if not isinstance(sarif_dict, dict):
        raise ValueError("SARIF document must be a JSON object")

    runs = sarif_dict.get("runs", [])
    if not isinstance(runs, list):
        return []

    findings: List[AuditFinding] = []

    for run in runs:
        if not isinstance(run, dict):
            continue

        tool_info = run.get("tool", {}).get("driver", {})
        scanner_name = tool_info.get("name", "sast-scanner")

        # Map rules to metadata (CWEs, default level)
        rules_dict: Dict[str, Dict[str, Any]] = {}
        for r in tool_info.get("rules", []):
            if isinstance(r, dict) and "id" in r:
                rules_dict[r["id"]] = r

        results = run.get("results", [])
        for res in results:
            if not isinstance(res, dict):
                continue

            rule_id = res.get("ruleId") or "UNKNOWN_RULE"
            msg_obj = res.get("message", {})
            message = msg_obj.get("text", "No finding message provided") if isinstance(msg_obj, dict) else str(msg_obj)

            # Determine severity level
            level_str = (res.get("level") or "").lower()
            if level_str in ("error", "critical"):
                severity = SeverityLevel.HIGH
            elif level_str == "warning":
                severity = SeverityLevel.MEDIUM
            elif level_str in ("note", "info"):
                severity = SeverityLevel.LOW
            else:
                severity = SeverityLevel.MEDIUM

            # File path and line number
            file_path = "unknown"
            start_line = 1
            locations = res.get("locations", [])
            if locations and isinstance(locations, list) and isinstance(locations[0], dict):
                phys = locations[0].get("physicalLocation", {})
                art_loc = phys.get("artifactLocation", {})
                if "uri" in art_loc:
                    file_path = art_loc["uri"]
                region = phys.get("region", {})
                start_line = max(1, region.get("startLine", 1))

            # Extract CWEs from rule properties or tags
            cwe_ids: List[int] = []
            rule_meta = rules_dict.get(rule_id, {})
            help_tags = rule_meta.get("properties", {}).get("tags", [])
            if isinstance(help_tags, list):
                for tag in help_tags:
                    matches = re.findall(r"CWE-(\d+)", str(tag), re.IGNORECASE)
                    for m in matches:
                        cwe_ids.append(int(m))

            findings.append(
                AuditFinding(
                    rule_id=str(rule_id),
                    message=str(message),
                    severity=severity,
                    file_path=str(file_path),
                    start_line=start_line,
                    cwe_ids=sorted(list(set(cwe_ids))),
                    scanner_name=str(scanner_name),
                )
            )

    return findings


def parse_cyclonedx_sbom(sbom_data: Union[str, Dict[str, Any]]) -> List[SBOMComponent]:
    """Parse a CycloneDX SBOM JSON payload into normalized SBOMComponents.

    Args:
        sbom_data: Raw CycloneDX dictionary or JSON string.

    Returns:
        List of parsed SBOMComponent models.
    """
    if isinstance(sbom_data, str):
        try:
            sbom_dict = json.loads(sbom_data)
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid CycloneDX JSON syntax: {e}") from e
    else:
        sbom_dict = sbom_data

    if not isinstance(sbom_dict, dict):
        raise ValueError("CycloneDX document must be a JSON object")

    raw_components = sbom_dict.get("components", [])
    if not isinstance(raw_components, list):
        return []

    components: List[SBOMComponent] = []

    for comp in raw_components:
        if not isinstance(comp, dict):
            continue

        name = comp.get("name")
        version = comp.get("version", "0.0.0")
        if not name:
            continue

        purl = comp.get("purl")
        c_type = comp.get("type", "library")

        # Extract declared licenses
        licenses: List[str] = []
        raw_licenses = comp.get("licenses", [])
        if isinstance(raw_licenses, list):
            for lic in raw_licenses:
                if isinstance(lic, dict):
                    if "license" in lic and isinstance(lic["license"], dict):
                        lic_id = lic["license"].get("id") or lic["license"].get("name")
                        if lic_id:
                            licenses.append(str(lic_id))
                    elif "expression" in lic:
                        licenses.append(str(lic["expression"]))

        components.append(
            SBOMComponent(
                name=str(name),
                version=str(version),
                purl=str(purl) if purl else None,
                component_type=str(c_type),
                licenses=licenses,
            )
        )

    return components
