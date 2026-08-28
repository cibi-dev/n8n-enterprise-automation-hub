"""Unit tests for SARIF and CycloneDX parsers in n8n-devsecops-audit-bridge."""

import json
import pytest

from bridge.models import SeverityLevel
from bridge.parser import parse_cyclonedx_sbom, parse_sarif_report


def test_parse_sarif_report_valid_bandit_format():
    sarif_doc = {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Bandit",
                        "rules": [
                            {
                                "id": "B101",
                                "name": "assert_used",
                                "properties": {"tags": ["CWE-703"]},
                            }
                        ],
                    }
                },
                "results": [
                    {
                        "ruleId": "B101",
                        "level": "warning",
                        "message": {"text": "Use of assert detected"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "src/app.py"},
                                    "region": {"startLine": 25},
                                }
                            }
                        ],
                    }
                ],
            }
        ],
    }

    findings = parse_sarif_report(sarif_doc)
    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "B101"
    assert f.severity == SeverityLevel.MEDIUM
    assert f.file_path == "src/app.py"
    assert f.start_line == 25
    assert f.cwe_ids == [703]
    assert f.scanner_name == "Bandit"


def test_parse_sarif_report_from_json_string():
    sarif_str = json.dumps({
        "runs": [
            {
                "tool": {"driver": {"name": "CodeQL"}},
                "results": [
                    {
                        "ruleId": "py/sql-injection",
                        "level": "error",
                        "message": {"text": "SQL Injection potential"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "db.py"},
                                    "region": {"startLine": 110},
                                }
                            }
                        ],
                    }
                ],
            }
        ]
    })
    findings = parse_sarif_report(sarif_str)
    assert len(findings) == 1
    assert findings[0].severity == SeverityLevel.HIGH
    assert findings[0].file_path == "db.py"


def test_parse_sarif_report_invalid_json():
    with pytest.raises(ValueError) as exc:
        parse_sarif_report("{bad_json")
    assert "Invalid SARIF JSON syntax" in str(exc.value)

    with pytest.raises(ValueError):
        parse_sarif_report([1, 2, 3])  # type: ignore


def test_parse_cyclonedx_sbom_valid():
    sbom_doc = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "components": [
            {
                "name": "pydantic",
                "version": "2.8.2",
                "type": "library",
                "purl": "pkg:pypi/pydantic@2.8.2",
                "licenses": [{"license": {"id": "MIT"}}],
            },
            {
                "name": "httpx",
                "version": "0.27.0",
                "type": "library",
                "licenses": [{"expression": "BSD-3-Clause"}],
            },
        ],
    }

    components = parse_cyclonedx_sbom(sbom_doc)
    assert len(components) == 2
    assert components[0].name == "pydantic"
    assert components[0].licenses == ["MIT"]
    assert components[1].name == "httpx"
    assert components[1].licenses == ["BSD-3-Clause"]


def test_parse_cyclonedx_sbom_empty_or_invalid():
    assert parse_cyclonedx_sbom({}) == []
    assert parse_cyclonedx_sbom({"components": []}) == []

    with pytest.raises(ValueError):
        parse_cyclonedx_sbom("not a valid json")

    with pytest.raises(ValueError):
        parse_cyclonedx_sbom("12345")
