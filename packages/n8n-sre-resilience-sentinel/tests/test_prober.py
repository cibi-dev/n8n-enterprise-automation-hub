"""Unit tests for synthetic prober in n8n-sre-resilience-sentinel."""

import io
import urllib.error
import urllib.request
import pytest

from sentinel.models import ProbeTarget
from sentinel.prober import execute_synthetic_probe


def test_execute_synthetic_probe_healthy(monkeypatch):
    class MockResponse:
        def __init__(self):
            pass
        def getcode(self):
            return 200
        def __enter__(self):
            return self
        def __exit__(self, *args):
            pass

    monkeypatch.setattr(urllib.request, "urlopen", lambda req, timeout: MockResponse())

    target = ProbeTarget(service_name="api", url="http://example.com/healthz")
    sample = execute_synthetic_probe(target)
    assert sample.is_healthy is True
    assert sample.status_code == 200
    assert sample.error_message is None


def test_execute_synthetic_probe_wrong_status_code(monkeypatch):
    class MockResponse:
        def getcode(self):
            return 503
        def __enter__(self):
            return self
        def __exit__(self, *args):
            pass

    monkeypatch.setattr(urllib.request, "urlopen", lambda req, timeout: MockResponse())

    target = ProbeTarget(service_name="api", url="http://example.com/healthz", expected_status=200)
    sample = execute_synthetic_probe(target)
    assert sample.is_healthy is False
    assert sample.status_code == 503
    assert "Expected status 200" in sample.error_message


def test_execute_synthetic_probe_http_error(monkeypatch):
    def mock_urlopen(req, timeout):
        raise urllib.error.HTTPError(
            url="http://example.com", code=500, msg="Server Error", hdrs=None, fp=io.BytesIO(b"error")  # type: ignore
        )

    monkeypatch.setattr(urllib.request, "urlopen", mock_urlopen)

    target = ProbeTarget(service_name="api", url="http://example.com/healthz")
    sample = execute_synthetic_probe(target)
    assert sample.is_healthy is False
    assert sample.status_code == 500
    assert "HTTPError 500" in sample.error_message


def test_execute_synthetic_probe_connection_error(monkeypatch):
    def mock_urlopen(req, timeout):
        raise urllib.error.URLError("Connection refused")

    monkeypatch.setattr(urllib.request, "urlopen", mock_urlopen)

    target = ProbeTarget(service_name="api", url="http://example.com/healthz")
    sample = execute_synthetic_probe(target)
    assert sample.is_healthy is False
    assert sample.status_code is None
    assert "Connection failure" in sample.error_message


def test_execute_synthetic_probe_latency_breach(monkeypatch):
    import time

    class MockSlowResponse:
        def getcode(self):
            return 200
        def __enter__(self):
            time.sleep(0.08)  # Simulate 80ms
            return self
        def __exit__(self, *args):
            pass

    monkeypatch.setattr(urllib.request, "urlopen", lambda req, timeout: MockSlowResponse())

    target = ProbeTarget(service_name="api", url="http://example.com", timeout_ms=50.0)  # Max 50ms
    sample = execute_synthetic_probe(target)
    assert sample.is_healthy is False
    assert sample.latency_ms >= 50.0


def test_prober_invalid_scheme_ftp():
    target = ProbeTarget(service_name="api", url="ftp://example.com/file")
    sample = execute_synthetic_probe(target)
    assert sample.is_healthy is False
    assert "Invalid URL scheme" in sample.error_message


def test_prober_custom_status_code_match(monkeypatch):
    class MockResponse204:
        def getcode(self):
            return 204
        def __enter__(self):
            return self
        def __exit__(self, *args):
            pass

    monkeypatch.setattr(urllib.request, "urlopen", lambda req, timeout: MockResponse204())
    target = ProbeTarget(service_name="api", url="https://example.com/no-content", expected_status=204)
    sample = execute_synthetic_probe(target)
    assert sample.is_healthy is True
    assert sample.status_code == 204


