# tests/test_checks.py
import pytest
import asyncio
from unittest.mock import AsyncMock, patch, MagicMock
from network.checks import CheckResult, check_tcp, check_icmp, build_check_matrix, run_all_checks

def test_check_result_pass_icon():
    r = CheckResult(label="Test", target="1.2.3.4", port=443, passed=True)
    assert r.status_icon == "✓"
    assert r.passed is True

def test_check_result_fail_icon():
    r = CheckResult(label="Test", target="1.2.3.4", port=443, passed=False, error="timeout")
    assert r.status_icon == "✗"
    assert r.error == "timeout"

def test_check_result_str_pass():
    r = CheckResult(label="MyTest", target="1.2.3.4", port=443, passed=True)
    s = str(r)
    assert "MyTest" in s
    assert "1.2.3.4" in s
    assert "PASS" in s

def test_check_result_str_fail():
    r = CheckResult(label="MyTest", target="1.2.3.4", port=443, passed=False, error="timeout")
    s = str(r)
    assert "FAIL" in s
    assert "timeout" in s

async def test_check_tcp_success():
    mock_reader = AsyncMock()
    mock_writer = AsyncMock()
    mock_writer.wait_closed = AsyncMock()
    with patch("asyncio.open_connection", return_value=(mock_reader, mock_writer)):
        result = await check_tcp("1.2.3.4", 443, label="Test", timeout=2)
    assert result.passed
    assert result.error == ""

async def test_check_tcp_timeout():
    async def slow_connect(*a, **kw):
        await asyncio.sleep(100)
    with patch("asyncio.open_connection", side_effect=slow_connect):
        result = await check_tcp("1.2.3.4", 443, label="Test", timeout=0.01)
    assert not result.passed
    assert "timeout" in result.error.lower()

async def test_check_tcp_connection_refused():
    with patch("asyncio.open_connection", side_effect=ConnectionRefusedError):
        result = await check_tcp("1.2.3.4", 443, label="Test", timeout=2)
    assert not result.passed
    assert "refused" in result.error.lower()

def test_build_check_matrix_includes_cloud_ip():
    checks = build_check_matrix(cloud_ip="10.0.0.5")
    labels = [c["label"] for c in checks]
    assert any("Cloud Server" in l for l in labels)
    # Cloud check must be TCP 443
    cloud = next(c for c in checks if "Cloud Server" in c["label"])
    assert cloud["port"] == 443
    assert cloud["type"] == "tcp"

def test_build_check_matrix_skips_cloud_ip_when_none():
    checks = build_check_matrix(cloud_ip=None)
    labels = [c["label"] for c in checks]
    assert not any("Cloud Server" in l for l in labels)

def test_build_check_matrix_includes_required_targets():
    checks = build_check_matrix(cloud_ip=None)
    hosts = [c["host"] for c in checks]
    # Site reliability
    assert "hooks.slack.com" in hosts
    assert "storage.googleapis.com" in hosts
    # System updates
    assert "archive.ubuntu.com" in hosts
    assert "security.ubuntu.com" in hosts
    # Cloud microservice
    assert "ccs.asimily.com" in hosts
    assert "34.127.88.211" in hosts

async def test_run_all_checks_calls_progress():
    checks = [{"label": "T", "host": "1.1.1.1", "port": 80, "type": "tcp"}]
    calls = []
    async def fake_progress(done, total):
        calls.append((done, total))
    with patch("network.checks.check_tcp", new_callable=AsyncMock) as mock_tcp:
        mock_tcp.return_value = CheckResult(label="T", target="1.1.1.1", port=80, passed=True)
        results = await run_all_checks(checks, timeout=2, progress_callback=fake_progress)
    assert len(results) == 1
    assert len(calls) == 1
    assert calls[0] == (1, 1)

REMOVED_SOPHOS = [
    "d1.sophosupd.com",
    "d1.sophosxl.net",
    "d1.sophosupd.net",
    "mcs.sophos.com",
]

def test_removed_sophos_hosts_not_in_matrix():
    matrix = build_check_matrix(cloud_ip=None)
    hosts_in_matrix = {c["host"] for c in matrix}
    for host in REMOVED_SOPHOS:
        assert host not in hosts_in_matrix, (
            f"{host} must be removed from the check matrix"
        )

def test_globalsign_hosts_still_present():
    matrix = build_check_matrix(cloud_ip=None)
    hosts = {c["host"] for c in matrix}
    assert "ocsp2.globalsign.com" in hosts
    assert "crl.globalsign.com" in hosts
