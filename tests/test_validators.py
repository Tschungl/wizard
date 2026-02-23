# tests/test_validators.py
import pytest
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from validators import (
    validate_ip, validate_prefix, validate_gateway_in_subnet,
    validate_dns, parse_ip_prefix
)

def test_valid_ip():
    ok, msg = validate_ip("192.168.1.100")
    assert ok and msg == ""

def test_invalid_ip_format():
    ok, msg = validate_ip("999.1.1.1")
    assert not ok

def test_ip_must_not_be_network_address():
    ok, msg = validate_ip("192.168.1.0", prefix_len=24)
    assert not ok
    assert "network address" in msg.lower()

def test_ip_must_not_be_broadcast():
    ok, msg = validate_ip("192.168.1.255", prefix_len=24)
    assert not ok
    assert "broadcast" in msg.lower()

def test_valid_prefix():
    ok, _ = validate_prefix(24)
    assert ok

def test_invalid_prefix_zero():
    ok, _ = validate_prefix(0)
    assert not ok

def test_invalid_prefix_too_large():
    ok, _ = validate_prefix(33)
    assert not ok

def test_gateway_in_subnet():
    ok, _ = validate_gateway_in_subnet("192.168.1.1", "192.168.1.100", 24)
    assert ok

def test_gateway_not_in_subnet():
    ok, _ = validate_gateway_in_subnet("10.0.0.1", "192.168.1.100", 24)
    assert not ok

def test_valid_dns():
    ok, _ = validate_dns("8.8.8.8")
    assert ok

def test_invalid_dns():
    ok, _ = validate_dns("not-an-ip")
    assert not ok

def test_parse_ip_prefix():
    addr, prefix = parse_ip_prefix("192.168.1.0/24")
    assert addr == "192.168.1.0"
    assert prefix == 24
