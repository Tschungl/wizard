# tests/test_interfaces.py
import pytest
from unittest.mock import patch, MagicMock
from network.interfaces import InterfaceInfo, list_interfaces, get_interface_info

def test_interface_info_fields():
    iface = InterfaceInfo(
        name="eth0", operstate="up", link_speed_mbps=1000,
        port_type="RJ45", mac="aa:bb:cc:dd:ee:ff", ip_addresses=[]
    )
    assert iface.name == "eth0"
    assert iface.speed_label == "1 Gbit"

def test_speed_label_10g():
    iface = InterfaceInfo(
        name="eth1", operstate="up", link_speed_mbps=10000,
        port_type="SFP+", mac="", ip_addresses=[]
    )
    assert iface.speed_label == "10 Gbit"

def test_speed_label_unknown():
    iface = InterfaceInfo(
        name="eth2", operstate="down", link_speed_mbps=None,
        port_type="Unknown", mac="", ip_addresses=[]
    )
    assert iface.speed_label == "Unknown"

def test_speed_label_mbit():
    iface = InterfaceInfo(
        name="eth3", operstate="up", link_speed_mbps=100,
        port_type="RJ45", mac="", ip_addresses=[]
    )
    assert iface.speed_label == "100 Mbit"

def test_display_str_contains_key_fields():
    iface = InterfaceInfo(
        name="eth2", operstate="up", link_speed_mbps=10000,
        port_type="SFP+", mac="aa:bb:cc:dd:ee:ff", ip_addresses=["10.0.0.1/24"]
    )
    s = iface.display_str()
    assert "eth2" in s
    assert "SFP+" in s
    assert "10 Gbit" in s
    assert "UP" in s.upper()
    assert "aa:bb:cc:dd:ee:ff" in s
    assert "10.0.0.1/24" in s

def test_list_interfaces_excludes_loopback():
    """list_interfaces with exclude_lo=True should not return 'lo'."""
    with patch("network.interfaces.os.listdir", return_value=["lo", "eth0", "eth1"]):
        with patch("network.interfaces.get_interface_info") as mock_get:
            mock_get.side_effect = lambda name: InterfaceInfo(
                name=name, operstate="up", link_speed_mbps=1000,
                port_type="RJ45", mac="", ip_addresses=[]
            )
            result = list_interfaces(exclude_lo=True)
    names = [i.name for i in result]
    assert "lo" not in names
    assert "eth0" in names
    assert "eth1" in names
