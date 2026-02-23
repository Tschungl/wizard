# tests/test_netplan.py
import pytest
import network.netplan as netplan_mod
from pathlib import Path
from network.netplan import NetplanManager
from unittest.mock import MagicMock

@pytest.fixture
def tmp_netplan(tmp_path):
    """Return a NetplanManager pointed at a temp directory."""
    return NetplanManager(netplan_dir=str(tmp_path))

def test_backup_creates_bak_file(tmp_netplan, tmp_path):
    cfg = tmp_path / "50-cloud-init.yaml"
    cfg.write_text("network: {version: 2}\n")
    tmp_netplan.backup()
    backups = list(tmp_path.glob("*.bak"))
    assert len(backups) == 1
    assert backups[0].name == "50-cloud-init.yaml.bak"

def test_backup_does_not_duplicate_wizard_file(tmp_netplan, tmp_path):
    """The wizard's own file must not be backed up."""
    wizard = tmp_path / "60-asimily-wizard.yaml"
    wizard.write_text("network: {version: 2}\n")
    tmp_netplan.backup()
    backups = list(tmp_path.glob("*.bak"))
    assert len(backups) == 0

def test_write_static_config(tmp_netplan, tmp_path):
    tmp_netplan.write_static(
        iface="eth2",
        ip_cidr="192.168.10.5/24",
        gateway="192.168.10.1",
        dns=["8.8.8.8"],
        ntp=["pool.ntp.org"],
    )
    files = list(tmp_path.glob("*.yaml"))
    assert len(files) == 1
    content = files[0].read_text()
    assert "192.168.10.5/24" in content
    assert "eth2" in content
    assert "8.8.8.8" in content
    assert "10.1" in content  # gateway

def test_write_dhcp_config(tmp_netplan, tmp_path):
    tmp_netplan.write_dhcp(iface="eth0", dns=[], ntp=[])
    content = list(tmp_path.glob("*.yaml"))[0].read_text()
    assert "dhcp4: true" in content
    assert "eth0" in content

def test_restore_removes_wizard_file(tmp_netplan, tmp_path):
    wizard_file = tmp_path / "60-asimily-wizard.yaml"
    wizard_file.write_text("dummy: true\n")
    bak = tmp_path / "50-cloud-init.yaml.bak"
    bak.write_text("network: {version: 2}\n")
    tmp_netplan.restore()
    assert not wizard_file.exists()
    assert (tmp_path / "50-cloud-init.yaml").exists()
    assert not (tmp_path / "50-cloud-init.yaml.bak").exists()

def test_restore_is_idempotent_without_wizard_file(tmp_netplan, tmp_path):
    """restore() must not crash if wizard file does not exist."""
    tmp_netplan.restore()  # no exception expected

def test_written_yaml_has_correct_permissions(tmp_netplan, tmp_path):
    tmp_netplan.write_static(
        iface="eth0", ip_cidr="10.0.0.1/24", gateway="10.0.0.254",
        dns=[], ntp=[]
    )
    yaml_file = list(tmp_path.glob("*.yaml"))[0]
    import stat
    mode = stat.S_IMODE(yaml_file.stat().st_mode)
    assert mode == 0o600


def test_apply_ntp_writes_config(tmp_netplan, tmp_path, monkeypatch):
    """apply_ntp() writes a systemd-timesyncd drop-in file."""
    ntp_dir = tmp_path / "timesyncd.conf.d"
    monkeypatch.setattr(netplan_mod, "NTP_CONF_DIR", ntp_dir)
    tmp_netplan.apply_ntp(["pool.ntp.org", "time.google.com"])
    conf = ntp_dir / "wizard.conf"
    assert conf.exists()
    content = conf.read_text()
    assert "[Time]" in content
    assert "pool.ntp.org" in content
    assert "time.google.com" in content


def test_apply_ntp_skips_empty_list(tmp_netplan, tmp_path, monkeypatch):
    """apply_ntp() with empty list must not create any file."""
    ntp_dir = tmp_path / "timesyncd.conf.d"
    monkeypatch.setattr(netplan_mod, "NTP_CONF_DIR", ntp_dir)
    tmp_netplan.apply_ntp([])
    assert not ntp_dir.exists()


def test_apply_proxy_writes_environment(tmp_netplan, tmp_path, monkeypatch):
    """apply_proxy() writes proxy entries to /etc/environment."""
    env_file = tmp_path / "environment"
    monkeypatch.setattr(netplan_mod, "ENV_FILE", env_file)
    tmp_netplan.apply_proxy("proxy.example.com", 3128)
    content = env_file.read_text()
    assert "http_proxy=http://proxy.example.com:3128/" in content
    assert "https_proxy=http://proxy.example.com:3128/" in content
    assert "no_proxy=localhost,127.0.0.1" in content


def test_apply_proxy_with_credentials(tmp_netplan, tmp_path, monkeypatch):
    """apply_proxy() includes credentials in the URL when provided."""
    env_file = tmp_path / "environment"
    monkeypatch.setattr(netplan_mod, "ENV_FILE", env_file)
    tmp_netplan.apply_proxy("proxy.example.com", 3128, "alice", "s3cr3t")
    content = env_file.read_text()
    assert "http_proxy=http://alice:s3cr3t@proxy.example.com:3128/" in content


def test_apply_proxy_preserves_existing_lines(tmp_netplan, tmp_path, monkeypatch):
    """apply_proxy() keeps unrelated lines already in /etc/environment."""
    env_file = tmp_path / "environment"
    env_file.write_text("LANG=en_US.UTF-8\nTZ=UTC\n")
    monkeypatch.setattr(netplan_mod, "ENV_FILE", env_file)
    tmp_netplan.apply_proxy("proxy.example.com", 3128)
    content = env_file.read_text()
    assert "LANG=en_US.UTF-8" in content
    assert "TZ=UTC" in content
    assert "http_proxy=" in content


def test_write_mirror_ports_creates_yaml(tmp_netplan, tmp_path):
    """write_mirror_ports() creates YAML with dhcp4=false and promiscuous for each iface."""
    import yaml
    tmp_netplan.write_mirror_ports(["eth1", "eth2"])
    mirror_file = tmp_path / "61-asimily-mirror.yaml"
    assert mirror_file.exists()
    data = yaml.safe_load(mirror_file.read_text())
    ethernets = data["network"]["ethernets"]
    assert "eth1" in ethernets
    assert "eth2" in ethernets
    assert ethernets["eth1"]["dhcp4"] is False
    assert ethernets["eth1"]["promiscuous"] is True


def test_write_mirror_ports_empty_list_no_file(tmp_netplan, tmp_path):
    """write_mirror_ports() with empty list must not write any file."""
    tmp_netplan.write_mirror_ports([])
    mirror_file = tmp_path / "61-asimily-mirror.yaml"
    assert not mirror_file.exists()


def test_configure_mirror_promisc_calls_ip_link(tmp_netplan, monkeypatch):
    """configure_mirror_promisc() issues ip link promisc + up for each interface."""
    import network.netplan as nm_mod
    calls = []
    def fake_run(cmd, **kw):
        calls.append(cmd)
        return MagicMock(returncode=0)
    monkeypatch.setattr(nm_mod.subprocess, "run", fake_run)
    tmp_netplan.configure_mirror_promisc(["eth1", "eth2"])
    flat = [" ".join(c) for c in calls]
    assert any("eth1" in c and "promisc" in c for c in flat)
    assert any("eth1" in c and "up" in c for c in flat)
    assert any("eth2" in c and "promisc" in c for c in flat)
