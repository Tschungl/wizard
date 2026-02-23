# Asimily First Time Wizard - Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build a TUI-based (Textual) setup wizard for an Ubuntu edge appliance that guides an operator through network configuration, connectivity validation, and service initialization.

**Architecture:** Screen-based wizard using the `textual` library (async-native), with each wizard step implemented as a separate `Screen` subclass. A central `WizardState` dataclass carries configuration across screens. Network operations (Netplan apply, pre-flight checks) run as `asyncio` tasks so the UI never blocks.

**Tech Stack:** Python 3.11+, `textual` (TUI), `asyncio` (concurrency), `netplan` YAML via `/etc/netplan/`, `ipaddress` (stdlib validation), `ethtool`/`/sys/class/net/` (hardware info), `logging` (file logging to `/var/log/asimily_wizard.log`), `pytest` + `pytest-asyncio` (testing).

---

## Project File Tree

```
/opt/asimily/wizard/
├── main.py                  # Entry point (requires root, launches app)
├── app.py                   # AsimilyWizard(App) – screen routing, state
├── state.py                 # WizardState dataclass
├── logger.py                # Logging setup → /var/log/asimily_wizard.log
├── network/
│   ├── __init__.py
│   ├── interfaces.py        # Detect interfaces + hardware info
│   ├── netplan.py           # Read/write/apply Netplan YAML + backup/restore
│   └── checks.py            # Async connectivity checks (ping, TCP)
├── validators.py            # IP/mask/gateway/DNS validation (ipaddress)
├── screens/
│   ├── __init__.py
│   ├── s01_welcome.py       # Step 1 – Interface overview
│   ├── s02_network_config.py # Step 2 – Management port config form
│   ├── s03_network_apply.py  # Step 3 – Apply + 60 s countdown
│   ├── s04_cloud_ip.py      # Step 4 – Cloud server IP (skippable)
│   ├── s05_preflight.py     # Step 5 – Async pre-flight checks + 30 s timer
│   ├── s06_mirror_ports.py  # Step 6 – Mirror port multiselect
│   └── s07_finish.py        # Step 7 – Trigger install.sh + exit
└── tests/
    ├── conftest.py
    ├── test_validators.py
    ├── test_interfaces.py
    ├── test_netplan.py
    └── test_checks.py
```

---

### Task 1: Project scaffold, dependencies, logging

**Files:**
- Create: `/opt/asimily/wizard/logger.py`
- Create: `/opt/asimily/wizard/state.py`
- Create: `/opt/asimily/wizard/main.py`
- Create: `/opt/asimily/wizard/app.py` (stub)
- Create: `/opt/asimily/wizard/tests/conftest.py`
- Create: `/opt/asimily/wizard/requirements.txt`

**Step 1: Install dependencies**

```bash
pip install textual pytest pytest-asyncio
```

**Step 2: Create requirements.txt**

```
textual>=0.60.0
pytest>=8.0
pytest-asyncio>=0.23
```

**Step 3: Write logger.py**

```python
# /opt/asimily/wizard/logger.py
import logging
import sys

LOG_FILE = "/var/log/asimily_wizard.log"

def setup_logger() -> logging.Logger:
    logger = logging.getLogger("asimily_wizard")
    logger.setLevel(logging.DEBUG)

    fmt = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )

    fh = logging.FileHandler(LOG_FILE)
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(fmt)

    sh = logging.StreamHandler(sys.stderr)
    sh.setLevel(logging.WARNING)
    sh.setFormatter(fmt)

    logger.addHandler(fh)
    logger.addHandler(sh)
    return logger

log = setup_logger()
```

**Step 4: Write state.py**

```python
# /opt/asimily/wizard/state.py
from dataclasses import dataclass, field
from typing import Optional

@dataclass
class WizardState:
    # Step 2
    mgmt_interface: str = ""
    use_dhcp: bool = False
    ip_address: str = ""
    prefix_len: int = 24
    gateway: str = ""
    dns_servers: list[str] = field(default_factory=list)
    ntp_servers: list[str] = field(default_factory=list)
    proxy_enabled: bool = False
    proxy_host: str = ""
    proxy_port: int = 0
    proxy_user: str = ""
    proxy_password: str = ""

    # Step 4
    cloud_ip: Optional[str] = None   # None = skipped

    # Step 6
    mirror_interfaces: list[str] = field(default_factory=list)
```

**Step 5: Write app.py stub**

```python
# /opt/asimily/wizard/app.py
from textual.app import App
from state import WizardState
from logger import log

class AsimilyWizard(App):
    """Asimily First Time Setup Wizard."""

    CSS = """
    Screen { background: $surface; }
    Label.title { text-style: bold; color: $accent; }
    """

    def __init__(self):
        super().__init__()
        self.state = WizardState()
        log.info("AsimilyWizard started")

    def on_mount(self) -> None:
        from screens.s01_welcome import WelcomeScreen
        self.push_screen(WelcomeScreen())
```

**Step 6: Write main.py**

```python
# /opt/asimily/wizard/main.py
import os, sys
from app import AsimilyWizard

def main():
    if os.geteuid() != 0:
        print("ERROR: This wizard must be run as root.", file=sys.stderr)
        sys.exit(1)
    AsimilyWizard().run()

if __name__ == "__main__":
    main()
```

**Step 7: Write tests/conftest.py**

```python
# /opt/asimily/wizard/tests/conftest.py
import pytest
from state import WizardState

@pytest.fixture
def state():
    return WizardState()
```

**Step 8: Commit**

```bash
cd /opt/asimily/wizard
git add .
git commit -m "feat: project scaffold, logging, wizard state"
```

---

### Task 2: Input validation utilities

**Files:**
- Create: `/opt/asimily/wizard/validators.py`
- Create: `/opt/asimily/wizard/tests/test_validators.py`

**Step 1: Write failing tests**

```python
# /opt/asimily/wizard/tests/test_validators.py
import pytest
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
    # 192.168.1.0/24 → network address
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
```

**Step 2: Run tests to verify they fail**

```bash
cd /opt/asimily/wizard
pytest tests/test_validators.py -v
```

Expected: `ImportError` or `ModuleNotFoundError` – validators.py does not exist yet.

**Step 3: Implement validators.py**

```python
# /opt/asimily/wizard/validators.py
import ipaddress
from typing import Tuple

def validate_ip(address: str, prefix_len: int = None) -> Tuple[bool, str]:
    try:
        ip = ipaddress.IPv4Address(address)
    except ValueError:
        return False, f"'{address}' is not a valid IPv4 address."

    if prefix_len is not None:
        try:
            network = ipaddress.IPv4Network(f"{address}/{prefix_len}", strict=True)
        except ValueError:
            # strict=True raises if host bits set – that would mean it's the network addr
            pass
        # Check network address
        net = ipaddress.IPv4Network(f"{address}/{prefix_len}", strict=False)
        if ip == net.network_address:
            return False, f"{address} is the network address of {net}."
        if ip == net.broadcast_address:
            return False, f"{address} is the broadcast address of {net}."

    return True, ""

def validate_prefix(prefix_len: int) -> Tuple[bool, str]:
    if not isinstance(prefix_len, int) or not (1 <= prefix_len <= 32):
        return False, f"Prefix length must be 1–32, got {prefix_len}."
    return True, ""

def validate_gateway_in_subnet(
    gateway: str, host_ip: str, prefix_len: int
) -> Tuple[bool, str]:
    try:
        gw = ipaddress.IPv4Address(gateway)
        net = ipaddress.IPv4Network(f"{host_ip}/{prefix_len}", strict=False)
    except ValueError as e:
        return False, str(e)

    if gw not in net:
        return False, f"Gateway {gateway} is not in subnet {net}."
    return True, ""

def validate_dns(address: str) -> Tuple[bool, str]:
    try:
        ipaddress.IPv4Address(address)
        return True, ""
    except ValueError:
        return False, f"'{address}' is not a valid DNS server IP."

def parse_ip_prefix(cidr: str) -> Tuple[str, int]:
    """Parse '192.168.1.0/24' → ('192.168.1.0', 24). Raises ValueError on bad input."""
    net = ipaddress.IPv4Network(cidr, strict=False)
    return str(net.network_address), net.prefixlen
```

**Step 4: Run tests – must pass**

```bash
cd /opt/asimily/wizard
pytest tests/test_validators.py -v
```

Expected: all PASS.

**Step 5: Commit**

```bash
git add validators.py tests/test_validators.py
git commit -m "feat: IP/subnet input validation with full test coverage"
```

---

### Task 3: Network interface detection (hardware info)

**Files:**
- Create: `/opt/asimily/wizard/network/__init__.py`
- Create: `/opt/asimily/wizard/network/interfaces.py`
- Create: `/opt/asimily/wizard/tests/test_interfaces.py`

**Step 1: Write failing tests**

```python
# /opt/asimily/wizard/tests/test_interfaces.py
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

def test_display_str():
    iface = InterfaceInfo(
        name="eth2", operstate="up", link_speed_mbps=10000,
        port_type="SFP+", mac="aa:bb:cc:dd:ee:ff", ip_addresses=["10.0.0.1/24"]
    )
    s = iface.display_str()
    assert "eth2" in s
    assert "SFP+" in s
    assert "10 Gbit" in s
    assert "UP" in s.upper()
```

**Step 2: Run tests – verify they fail**

```bash
pytest tests/test_interfaces.py -v
```

Expected: `ModuleNotFoundError`.

**Step 3: Implement network/interfaces.py**

```python
# /opt/asimily/wizard/network/interfaces.py
from __future__ import annotations
import os, subprocess, json
from dataclasses import dataclass, field
from typing import Optional
from logger import log

SYS_NET = "/sys/class/net"

@dataclass
class InterfaceInfo:
    name: str
    operstate: str          # "up" | "down" | "unknown"
    link_speed_mbps: Optional[int]  # None if not available
    port_type: str          # "RJ45" | "SFP+" | "SFP" | "Loopback" | "Unknown"
    mac: str
    ip_addresses: list[str]  # CIDR notation

    @property
    def speed_label(self) -> str:
        if self.link_speed_mbps is None:
            return "Unknown"
        gbps = self.link_speed_mbps / 1000
        if gbps >= 1:
            return f"{int(gbps)} Gbit"
        return f"{self.link_speed_mbps} Mbit"

    def display_str(self) -> str:
        state = self.operstate.upper()
        ips = ", ".join(self.ip_addresses) if self.ip_addresses else "no IP"
        return (
            f"{self.name:<12} {self.port_type:<8} {self.speed_label:<10} "
            f"{state:<6}  {self.mac}  [{ips}]"
        )


def _read_sysfs(iface: str, attr: str, default=None) -> Optional[str]:
    path = os.path.join(SYS_NET, iface, attr)
    try:
        with open(path) as f:
            return f.read().strip()
    except OSError:
        return default


def _get_port_type(iface: str) -> str:
    """Determine port type via ethtool; fall back to sysfs heuristics."""
    # Loopback
    if iface.startswith("lo"):
        return "Loopback"
    try:
        result = subprocess.run(
            ["ethtool", iface], capture_output=True, text=True, timeout=2
        )
        for line in result.stdout.splitlines():
            line_l = line.strip().lower()
            if "port:" in line_l:
                port = line_l.split("port:")[-1].strip()
                if "fibre" in port or "sfp" in port:
                    # Distinguish SFP vs SFP+
                    speed = _read_sysfs(iface, "speed")
                    if speed and int(speed) >= 10000:
                        return "SFP+"
                    return "SFP"
                if "tp" in port or "twisted" in port:
                    return "RJ45"
                if "da" in port:
                    return "DAC"
    except Exception as e:
        log.debug(f"ethtool failed for {iface}: {e}")
    return "Unknown"


def _get_ip_addresses(iface: str) -> list[str]:
    try:
        result = subprocess.run(
            ["ip", "-j", "addr", "show", iface],
            capture_output=True, text=True, timeout=2
        )
        data = json.loads(result.stdout)
        addrs = []
        for entry in data:
            for ai in entry.get("addr_info", []):
                if ai.get("family") == "inet":
                    addrs.append(f"{ai['local']}/{ai['prefixlen']}")
        return addrs
    except Exception as e:
        log.debug(f"ip addr failed for {iface}: {e}")
        return []


def get_interface_info(iface: str) -> InterfaceInfo:
    operstate = _read_sysfs(iface, "operstate", "unknown")
    mac = _read_sysfs(iface, "address", "")
    speed_str = _read_sysfs(iface, "speed")
    speed = int(speed_str) if speed_str and speed_str.isdigit() else None
    port_type = _get_port_type(iface)
    ips = _get_ip_addresses(iface)
    return InterfaceInfo(
        name=iface, operstate=operstate, link_speed_mbps=speed,
        port_type=port_type, mac=mac or "", ip_addresses=ips,
    )


def list_interfaces(exclude_lo: bool = True) -> list[InterfaceInfo]:
    """Return all interfaces from /sys/class/net, sorted by name."""
    try:
        ifaces = sorted(os.listdir(SYS_NET))
    except OSError:
        return []
    result = []
    for name in ifaces:
        if exclude_lo and name == "lo":
            continue
        result.append(get_interface_info(name))
    return result
```

**Step 4: Create network/__init__.py**

```python
# /opt/asimily/wizard/network/__init__.py
```

**Step 5: Run tests – must pass**

```bash
pytest tests/test_interfaces.py -v
```

**Step 6: Commit**

```bash
git add network/ tests/test_interfaces.py
git commit -m "feat: network interface detection with hardware info (SFP/RJ45/speed)"
```

---

### Task 4: Netplan manager (read / backup / write / apply)

**Files:**
- Create: `/opt/asimily/wizard/network/netplan.py`
- Create: `/opt/asimily/wizard/tests/test_netplan.py`

**Step 1: Write failing tests**

```python
# /opt/asimily/wizard/tests/test_netplan.py
import pytest, textwrap, tempfile, os
from pathlib import Path
from unittest.mock import patch
from network.netplan import NetplanManager

@pytest.fixture
def tmp_netplan(tmp_path):
    """Return a NetplanManager pointed at a temp directory."""
    return NetplanManager(netplan_dir=str(tmp_path))

def test_backup_creates_file(tmp_netplan, tmp_path):
    # Create a fake existing config
    cfg = tmp_path / "50-cloud-init.yaml"
    cfg.write_text("network: {version: 2}\n")
    tmp_netplan.backup()
    backups = list(tmp_path.glob("*.bak"))
    assert len(backups) == 1

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

def test_write_dhcp_config(tmp_netplan, tmp_path):
    tmp_netplan.write_dhcp(iface="eth0", dns=[], ntp=[])
    content = list(tmp_path.glob("*.yaml"))[0].read_text()
    assert "dhcp4: true" in content

def test_restore_removes_wizard_file(tmp_netplan, tmp_path):
    # Write wizard file
    wizard_file = tmp_path / "60-asimily-wizard.yaml"
    wizard_file.write_text("dummy: true\n")
    # Write a backup
    bak = tmp_path / "50-cloud-init.yaml.bak"
    bak.write_text("original: true\n")
    tmp_netplan.restore()
    assert not wizard_file.exists()
    # Backup renamed back
    assert (tmp_path / "50-cloud-init.yaml").exists()
```

**Step 2: Run – verify they fail**

```bash
pytest tests/test_netplan.py -v
```

**Step 3: Implement network/netplan.py**

```python
# /opt/asimily/wizard/network/netplan.py
from __future__ import annotations
import os, shutil, subprocess, yaml
from datetime import datetime
from pathlib import Path
from typing import Optional
from logger import log

WIZARD_FILENAME = "60-asimily-wizard.yaml"

class NetplanManager:
    def __init__(self, netplan_dir: str = "/etc/netplan"):
        self.netplan_dir = Path(netplan_dir)

    # ── Backup / Restore ──────────────────────────────────────────────

    def backup(self) -> None:
        """Rename all existing .yaml files to .yaml.bak (overwriting old backups)."""
        for f in self.netplan_dir.glob("*.yaml"):
            if f.name == WIZARD_FILENAME:
                continue
            bak = f.with_suffix(".yaml.bak")
            shutil.copy2(f, bak)
            log.info(f"Backed up {f} → {bak}")

    def restore(self) -> None:
        """Remove wizard YAML, restore .bak files."""
        wizard = self.netplan_dir / WIZARD_FILENAME
        if wizard.exists():
            wizard.unlink()
            log.info(f"Removed wizard netplan config {wizard}")
        for bak in self.netplan_dir.glob("*.bak"):
            original = bak.with_suffix("")   # strips .bak → .yaml
            shutil.copy2(bak, original)
            log.info(f"Restored {bak} → {original}")

    # ── Write ─────────────────────────────────────────────────────────

    def _write_yaml(self, config: dict) -> None:
        path = self.netplan_dir / WIZARD_FILENAME
        with open(path, "w") as f:
            yaml.dump(config, f, default_flow_style=False)
        os.chmod(path, 0o600)
        log.info(f"Wrote netplan config to {path}")

    def write_static(
        self,
        iface: str,
        ip_cidr: str,
        gateway: str,
        dns: list[str],
        ntp: list[str],
        proxy: Optional[dict] = None,
    ) -> None:
        config = {
            "network": {
                "version": 2,
                "renderer": "networkd",
                "ethernets": {
                    iface: {
                        "addresses": [ip_cidr],
                        "routes": [{"to": "default", "via": gateway}],
                        "nameservers": {"addresses": dns} if dns else {},
                    }
                },
            }
        }
        self._write_yaml(config)

    def write_dhcp(
        self,
        iface: str,
        dns: list[str],
        ntp: list[str],
        proxy: Optional[dict] = None,
    ) -> None:
        config = {
            "network": {
                "version": 2,
                "renderer": "networkd",
                "ethernets": {
                    iface: {
                        "dhcp4": True,
                        "nameservers": {"addresses": dns} if dns else {},
                    }
                },
            }
        }
        self._write_yaml(config)

    # ── Apply (wraps `netplan try`) ───────────────────────────────────

    def apply_try(self, timeout: int = 60) -> subprocess.Popen:
        """
        Start `netplan try --timeout <N>` and return the Popen object.
        The caller is responsible for confirming (writing \\n to stdin)
        or letting it time out for automatic rollback.
        """
        log.info(f"Running: netplan try --timeout {timeout}")
        proc = subprocess.Popen(
            ["netplan", "try", f"--timeout={timeout}"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        return proc

    def confirm_apply(self, proc: subprocess.Popen) -> None:
        """Confirm the pending netplan try by writing Enter to stdin."""
        try:
            proc.stdin.write("\n")
            proc.stdin.flush()
            log.info("netplan try confirmed by user")
        except OSError as e:
            log.error(f"Failed to confirm netplan try: {e}")
```

**Step 4: Run tests – must pass**

```bash
pytest tests/test_netplan.py -v
```

**Step 5: Commit**

```bash
git add network/netplan.py tests/test_netplan.py
git commit -m "feat: netplan manager with backup/restore/static/DHCP/try support"
```

---

### Task 5: Async connectivity checks

**Files:**
- Create: `/opt/asimily/wizard/network/checks.py`
- Create: `/opt/asimily/wizard/tests/test_checks.py`

**Step 1: Write failing tests**

```python
# /opt/asimily/wizard/tests/test_checks.py
import pytest, asyncio
from unittest.mock import AsyncMock, patch
from network.checks import CheckResult, check_tcp, run_all_checks, build_check_matrix

def test_check_result_fields():
    r = CheckResult(label="Test", target="1.2.3.4", port=443, passed=True)
    assert r.label == "Test"
    assert r.status_icon == "✓"

def test_check_result_fail_icon():
    r = CheckResult(label="Test", target="1.2.3.4", port=443, passed=False, error="timeout")
    assert r.status_icon == "✗"

@pytest.mark.asyncio
async def test_check_tcp_success():
    with patch("asyncio.open_connection", new_callable=AsyncMock) as mock_conn:
        mock_writer = AsyncMock()
        mock_conn.return_value = (AsyncMock(), mock_writer)
        result = await check_tcp("1.2.3.4", 443, label="Test", timeout=2)
    assert result.passed

@pytest.mark.asyncio
async def test_check_tcp_failure():
    async def fail(*a, **kw):
        raise ConnectionRefusedError
    with patch("asyncio.open_connection", side_effect=fail):
        result = await check_tcp("1.2.3.4", 443, label="Test", timeout=2)
    assert not result.passed
    assert "refused" in result.error.lower()

def test_build_check_matrix_includes_cloud_ip():
    checks = build_check_matrix(cloud_ip="10.0.0.5")
    labels = [c["label"] for c in checks]
    assert any("Cloud Server" in l for l in labels)

def test_build_check_matrix_skips_cloud_ip_when_none():
    checks = build_check_matrix(cloud_ip=None)
    labels = [c["label"] for c in checks]
    assert not any("Cloud Server" in l for l in labels)
```

**Step 2: Run – verify they fail**

```bash
pytest tests/test_checks.py -v
```

**Step 3: Implement network/checks.py**

```python
# /opt/asimily/wizard/network/checks.py
from __future__ import annotations
import asyncio, socket
from dataclasses import dataclass, field
from typing import Optional
from logger import log

@dataclass
class CheckResult:
    label: str
    target: str
    port: Optional[int]
    passed: bool
    error: str = ""

    @property
    def status_icon(self) -> str:
        return "✓" if self.passed else "✗"

    def __str__(self) -> str:
        port_str = f":{self.port}" if self.port else ""
        status = "PASS" if self.passed else f"FAIL ({self.error})"
        return f"[{self.status_icon}] {self.label}: {self.target}{port_str} → {status}"


async def check_tcp(
    host: str, port: int, *, label: str, timeout: float = 10.0
) -> CheckResult:
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )
        writer.close()
        await writer.wait_closed()
        log.info(f"TCP check PASS: {host}:{port}")
        return CheckResult(label=label, target=host, port=port, passed=True)
    except asyncio.TimeoutError:
        log.warning(f"TCP check TIMEOUT: {host}:{port}")
        return CheckResult(label=label, target=host, port=port,
                           passed=False, error="timeout")
    except ConnectionRefusedError:
        return CheckResult(label=label, target=host, port=port,
                           passed=False, error="connection refused")
    except OSError as e:
        return CheckResult(label=label, target=host, port=port,
                           passed=False, error=str(e))


async def check_icmp(host: str, *, label: str, timeout: float = 5.0) -> CheckResult:
    """ICMP ping via 'ping -c1 -W<timeout>'."""
    try:
        proc = await asyncio.create_subprocess_exec(
            "ping", "-c1", f"-W{int(timeout)}", host,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        returncode = await asyncio.wait_for(proc.wait(), timeout=timeout + 2)
        passed = (returncode == 0)
        log.info(f"ICMP check {'PASS' if passed else 'FAIL'}: {host}")
        return CheckResult(label=label, target=host, port=None, passed=passed,
                           error="" if passed else "no response")
    except asyncio.TimeoutError:
        return CheckResult(label=label, target=host, port=None,
                           passed=False, error="timeout")


async def resolve_host(hostname: str) -> Optional[str]:
    """Return first resolved IPv4, or None on failure."""
    try:
        loop = asyncio.get_event_loop()
        infos = await loop.getaddrinfo(
            hostname, None, family=socket.AF_INET,
            type=socket.SOCK_STREAM
        )
        return infos[0][4][0] if infos else None
    except Exception:
        return None


def build_check_matrix(cloud_ip: Optional[str]) -> list[dict]:
    """
    Returns list of check descriptors.
    Each dict: {label, host, port (None=ICMP), type ('tcp'|'icmp')}
    """
    checks = []

    if cloud_ip:
        checks.append({
            "label": "Edge → Asimily Cloud Server",
            "host": cloud_ip, "port": 443, "type": "tcp"
        })

    # Cloud MicroService – ICMP + TCP 443
    for host in ["ccs.asimily.com", "34.127.88.211"]:
        checks.append({"label": f"Cloud MicroService ICMP ({host})",
                        "host": host, "port": None, "type": "icmp"})
        checks.append({"label": f"Cloud MicroService TCP 443 ({host})",
                        "host": host, "port": 443, "type": "tcp"})

    # Site Reliability
    for host in ["hooks.slack.com", "storage.googleapis.com"]:
        checks.append({"label": f"Site Reliability TCP 443 ({host})",
                        "host": host, "port": 443, "type": "tcp"})

    # Systems Updates
    for host in ["archive.ubuntu.com", "security.ubuntu.com"]:
        checks.append({"label": f"Systems Updates TCP 80 ({host})",
                        "host": host, "port": 80, "type": "tcp"})

    # Sophos Antivirus – representative hostnames (wildcards resolved at runtime)
    sophos_hosts = [
        "d1.sophosupd.com", "d1.sophosupd.net", "d1.sophosxl.net",
        "mcs.sophos.com", "ocsp2.globalsign.com", "crl.globalsign.com",
    ]
    for host in sophos_hosts:
        for port in [80, 443]:
            checks.append({"label": f"Antivirus TCP {port} ({host})",
                            "host": host, "port": port, "type": "tcp"})

    return checks


async def run_all_checks(
    checks: list[dict],
    timeout: float = 10.0,
    progress_callback=None,   # async callable(completed: int, total: int)
) -> list[CheckResult]:
    results = []
    total = len(checks)

    async def _run_one(c: dict) -> CheckResult:
        if c["type"] == "icmp":
            return await check_icmp(c["host"], label=c["label"], timeout=timeout)
        else:
            return await check_tcp(c["host"], c["port"], label=c["label"], timeout=timeout)

    tasks = [asyncio.create_task(_run_one(c)) for c in checks]
    for i, task in enumerate(asyncio.as_completed(tasks), 1):
        result = await task
        results.append(result)
        if progress_callback:
            await progress_callback(i, total)

    return results
```

**Step 4: Run tests – must pass**

```bash
pytest tests/test_checks.py -v
```

**Step 5: Commit**

```bash
git add network/checks.py tests/test_checks.py
git commit -m "feat: async connectivity checks (TCP/ICMP) with connectivity matrix"
```

---

### Task 6: Screen 1 – Welcome & Interface Overview

**Files:**
- Create: `/opt/asimily/wizard/screens/__init__.py`
- Create: `/opt/asimily/wizard/screens/s01_welcome.py`

**Step 1: Implement s01_welcome.py**

No unit tests for pure TUI screens – they are integration-tested manually via `main.py`.

```python
# /opt/asimily/wizard/screens/s01_welcome.py
from textual.app import ComposeResult
from textual.screen import Screen
from textual.widgets import Header, Footer, Button, Static, DataTable
from textual.containers import Container, Vertical
from network.interfaces import list_interfaces
from logger import log

BANNER = """\
  █████╗ ███████╗██╗███╗   ███╗██╗██╗  ██╗   ██╗
 ██╔══██╗██╔════╝██║████╗ ████║██║██║  ╚██╗ ██╔╝
 ███████║███████╗██║██╔████╔██║██║██║   ╚████╔╝
 ██╔══██║╚════██║██║██║╚██╔╝██║██║██║    ╚██╔╝
 ██║  ██║███████║██║██║ ╚═╝ ██║██║███████╗██║
 ╚═╝  ╚═╝╚══════╝╚═╝╚═╝     ╚═╝╚═╝╚══════╝╚═╝
          First Time Setup Wizard
"""

class WelcomeScreen(Screen):
    """Step 1: Welcome screen showing all network interfaces."""

    BINDINGS = [("n", "next_step", "Next →")]

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield Static(BANNER, id="banner")
        with Container(id="content"):
            yield Static("Detected Network Interfaces", classes="title")
            yield DataTable(id="iface_table")
            yield Static(
                "\nPress [bold]N[/bold] or click [bold]Next[/bold] to continue.",
                markup=True
            )
        with Container(id="footer_buttons"):
            yield Button("Next →", id="btn_next", variant="primary")
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one("#iface_table", DataTable)
        table.add_columns("Interface", "Type", "Speed", "State", "MAC", "IP Addresses")
        ifaces = list_interfaces()
        log.info(f"Step 1: Found {len(ifaces)} interfaces")
        for iface in ifaces:
            ips = ", ".join(iface.ip_addresses) or "—"
            table.add_row(
                iface.name,
                iface.port_type,
                iface.speed_label,
                iface.operstate.upper(),
                iface.mac or "—",
                ips,
            )

    def action_next_step(self) -> None:
        from screens.s02_network_config import NetworkConfigScreen
        self.app.push_screen(NetworkConfigScreen())

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn_next":
            self.action_next_step()
```

**Step 2: Create screens/__init__.py**

```python
# /opt/asimily/wizard/screens/__init__.py
```

**Step 3: Manual smoke test**

```bash
cd /opt/asimily/wizard && python main.py
# Should display welcome screen with interface table; press N
```

**Step 4: Commit**

```bash
git add screens/
git commit -m "feat: step 1 – welcome screen with interface hardware overview"
```

---

### Task 7: Screen 2 – Network Configuration Form

**Files:**
- Create: `/opt/asimily/wizard/screens/s02_network_config.py`

**Step 1: Implement s02_network_config.py**

```python
# /opt/asimily/wizard/screens/s02_network_config.py
from __future__ import annotations
from textual.app import ComposeResult
from textual.screen import Screen
from textual.widgets import (
    Header, Footer, Button, Static, Select,
    Input, Checkbox, Label
)
from textual.containers import Container, Vertical, Horizontal
from network.interfaces import list_interfaces
from validators import validate_ip, validate_prefix, validate_gateway_in_subnet, validate_dns
from logger import log

class NetworkConfigScreen(Screen):
    """Step 2: Select management interface and configure IP settings."""

    BINDINGS = [
        ("escape", "go_back", "← Back"),
        ("n", "go_next", "Next →"),
    ]

    def compose(self) -> ComposeResult:
        ifaces = list_interfaces()
        iface_options = [(i.display_str(), i.name) for i in ifaces]

        yield Header(show_clock=True)
        with Vertical(id="form"):
            yield Static("Step 2: Management Port Configuration", classes="title")
            yield Label("Select Management Interface:")
            yield Select(options=iface_options, id="sel_iface", prompt="Choose interface…")

            yield Checkbox("Use DHCP", id="chk_dhcp", value=False)

            with Vertical(id="static_fields"):
                yield Label("IP Address:")
                yield Input(placeholder="e.g. 192.168.1.100", id="inp_ip")
                yield Label("Subnet Prefix Length (e.g. 24):")
                yield Input(placeholder="24", id="inp_prefix")
                yield Label("Default Gateway:")
                yield Input(placeholder="e.g. 192.168.1.1", id="inp_gw")

            yield Label("DNS Servers (comma-separated):")
            yield Input(placeholder="8.8.8.8, 8.8.4.4", id="inp_dns")
            yield Label("NTP Servers (comma-separated):")
            yield Input(placeholder="pool.ntp.org", id="inp_ntp")

            yield Checkbox("Use HTTP Proxy", id="chk_proxy", value=False)
            with Vertical(id="proxy_fields", classes="hidden"):
                yield Label("Proxy Host / IP:")
                yield Input(id="inp_proxy_host")
                yield Label("Proxy Port:")
                yield Input(id="inp_proxy_port")
                yield Label("Proxy Username (optional):")
                yield Input(id="inp_proxy_user")
                yield Label("Proxy Password (optional):")
                yield Input(id="inp_proxy_pass", password=True)

            yield Static("", id="err_msg")

        with Horizontal(id="nav_buttons"):
            yield Button("← Back", id="btn_back", variant="default")
            yield Button("Apply →", id="btn_next", variant="primary")
        yield Footer()

    def on_checkbox_changed(self, event: Checkbox.Changed) -> None:
        if event.checkbox.id == "chk_dhcp":
            self.query_one("#static_fields").set_class(event.value, "hidden")
        elif event.checkbox.id == "chk_proxy":
            self.query_one("#proxy_fields").set_class(not event.value, "hidden")

    def _collect_and_validate(self) -> bool:
        state = self.app.state
        iface_sel = self.query_one("#sel_iface", Select)
        if iface_sel.value is Select.BLANK:
            self._show_error("Please select a management interface.")
            return False
        state.mgmt_interface = iface_sel.value
        state.use_dhcp = self.query_one("#chk_dhcp", Checkbox).value

        if not state.use_dhcp:
            ip = self.query_one("#inp_ip", Input).value.strip()
            prefix_str = self.query_one("#inp_prefix", Input).value.strip()
            gw = self.query_one("#inp_gw", Input).value.strip()

            try:
                prefix = int(prefix_str)
            except ValueError:
                self._show_error("Prefix length must be a number (e.g. 24).")
                return False

            ok, msg = validate_prefix(prefix)
            if not ok:
                self._show_error(msg); return False

            ok, msg = validate_ip(ip, prefix_len=prefix)
            if not ok:
                self._show_error(msg); return False

            ok, msg = validate_gateway_in_subnet(gw, ip, prefix)
            if not ok:
                self._show_error(msg); return False

            state.ip_address = ip
            state.prefix_len = prefix
            state.gateway = gw

        dns_raw = self.query_one("#inp_dns", Input).value.strip()
        if dns_raw:
            dns_list = [s.strip() for s in dns_raw.split(",")]
            for d in dns_list:
                ok, msg = validate_dns(d)
                if not ok:
                    self._show_error(msg); return False
            state.dns_servers = dns_list

        ntp_raw = self.query_one("#inp_ntp", Input).value.strip()
        state.ntp_servers = [s.strip() for s in ntp_raw.split(",") if s.strip()]

        state.proxy_enabled = self.query_one("#chk_proxy", Checkbox).value
        if state.proxy_enabled:
            state.proxy_host = self.query_one("#inp_proxy_host", Input).value.strip()
            port_str = self.query_one("#inp_proxy_port", Input).value.strip()
            try:
                state.proxy_port = int(port_str)
            except ValueError:
                self._show_error("Proxy port must be a number."); return False
            state.proxy_user = self.query_one("#inp_proxy_user", Input).value.strip()
            state.proxy_password = self.query_one("#inp_proxy_pass", Input).value

        log.info(f"Step 2: config collected – iface={state.mgmt_interface}, "
                 f"dhcp={state.use_dhcp}, ip={state.ip_address}/{state.prefix_len}, "
                 f"gw={state.gateway}, dns={state.dns_servers}")
        return True

    def _show_error(self, msg: str) -> None:
        self.query_one("#err_msg", Static).update(f"[red]Error: {msg}[/red]")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn_back":
            self.app.pop_screen()
        elif event.button.id == "btn_next":
            if self._collect_and_validate():
                from screens.s03_network_apply import NetworkApplyScreen
                self.app.push_screen(NetworkApplyScreen())

    def action_go_back(self) -> None:
        self.app.pop_screen()

    def action_go_next(self) -> None:
        if self._collect_and_validate():
            from screens.s03_network_apply import NetworkApplyScreen
            self.app.push_screen(NetworkApplyScreen())
```

**Step 2: Manual smoke test**

```bash
python main.py
# Navigate to Step 2; test validation (bad IP, out-of-subnet gateway)
```

**Step 3: Commit**

```bash
git add screens/s02_network_config.py
git commit -m "feat: step 2 – network config form with full input validation"
```

---

### Task 8: Screen 3 – Network Apply with 60-second Countdown

**Files:**
- Create: `/opt/asimily/wizard/screens/s03_network_apply.py`

**Step 1: Implement s03_network_apply.py**

```python
# /opt/asimily/wizard/screens/s03_network_apply.py
from __future__ import annotations
import asyncio
from textual.app import ComposeResult
from textual.screen import Screen
from textual.widgets import Header, Footer, Button, Static, ProgressBar
from textual.containers import Container, Vertical
from network.netplan import NetplanManager
from logger import log

COUNTDOWN_SECONDS = 60

class NetworkApplyScreen(Screen):
    """Step 3: Apply network config via 'netplan try' with 60-second rollback countdown."""

    BINDINGS = [("enter", "confirm_settings", "Confirm")]

    def __init__(self):
        super().__init__()
        self._netplan = NetplanManager()
        self._proc = None
        self._countdown = COUNTDOWN_SECONDS
        self._confirmed = False
        self._timer_task = None

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Vertical(id="content"):
            yield Static("Step 3: Applying Network Configuration", classes="title")
            yield Static("", id="status_msg")
            yield Static(
                f"[bold]Time remaining to confirm:[/bold] {COUNTDOWN_SECONDS}s",
                id="countdown_label", markup=True
            )
            yield ProgressBar(total=COUNTDOWN_SECONDS, id="countdown_bar")
            yield Static(
                "\nPress [bold]ENTER[/bold] or click [bold]Confirm[/bold] to accept "
                "the new settings.\nIf no action is taken, the old settings will be "
                "restored automatically.",
                markup=True
            )
            yield Static("", id="err_msg")

        with Container(id="nav_buttons"):
            yield Button("✓ Confirm Settings", id="btn_confirm", variant="success",
                         disabled=True)
            yield Button("← Back to Config", id="btn_back", variant="default",
                         disabled=True)
        yield Footer()

    def on_mount(self) -> None:
        self._timer_task = asyncio.create_task(self._apply_and_countdown())

    async def _apply_and_countdown(self) -> None:
        state = self.app.state
        nm = self._netplan
        status = self.query_one("#status_msg", Static)
        err = self.query_one("#err_msg", Static)

        try:
            status.update("Backing up existing configuration…")
            nm.backup()

            status.update("Writing new Netplan configuration…")
            if state.use_dhcp:
                nm.write_dhcp(iface=state.mgmt_interface,
                               dns=state.dns_servers, ntp=state.ntp_servers)
            else:
                nm.write_static(
                    iface=state.mgmt_interface,
                    ip_cidr=f"{state.ip_address}/{state.prefix_len}",
                    gateway=state.gateway,
                    dns=state.dns_servers,
                    ntp=state.ntp_servers,
                )

            status.update("Applying with 'netplan try'… waiting for confirmation.")
            self._proc = nm.apply_try(timeout=COUNTDOWN_SECONDS)
            # Enable confirm button once netplan try is running
            self.query_one("#btn_confirm").disabled = False

        except Exception as e:
            err.update(f"[red]Error applying config: {e}[/red]")
            self.query_one("#btn_back").disabled = False
            log.error(f"Step 3 apply failed: {e}")
            return

        # Countdown loop
        bar = self.query_one("#countdown_bar", ProgressBar)
        label = self.query_one("#countdown_label", Static)
        for remaining in range(COUNTDOWN_SECONDS, 0, -1):
            if self._confirmed:
                break
            label.update(
                f"[bold]Time remaining to confirm:[/bold] {remaining}s"
            )
            bar.advance(1)
            await asyncio.sleep(1)

        if not self._confirmed:
            log.info("Step 3: countdown expired – netplan will auto-rollback")
            status.update("[yellow]Timeout – rolling back to previous configuration.[/yellow]")
            try:
                self._proc.wait(timeout=5)
            except Exception:
                pass
            self.query_one("#btn_back").disabled = False

    def action_confirm_settings(self) -> None:
        if not self._confirmed and self._proc:
            self._do_confirm()

    def _do_confirm(self) -> None:
        self._confirmed = True
        from network.netplan import NetplanManager
        nm = NetplanManager()
        nm.confirm_apply(self._proc)
        log.info("Step 3: network settings confirmed by user")
        self.query_one("#status_msg", Static).update(
            "[green]✓ Configuration confirmed and applied.[/green]"
        )
        self.query_one("#btn_confirm").disabled = True
        # After short delay, advance to next screen
        asyncio.create_task(self._advance())

    async def _advance(self) -> None:
        await asyncio.sleep(1.5)
        from screens.s04_cloud_ip import CloudIPScreen
        self.app.push_screen(CloudIPScreen())

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn_confirm":
            self._do_confirm()
        elif event.button.id == "btn_back":
            self.app.pop_screen()
```

**Step 2: Manual smoke test**

```bash
python main.py
# Navigate to step 3; verify countdown ticks; confirm with Enter
```

**Step 3: Commit**

```bash
git add screens/s03_network_apply.py
git commit -m "feat: step 3 – netplan try with 60s countdown + rollback protection"
```

---

### Task 9: Screen 4 – Cloud Server IP (Optional)

**Files:**
- Create: `/opt/asimily/wizard/screens/s04_cloud_ip.py`

**Step 1: Implement s04_cloud_ip.py**

```python
# /opt/asimily/wizard/screens/s04_cloud_ip.py
from textual.app import ComposeResult
from textual.screen import Screen
from textual.widgets import Header, Footer, Button, Static, Input, Label
from textual.containers import Vertical, Horizontal
from validators import validate_ip
from logger import log

class CloudIPScreen(Screen):
    """Step 4: Optional Asimily Cloud Server IP."""

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Vertical(id="content"):
            yield Static("Step 4: Asimily Cloud Server IP (Optional)", classes="title")
            yield Static(
                "Enter the unique Asimily Cloud Server IP assigned to your site.\n"
                "Leave empty and click [bold]Skip[/bold] to configure later.",
                markup=True
            )
            yield Label("Cloud Server IP Address:")
            yield Input(placeholder="e.g. 203.0.113.10", id="inp_cloud_ip")
            yield Static("", id="err_msg")

        with Horizontal(id="nav_buttons"):
            yield Button("← Back", id="btn_back", variant="default")
            yield Button("Skip →", id="btn_skip", variant="warning")
            yield Button("Next →", id="btn_next", variant="primary")
        yield Footer()

    def _go_next(self) -> None:
        from screens.s05_preflight import PreflightScreen
        self.app.push_screen(PreflightScreen())

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn_back":
            self.app.pop_screen()
        elif event.button.id == "btn_skip":
            self.app.state.cloud_ip = None
            log.info("Step 4: Cloud IP skipped by user")
            self._go_next()
        elif event.button.id == "btn_next":
            ip = self.query_one("#inp_cloud_ip", Input).value.strip()
            if not ip:
                self.app.state.cloud_ip = None
                log.info("Step 4: Cloud IP left empty – treated as skip")
                self._go_next()
                return
            ok, msg = validate_ip(ip)
            if not ok:
                self.query_one("#err_msg", Static).update(f"[red]{msg}[/red]")
                return
            self.app.state.cloud_ip = ip
            log.info(f"Step 4: Cloud IP set to {ip}")
            self._go_next()
```

**Step 2: Commit**

```bash
git add screens/s04_cloud_ip.py
git commit -m "feat: step 4 – optional cloud server IP with skip support"
```

---

### Task 10: Screen 5 – Async Pre-flight Checks with 30-second Timer

**Files:**
- Create: `/opt/asimily/wizard/screens/s05_preflight.py`

**Step 1: Implement s05_preflight.py**

```python
# /opt/asimily/wizard/screens/s05_preflight.py
from __future__ import annotations
import asyncio
from textual.app import ComposeResult
from textual.screen import Screen
from textual.widgets import (
    Header, Footer, Button, Static, ProgressBar, ListView, ListItem, Label, Input
)
from textual.containers import Vertical, Horizontal, Container
from network.checks import build_check_matrix, run_all_checks, CheckResult
from logger import log

COUNTDOWN = 30

class PreflightScreen(Screen):
    """Step 5: Async pre-flight connectivity checks with 30-second countdown."""

    def __init__(self):
        super().__init__()
        self._results: list[CheckResult] = []

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Vertical(id="content"):
            yield Static("Step 5: Pre-Flight Network Check", classes="title")
            yield Static(f"Running connectivity tests (up to {COUNTDOWN}s)…",
                         id="status_msg")
            yield ProgressBar(total=COUNTDOWN, id="timer_bar")
            yield Static(f"[bold]Elapsed:[/bold] 0s", id="timer_label", markup=True)
            yield Static("", id="spinner")
            yield ListView(id="results_list")
            yield Static("", id="err_msg")
            yield Static("", id="retry_prompt")

        with Horizontal(id="nav_buttons"):
            yield Button("← Retry Network Config", id="btn_back", variant="default",
                         disabled=True)
            yield Button("Next →", id="btn_next", variant="primary", disabled=True)
        yield Footer()

    def on_mount(self) -> None:
        asyncio.create_task(self._run_checks())
        asyncio.create_task(self._run_timer())

    async def _run_timer(self) -> None:
        bar = self.query_one("#timer_bar", ProgressBar)
        label = self.query_one("#timer_label", Static)
        for elapsed in range(1, COUNTDOWN + 1):
            await asyncio.sleep(1)
            bar.advance(1)
            label.update(f"[bold]Elapsed:[/bold] {elapsed}s")

    async def _run_checks(self) -> None:
        state = self.app.state
        checks = build_check_matrix(cloud_ip=state.cloud_ip)
        spinner_frames = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
        spinner_widget = self.query_one("#spinner", Static)
        frame_idx = 0
        results_list = self.query_one("#results_list", ListView)
        completed = 0

        async def progress_cb(done: int, total: int) -> None:
            nonlocal frame_idx, completed
            completed = done
            spinner_widget.update(spinner_frames[frame_idx % len(spinner_frames)])
            frame_idx += 1

        self._results = await run_all_checks(checks, timeout=10, progress_callback=progress_cb)

        spinner_widget.update("")
        results_list.clear()
        cloud_failed = False
        general_failed = False

        for r in self._results:
            icon = "[green]✓[/green]" if r.passed else "[red]✗[/red]"
            detail = f"  {r.error}" if not r.passed else ""
            results_list.append(
                ListItem(Label(f"{icon} {r.label} ({r.target}){detail}", markup=True))
            )
            if not r.passed:
                if "Cloud Server" in r.label:
                    cloud_failed = True
                else:
                    general_failed = True

        log.info(f"Step 5: {sum(1 for r in self._results if r.passed)}/{len(self._results)} checks passed")

        err = self.query_one("#err_msg", Static)
        if cloud_failed and state.cloud_ip is not None:
            err.update(
                "[yellow]Cloud Server check failed. Enter a new IP below or skip:[/yellow]"
            )
            self._show_cloud_retry()
        elif general_failed:
            err.update("[red]Some connectivity checks failed. You can go back to fix "
                       "network settings or proceed anyway.[/red]")

        self.query_one("#btn_back").disabled = False
        self.query_one("#btn_next").disabled = False
        self.query_one("#status_msg", Static).update("Checks complete.")

    def _show_cloud_retry(self) -> None:
        retry = self.query_one("#retry_prompt", Static)
        retry.update(
            "New Cloud Server IP (leave empty to skip): "
        )
        # Mount a dynamic input widget
        self.mount(Input(placeholder="New Cloud IP or leave empty", id="inp_retry_ip"),
                   after="#retry_prompt")
        self.mount(
            Button("Retry with new IP", id="btn_retry_ip", variant="warning"),
            after="#inp_retry_ip"
        )
        self.mount(
            Button("Skip Cloud Check", id="btn_skip_cloud", variant="default"),
            after="#btn_retry_ip"
        )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn_back":
            self.app.pop_screen()  # back to network config
        elif event.button.id == "btn_next":
            from screens.s06_mirror_ports import MirrorPortsScreen
            self.app.push_screen(MirrorPortsScreen())
        elif event.button.id == "btn_retry_ip":
            inp = self.query_one("#inp_retry_ip", Input)
            new_ip = inp.value.strip()
            if new_ip:
                self.app.state.cloud_ip = new_ip
                log.info(f"Step 5: retrying with new cloud IP {new_ip}")
                asyncio.create_task(self._run_checks())
        elif event.button.id == "btn_skip_cloud":
            self.app.state.cloud_ip = None
            log.info("Step 5: Cloud IP check skipped by user")
            asyncio.create_task(self._run_checks())
```

**Step 2: Commit**

```bash
git add screens/s05_preflight.py
git commit -m "feat: step 5 – async pre-flight checks with 30s timer, spinner, retry/skip"
```

---

### Task 11: Screen 6 – Mirror Port Multiselect

**Files:**
- Create: `/opt/asimily/wizard/screens/s06_mirror_ports.py`

**Step 1: Implement s06_mirror_ports.py**

```python
# /opt/asimily/wizard/screens/s06_mirror_ports.py
from textual.app import ComposeResult
from textual.screen import Screen
from textual.widgets import Header, Footer, Button, Static, SelectionList
from textual.widgets.selection_list import Selection
from textual.containers import Vertical, Horizontal
from network.interfaces import list_interfaces
from logger import log

class MirrorPortsScreen(Screen):
    """Step 6: Multiselect mirror ports from remaining interfaces."""

    def compose(self) -> ComposeResult:
        state = self.app.state
        ifaces = list_interfaces()
        # Exclude the management interface
        candidates = [i for i in ifaces if i.name != state.mgmt_interface]

        selections = [
            Selection(
                f"{i.name}  ({i.port_type} {i.speed_label})",
                i.name,
                initial_state=False,
            )
            for i in candidates
        ]

        yield Header(show_clock=True)
        with Vertical(id="content"):
            yield Static("Step 6: Mirror Port Selection", classes="title")
            yield Static(
                "Select the interfaces that will receive mirrored/SPAN traffic "
                "(PCAP / traffic analysis).\nUse [bold]Space[/bold] to toggle, "
                "[bold]↑↓[/bold] to navigate.",
                markup=True
            )
            if selections:
                yield SelectionList(*selections, id="mirror_list")
            else:
                yield Static("[yellow]No additional interfaces available.[/yellow]",
                             markup=True)
            yield Static("", id="err_msg")

        with Horizontal(id="nav_buttons"):
            yield Button("← Back", id="btn_back", variant="default")
            yield Button("Finish →", id="btn_next", variant="primary")
        yield Footer()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn_back":
            self.app.pop_screen()
        elif event.button.id == "btn_next":
            try:
                sel_list = self.query_one("#mirror_list", SelectionList)
                selected = list(sel_list.selected)
            except Exception:
                selected = []
            self.app.state.mirror_interfaces = selected
            log.info(f"Step 6: mirror interfaces = {selected}")
            from screens.s07_finish import FinishScreen
            self.app.push_screen(FinishScreen())
```

**Step 2: Commit**

```bash
git add screens/s06_mirror_ports.py
git commit -m "feat: step 6 – mirror port multiselect"
```

---

### Task 12: Screen 7 – Finish & Launch install.sh

**Files:**
- Create: `/opt/asimily/wizard/screens/s07_finish.py`

**Step 1: Implement s07_finish.py**

```python
# /opt/asimily/wizard/screens/s07_finish.py
from __future__ import annotations
import asyncio, subprocess, json
from pathlib import Path
from textual.app import ComposeResult
from textual.screen import Screen
from textual.widgets import Header, Footer, Button, Static
from textual.containers import Vertical
from logger import log

INSTALL_SCRIPT = "/opt/asimily/install.sh"

class FinishScreen(Screen):
    """Step 7: Summary, final confirmation, launch install.sh."""

    def compose(self) -> ComposeResult:
        state = self.app.state
        summary = self._build_summary(state)
        yield Header(show_clock=True)
        with Vertical(id="content"):
            yield Static("Step 7: Configuration Complete", classes="title")
            yield Static(summary, markup=True)
            yield Static("", id="status_msg")
        with Vertical(id="nav_buttons"):
            yield Button("← Back", id="btn_back", variant="default")
            yield Button("▶ Start Installation", id="btn_install", variant="success")
        yield Footer()

    def _build_summary(self, state) -> str:
        lines = ["[bold]Configuration Summary[/bold]\n"]
        lines.append(f"  Management Interface : [cyan]{state.mgmt_interface}[/cyan]")
        if state.use_dhcp:
            lines.append("  IP Assignment        : DHCP")
        else:
            lines.append(f"  IP Address           : {state.ip_address}/{state.prefix_len}")
            lines.append(f"  Gateway              : {state.gateway}")
        lines.append(f"  DNS                  : {', '.join(state.dns_servers) or '—'}")
        lines.append(f"  NTP                  : {', '.join(state.ntp_servers) or '—'}")
        lines.append(f"  Proxy                : {'Yes' if state.proxy_enabled else 'No'}")
        lines.append(f"  Cloud Server IP      : {state.cloud_ip or '(skipped)'}")
        lines.append(f"  Mirror Interfaces    : {', '.join(state.mirror_interfaces) or '—'}")
        return "\n".join(lines)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn_back":
            self.app.pop_screen()
        elif event.button.id == "btn_install":
            event.button.disabled = True
            asyncio.create_task(self._launch_install())

    async def _launch_install(self) -> None:
        status = self.query_one("#status_msg", Static)
        state = self.app.state

        # Persist final config as JSON for install.sh to consume
        config_path = Path("/etc/asimily/wizard_config.json")
        config_path.parent.mkdir(parents=True, exist_ok=True)
        config_data = {
            "mgmt_interface": state.mgmt_interface,
            "use_dhcp": state.use_dhcp,
            "ip_address": state.ip_address,
            "prefix_len": state.prefix_len,
            "gateway": state.gateway,
            "dns_servers": state.dns_servers,
            "ntp_servers": state.ntp_servers,
            "proxy_enabled": state.proxy_enabled,
            "proxy_host": state.proxy_host,
            "proxy_port": state.proxy_port,
            "proxy_user": state.proxy_user,
            "cloud_ip": state.cloud_ip,
            "mirror_interfaces": state.mirror_interfaces,
        }
        config_path.write_text(json.dumps(config_data, indent=2))
        log.info(f"Config written to {config_path}")

        if not Path(INSTALL_SCRIPT).exists():
            log.warning(f"Install script not found at {INSTALL_SCRIPT}; skipping.")
            status.update(
                f"[yellow]Warning: {INSTALL_SCRIPT} not found. "
                "Configuration saved to /etc/asimily/wizard_config.json.[/yellow]"
            )
            return

        log.info(f"Launching {INSTALL_SCRIPT}")
        status.update(f"[cyan]Launching {INSTALL_SCRIPT}…[/cyan]")

        try:
            proc = await asyncio.create_subprocess_exec(
                "bash", INSTALL_SCRIPT,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
            )
            stdout, _ = await proc.communicate()
            if proc.returncode == 0:
                log.info("install.sh completed successfully")
                status.update("[green]✓ Installation completed. The wizard will now exit.[/green]")
                await asyncio.sleep(3)
                self.app.exit()
            else:
                log.error(f"install.sh exited with code {proc.returncode}")
                status.update(
                    f"[red]install.sh failed (exit code {proc.returncode}). "
                    f"Check /var/log/asimily_wizard.log[/red]"
                )
        except Exception as e:
            log.error(f"Failed to launch install.sh: {e}")
            status.update(f"[red]Error: {e}[/red]")
```

**Step 2: Commit**

```bash
git add screens/s07_finish.py
git commit -m "feat: step 7 – summary, config export, install.sh launcher"
```

---

### Task 13: Wire up app.py CSS & Final Integration

**Files:**
- Modify: `/opt/asimily/wizard/app.py`

**Step 1: Update app.py with CSS theme**

```python
# /opt/asimily/wizard/app.py
from textual.app import App
from state import WizardState
from logger import log

class AsimilyWizard(App):
    """Asimily First Time Setup Wizard."""

    CSS = """
    Screen {
        background: $surface;
    }
    .title {
        text-style: bold;
        color: $accent;
        margin-bottom: 1;
    }
    .hidden {
        display: none;
    }
    #banner {
        color: $primary;
        margin: 1 2;
    }
    #content {
        margin: 1 2;
    }
    #form {
        margin: 1 2;
    }
    #nav_buttons {
        dock: bottom;
        height: 3;
        align: center middle;
        margin: 1 2;
    }
    #footer_buttons {
        dock: bottom;
        height: 3;
        align: center middle;
    }
    Button {
        margin: 0 1;
    }
    #err_msg {
        margin-top: 1;
        color: $error;
    }
    DataTable {
        height: 12;
    }
    ListView {
        height: 20;
        border: solid $primary;
    }
    SelectionList {
        height: 15;
        border: solid $primary;
    }
    Input {
        margin-bottom: 1;
    }
    #countdown_label, #timer_label {
        margin-top: 1;
    }
    """

    def __init__(self):
        super().__init__()
        self.state = WizardState()
        log.info("AsimilyWizard started")

    def on_mount(self) -> None:
        from screens.s01_welcome import WelcomeScreen
        self.push_screen(WelcomeScreen())
```

**Step 2: Full end-to-end manual test**

```bash
python main.py
# Walk through all 7 steps
# Verify: interface table, validation errors, countdown, preflight checks, mirror select
```

**Step 3: Commit**

```bash
git add app.py
git commit -m "feat: wire up TUI theme and complete wizard flow"
```

---

### Task 14: Systemd service unit (auto-start on first boot)

**Files:**
- Create: `/etc/systemd/system/asimily-wizard.service`

**Step 1: Write service unit**

```ini
# /etc/systemd/system/asimily-wizard.service
[Unit]
Description=Asimily First Time Setup Wizard
After=network-pre.target
Before=network.target
ConditionPathExists=!/etc/asimily/wizard_config.json

[Service]
Type=simple
ExecStart=/usr/bin/python3 /opt/asimily/wizard/main.py
StandardInput=tty
StandardOutput=tty
StandardError=journal
TTYPath=/dev/tty1
TTYReset=yes
TTYVHangup=yes
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

**Step 2: Enable the service**

```bash
systemctl daemon-reload
systemctl enable asimily-wizard.service
```

**Step 3: Commit**

```bash
git add /etc/systemd/system/asimily-wizard.service
git commit -m "feat: systemd service for first-boot wizard auto-launch"
```

---

### Task 15: Final cleanup – run all tests

**Step 1: Run full test suite**

```bash
cd /opt/asimily/wizard
pytest tests/ -v --tb=short
```

Expected: All tests PASS.

**Step 2: Lint check**

```bash
python -m py_compile main.py app.py state.py logger.py validators.py \
    network/interfaces.py network/netplan.py network/checks.py \
    screens/s01_welcome.py screens/s02_network_config.py \
    screens/s03_network_apply.py screens/s04_cloud_ip.py \
    screens/s05_preflight.py screens/s06_mirror_ports.py \
    screens/s07_finish.py
echo "Syntax OK"
```

**Step 3: Final commit**

```bash
git add .
git commit -m "chore: final integration, all tests green"
```

---

## Dependency Summary

| Package | Version | Purpose |
|---|---|---|
| `textual` | ≥0.60 | Async TUI framework |
| `pyyaml` | ≥6.0 | Netplan YAML generation |
| `pytest` | ≥8.0 | Test runner |
| `pytest-asyncio` | ≥0.23 | Async test support |

System tools required: `netplan`, `ethtool`, `ip`, `ping` (iproute2), `bash`

---

## Key Design Decisions

1. **`textual` over `urwid`/`prompt_toolkit`**: Native `asyncio` support, richer widget set, active maintenance.
2. **One `Screen` per wizard step**: Clean separation, simple `push_screen`/`pop_screen` navigation with state preserved in `app.state`.
3. **`netplan try --timeout 60`**: Leverages Ubuntu's built-in safe-mode rollback; no custom rollback logic needed.
4. **Config JSON at `/etc/asimily/wizard_config.json`**: Decouples wizard from `install.sh`; install script reads structured config.
5. **Systemd `ConditionPathExists=!…`**: Wizard only runs once; after completion the config file exists and the service is a no-op.
