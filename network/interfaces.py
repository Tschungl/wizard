# network/interfaces.py
from __future__ import annotations
import os
import subprocess
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, List
from logger import log

SYS_NET = "/sys/class/net"


@dataclass
class InterfaceInfo:
    name: str
    operstate: str          # "up" | "down" | "unknown"
    link_speed_mbps: Optional[int]  # None if not available
    port_type: str          # "RJ45" | "SFP+" | "SFP" | "Loopback" | "Unknown"
    mac: str
    ip_addresses: List[str]  # CIDR notation

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


def _read_sysfs(iface: str, attr: str, default: Optional[str] = None) -> Optional[str]:
    path = os.path.join(SYS_NET, iface, attr)
    try:
        with open(path) as f:
            return f.read().strip()
    except OSError:
        return default


def _get_port_type(iface: str) -> str:
    """Determine port type via ethtool; fall back to sysfs heuristics."""
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
                    speed = _read_sysfs(iface, "speed")
                    if speed and speed.isdigit() and int(speed) >= 10000:
                        return "SFP+"
                    return "SFP"
                if "tp" in port or "twisted" in port:
                    return "RJ45"
                if port in ("da", "direct attach"):
                    return "DAC"
    except Exception as e:
        log.debug(f"ethtool failed for {iface}: {e}")
    return "Unknown"


def _get_ip_addresses(iface: str) -> List[str]:
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
        name=iface,
        operstate=operstate or "unknown",
        link_speed_mbps=speed,
        port_type=port_type,
        mac=mac or "",
        ip_addresses=ips,
    )


def list_interfaces(exclude_lo: bool = True) -> List[InterfaceInfo]:
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


async def async_iface_status(iface: str) -> tuple[str, list[str]]:
    """
    Return (operstate, [ip/prefix, ...]) for `iface` without blocking.
    Reads operstate from sysfs; parses IPs from `ip -4 addr show dev <iface>`.
    Returns ("unknown", []) if the interface does not exist.
    """
    import asyncio

    # operstate
    operstate_path = Path(f"/sys/class/net/{iface}/operstate")
    try:
        operstate = operstate_path.read_text().strip()
    except OSError:
        return "unknown", []

    # IP addresses via `ip -4 addr show dev <iface>`
    try:
        proc = await asyncio.create_subprocess_exec(
            "ip", "-4", "addr", "show", "dev", iface,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        stdout, _ = await proc.communicate()
    except OSError:
        return "unknown", []

    ips: list[str] = []
    for line in stdout.decode().splitlines():
        line = line.strip()
        if line.startswith("inet "):
            parts = line.split()
            if len(parts) >= 2:
                ips.append(parts[1])   # e.g. "192.168.1.100/24"

    return operstate, ips
