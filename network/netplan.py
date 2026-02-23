# network/netplan.py
from __future__ import annotations
import os
import shutil
import subprocess
import yaml
from pathlib import Path
from typing import Optional, List
from logger import log

WIZARD_FILENAME = "60-asimily-wizard.yaml"
NTP_CONF_DIR = Path("/etc/systemd/timesyncd.conf.d")
NTP_CONF_FILENAME = "wizard.conf"
ENV_FILE = Path("/etc/environment")
MIRROR_FILENAME = "61-asimily-mirror.yaml"


class NetplanManager:
    def __init__(self, netplan_dir: str = "/etc/netplan"):
        self.netplan_dir = Path(netplan_dir)

    # -- Backup / Restore --------------------------------------------------

    def backup(self) -> None:
        """Copy all existing .yaml files to .yaml.bak (skipping wizard file)."""
        for f in self.netplan_dir.glob("*.yaml"):
            if f.name == WIZARD_FILENAME:
                continue
            bak = f.with_suffix(".yaml.bak")
            shutil.copy2(f, bak)
            log.info(f"Backed up {f} -> {bak}")

    def restore(self) -> None:
        """Remove wizard YAML, restore .bak files."""
        wizard = self.netplan_dir / WIZARD_FILENAME
        if wizard.exists():
            wizard.unlink()
            log.info(f"Removed wizard netplan config {wizard}")
        for bak in self.netplan_dir.glob("*.bak"):
            original = bak.with_suffix("")   # strips .bak -> .yaml
            bak.rename(original)
            log.info(f"Restored {bak} -> {original}")

    # -- Write -------------------------------------------------------------

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
        dns: List[str],
        ntp: List[str],
        proxy: Optional[dict] = None,
    ) -> None:
        ethernets_entry: dict = {
            "addresses": [ip_cidr],
            "routes": [{"to": "default", "via": gateway}],
        }
        if dns:
            ethernets_entry["nameservers"] = {"addresses": dns}
        config = {
            "network": {
                "version": 2,
                "renderer": "networkd",
                "ethernets": {iface: ethernets_entry},
            }
        }
        self._write_yaml(config)

    def write_dhcp(
        self,
        iface: str,
        dns: List[str],
        ntp: List[str],
        proxy: Optional[dict] = None,
    ) -> None:
        ethernets_entry: dict = {"dhcp4": True}
        if dns:
            ethernets_entry["nameservers"] = {"addresses": dns}
        config = {
            "network": {
                "version": 2,
                "renderer": "networkd",
                "ethernets": {iface: ethernets_entry},
            }
        }
        self._write_yaml(config)

    # -- Apply (wraps `netplan try`) ---------------------------------------

    def apply_try(self, timeout: int = 60) -> subprocess.Popen:
        """
        Start `netplan try --timeout <N>` and return the Popen object.
        The caller confirms by writing newline to stdin, or lets it time out
        for automatic rollback.
        """
        log.info(f"Running: netplan try --timeout={timeout}")
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

    # -- NTP / Proxy -----------------------------------------------------------

    def apply_ntp(self, ntp_servers: List[str]) -> None:
        """Write NTP servers to a systemd-timesyncd drop-in config file."""
        if not ntp_servers:
            return
        NTP_CONF_DIR.mkdir(parents=True, exist_ok=True)
        conf_path = NTP_CONF_DIR / NTP_CONF_FILENAME
        content = f"[Time]\nNTP={' '.join(ntp_servers)}\n"
        conf_path.write_text(content)
        os.chmod(conf_path, 0o644)
        log.info("Wrote NTP config to %s", conf_path)

    def apply_proxy(
        self,
        host: str,
        port: int,
        user: str = "",
        password: str = "",
    ) -> None:
        """Write http_proxy / https_proxy entries to /etc/environment."""
        if user and password:
            url = f"http://{user}:{password}@{host}:{port}/"
        else:
            url = f"http://{host}:{port}/"
        # Preserve unrelated lines from any existing file
        lines: List[str] = []
        _proxy_keys = (
            "http_proxy=", "HTTP_PROXY=",
            "https_proxy=", "HTTPS_PROXY=",
            "no_proxy=", "NO_PROXY=",
        )
        if ENV_FILE.exists():
            for line in ENV_FILE.read_text().splitlines():
                if not any(line.startswith(k) for k in _proxy_keys):
                    lines.append(line)
        lines += [
            f"http_proxy={url}",
            f"HTTP_PROXY={url}",
            f"https_proxy={url}",
            f"HTTPS_PROXY={url}",
            "no_proxy=localhost,127.0.0.1",
            "NO_PROXY=localhost,127.0.0.1",
        ]
        ENV_FILE.write_text("\n".join(lines) + "\n")
        log.info("Wrote proxy config to %s", ENV_FILE)

    # -- Mirror ports -----------------------------------------------------------

    def write_mirror_ports(self, ifaces: List[str]) -> None:
        """Write a netplan YAML that sets mirror interfaces to promiscuous/no-IP."""
        if not ifaces:
            return
        ethernets = {
            iface: {"dhcp4": False, "link": {"promiscuous": True}}
            for iface in ifaces
        }
        config = {
            "network": {
                "version": 2,
                "renderer": "networkd",
                "ethernets": ethernets,
            }
        }
        path = self.netplan_dir / MIRROR_FILENAME
        with open(path, "w") as f:
            yaml.dump(config, f, default_flow_style=False)
        os.chmod(path, 0o600)
        log.info("Wrote mirror ports config to %s", path)

    def configure_mirror_promisc(self, ifaces: List[str]) -> None:
        """Immediately bring up each interface in promiscuous mode via ip link."""
        for iface in ifaces:
            try:
                subprocess.run(
                    ["ip", "link", "set", iface, "promisc", "on"],
                    check=True, capture_output=True
                )
                log.info("Set %s promisc on", iface)
            except subprocess.CalledProcessError as e:
                log.warning("ip link set %s promisc on failed: %s", iface, e)
            try:
                subprocess.run(
                    ["ip", "link", "set", iface, "up"],
                    check=True, capture_output=True
                )
                log.info("Set %s up", iface)
            except subprocess.CalledProcessError as e:
                log.warning("ip link set %s up failed: %s", iface, e)
