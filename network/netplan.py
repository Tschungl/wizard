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
