# state.py
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional, List

@dataclass
class WizardState:
    # Step 2
    mgmt_interface: str = ""
    use_dhcp: bool = False
    ip_address: str = ""
    prefix_len: int = 24
    gateway: str = ""
    dns_servers: List[str] = field(default_factory=list)
    ntp_servers: List[str] = field(default_factory=list)
    proxy_enabled: bool = False
    proxy_host: str = ""
    proxy_port: int = 0
    proxy_user: str = ""
    proxy_password: str = ""

    # Step 4
    cloud_ip: Optional[str] = None   # None = skipped

    # Step 6
    mirror_interfaces: List[str] = field(default_factory=list)
