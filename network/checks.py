# network/checks.py
from __future__ import annotations
import asyncio
import socket
from dataclasses import dataclass, field
from typing import Optional, List, Callable, Awaitable
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
        return f"[{self.status_icon}] {self.label}: {self.target}{port_str} -> {status}"


async def check_tcp(
    host: str, port: int, *, label: str, timeout: float = 10.0
) -> CheckResult:
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )
        writer.close()
        await writer.wait_closed()
        log.info("TCP check PASS: %s:%s", host, port)
        return CheckResult(label=label, target=host, port=port, passed=True)
    except asyncio.TimeoutError:
        log.warning("TCP check TIMEOUT: %s:%s", host, port)
        return CheckResult(label=label, target=host, port=port,
                           passed=False, error="timeout")
    except ConnectionRefusedError:
        log.warning("TCP check REFUSED: %s:%s", host, port)
        return CheckResult(label=label, target=host, port=port,
                           passed=False, error="connection refused")
    except OSError as e:
        log.warning("TCP check FAILED: %s:%s: %s", host, port, e)
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
        log.info("ICMP check %s: %s", "PASS" if passed else "FAIL", host)
        return CheckResult(label=label, target=host, port=None, passed=passed,
                           error="" if passed else "no response")
    except asyncio.TimeoutError:
        log.warning("ICMP check TIMEOUT: %s", host)
        return CheckResult(label=label, target=host, port=None,
                           passed=False, error="timeout")
    except Exception as e:
        log.warning("ICMP check ERROR: %s: %s", host, e)
        return CheckResult(label=label, target=host, port=None,
                           passed=False, error=str(e))


async def resolve_host(hostname: str) -> Optional[str]:
    """Return first resolved IPv4, or None on failure."""
    try:
        loop = asyncio.get_running_loop()
        infos = await loop.getaddrinfo(
            hostname, None,
            family=socket.AF_INET,
            type=socket.SOCK_STREAM,
        )
        return infos[0][4][0] if infos else None
    except Exception:
        return None


def build_check_matrix(cloud_ip: Optional[str]) -> List[dict]:
    """
    Returns list of check descriptors.
    Each dict: {label, host, port (None=ICMP), type ('tcp'|'icmp')}
    """
    checks: List[dict] = []

    if cloud_ip:
        checks.append({
            "label": "Edge -> Asimily Cloud Server",
            "host": cloud_ip,
            "port": 443,
            "type": "tcp",
        })

    # Cloud MicroService – ICMP + TCP 443
    for host in ["ccs.asimily.com", "34.127.88.211"]:
        checks.append({
            "label": f"Cloud MicroService ICMP ({host})",
            "host": host, "port": None, "type": "icmp",
        })
        checks.append({
            "label": f"Cloud MicroService TCP 443 ({host})",
            "host": host, "port": 443, "type": "tcp",
        })

    # Site Reliability
    for host in ["hooks.slack.com", "storage.googleapis.com"]:
        checks.append({
            "label": f"Site Reliability TCP 443 ({host})",
            "host": host, "port": 443, "type": "tcp",
        })

    # Systems Updates
    for host in ["archive.ubuntu.com", "security.ubuntu.com"]:
        checks.append({
            "label": f"Systems Updates TCP 80 ({host})",
            "host": host, "port": 80, "type": "tcp",
        })

    # Sophos Antivirus – representative hostnames
    sophos_hosts = [
        "d1.sophosupd.com", "d1.sophosupd.net", "d1.sophosxl.net",
        "mcs.sophos.com", "ocsp2.globalsign.com", "crl.globalsign.com",
    ]
    for host in sophos_hosts:
        for port in [80, 443]:
            checks.append({
                "label": f"Antivirus TCP {port} ({host})",
                "host": host, "port": port, "type": "tcp",
            })

    return checks


async def run_all_checks(
    checks: List[dict],
    timeout: float = 10.0,
    progress_callback: Optional[Callable[[int, int], Awaitable[None]]] = None,
) -> List[CheckResult]:
    total = len(checks)
    results: List[CheckResult] = []

    async def _run_one(c: dict) -> CheckResult:
        if c["type"] == "icmp":
            return await check_icmp(c["host"], label=c["label"], timeout=timeout)
        return await check_tcp(c["host"], c["port"], label=c["label"], timeout=timeout)

    tasks = [asyncio.create_task(_run_one(c)) for c in checks]
    for i, coro in enumerate(asyncio.as_completed(tasks), 1):
        result = await coro
        results.append(result)
        if progress_callback:
            await progress_callback(i, total)

    return results
