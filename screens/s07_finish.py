# screens/s07_finish.py
from __future__ import annotations
import asyncio
import json
import sys
from pathlib import Path
from textual.app import ComposeResult
from textual.screen import Screen
from textual.widgets import Button, Footer, Static
from textual.containers import Vertical, Horizontal
from widgets.asimily_header import AsimilyHeader
from network.netplan import NetplanManager
from logger import log

INSTALL_SCRIPT = "/opt/asimily/install.sh"
CONFIG_PATH = Path("/etc/asimily/wizard_config.json")


class FinishScreen(Screen):
    """Step 7: Configuration summary, config export, install.sh launcher."""

    def compose(self) -> ComposeResult:
        yield AsimilyHeader()
        with Vertical(id="content"):
            yield Static("Step 7: Configuration Complete", classes="title")
            yield Static("", id="summary")
            # Mirror ports in their own highlighted box
            with Vertical(id="mirror_box"):
                yield Static("Configured Mirror Interfaces", id="mirror_box_title")
                yield Static("", id="mirror_iface_list")
            yield Static("", id="status_msg")
        with Horizontal(id="nav_buttons"):
            yield Button("← Back", id="btn_back", variant="default")
            yield Button("✓ Finish & Exit", id="btn_finish", variant="success")
        yield Footer()

    async def on_mount(self) -> None:
        state = self.app.state
        self.query_one("#summary", Static).update(self._build_summary(state))
        # Populate mirror box
        if state.mirror_interfaces:
            lines = "\n".join(
                f"  [bold green]▶ {iface}[/bold green]"
                for iface in state.mirror_interfaces
            )
        else:
            lines = "  [dim]No mirror interfaces selected[/dim]"
        self.query_one("#mirror_iface_list", Static).update(lines)

    def _build_summary(self, state) -> str:
        lines = ["[bold]Configuration Summary[/bold]\n"]
        lines.append(f"  Management Interface : [cyan]{state.mgmt_interface}[/cyan]")
        if state.use_dhcp:
            lines.append("  IP Assignment        : DHCP")
        else:
            lines.append(
                f"  IP Address           : {state.ip_address}/{state.prefix_len}"
            )
            lines.append(f"  Gateway              : {state.gateway}")
        lines.append(f"  DNS                  : {', '.join(state.dns_servers) or '—'}")
        lines.append(f"  NTP                  : {', '.join(state.ntp_servers) or '—'}")
        lines.append(f"  Proxy                : {'Yes' if state.proxy_enabled else 'No'}")
        lines.append(f"  Cloud Server IP      : {state.cloud_ip or '(skipped)'}")
        return "\n".join(lines)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn_back":
            self.app.pop_screen()
        elif event.button.id == "btn_finish":
            event.button.disabled = True
            asyncio.create_task(self._finish_and_exit())

    async def _finish_and_exit(self) -> None:
        status = self.query_one("#status_msg", Static)
        state = self.app.state

        try:
            # Write config JSON
            loop = asyncio.get_running_loop()
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
            payload = json.dumps(config_data, indent=2)
            try:
                await loop.run_in_executor(
                    None,
                    lambda: (
                        CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True),
                        CONFIG_PATH.write_text(payload),
                    )
                )
                log.info("Config written to %s", CONFIG_PATH)
            except OSError as e:
                log.error("Failed to write config: %s", e)
                status.update(f"[red]Failed to write config: {e}[/red]")
                self.query_one("#btn_finish", Button).disabled = False
                return

            # Apply NTP and proxy settings
            nm = NetplanManager()
            if state.ntp_servers:
                try:
                    await loop.run_in_executor(None, lambda: nm.apply_ntp(state.ntp_servers))
                except OSError as e:
                    log.warning("Failed to write NTP config: %s", e)
            if state.proxy_enabled and state.proxy_host:
                try:
                    await loop.run_in_executor(
                        None,
                        lambda: nm.apply_proxy(
                            state.proxy_host, state.proxy_port,
                            state.proxy_user, state.proxy_password,
                        )
                    )
                except OSError as e:
                    log.warning("Failed to write proxy config: %s", e)

            # Fire-and-forget install.sh if present
            install = Path(INSTALL_SCRIPT)
            if install.exists():
                log.info("Launching %s (fire and forget)", INSTALL_SCRIPT)
                status.update(f"[cyan]Launching {INSTALL_SCRIPT}…[/cyan]")
                try:
                    await asyncio.create_subprocess_exec(
                        "bash", INSTALL_SCRIPT,
                        stdout=asyncio.subprocess.DEVNULL,
                        stderr=asyncio.subprocess.DEVNULL,
                        start_new_session=True,
                    )
                except Exception as e:
                    log.error("Failed to launch install.sh: %s", e)
            else:
                log.info("install.sh not found at %s – skipping", INSTALL_SCRIPT)
                status.update(
                    "[yellow]Installation script not found. Configuration saved.[/yellow]"
                )

            await asyncio.sleep(1)
            log.info("Wizard complete – exiting")
            self.app.exit()

        except Exception as e:
            log.error("Unexpected error in _finish_and_exit: %s", e)
            status.update(f"[red]Unexpected error: {e}[/red]")
            self.query_one("#btn_finish", Button).disabled = False
