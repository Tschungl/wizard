# screens/s07_finish.py
from __future__ import annotations
import asyncio
import json
from pathlib import Path
from textual.app import ComposeResult
from textual.screen import Screen
from textual.widgets import Button, Footer, Header, Static
from textual.containers import Vertical
from network.netplan import NetplanManager
from logger import log

INSTALL_SCRIPT = "/opt/asimily/install.sh"
CONFIG_PATH = Path("/etc/asimily/wizard_config.json")


class FinishScreen(Screen):
    """Step 7: Configuration summary, config export, install.sh launcher."""

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Vertical(id="content"):
            yield Static("Step 7: Configuration Complete", classes="title")
            yield Static("", id="summary")
            yield Static("", id="status_msg")
        with Vertical(id="nav_buttons"):
            yield Button("← Back", id="btn_back", variant="default")
            yield Button("▶ Start Installation", id="btn_install", variant="success")
        yield Footer()

    async def on_mount(self) -> None:
        state = self.app.state
        summary = self._build_summary(state)
        self.query_one("#summary", Static).update(summary)

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
        lines.append(
            f"  DNS                  : {', '.join(state.dns_servers) or '—'}"
        )
        lines.append(
            f"  NTP                  : {', '.join(state.ntp_servers) or '—'}"
        )
        lines.append(f"  Proxy                : {'Yes' if state.proxy_enabled else 'No'}")
        lines.append(f"  Cloud Server IP      : {state.cloud_ip or '(skipped)'}")
        lines.append(
            f"  Mirror Interfaces    : {', '.join(state.mirror_interfaces) or '—'}"
        )
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

        # Write config JSON
        try:
            CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
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
            CONFIG_PATH.write_text(json.dumps(config_data, indent=2))
            log.info("Config written to %s", CONFIG_PATH)
        except OSError as e:
            log.error("Failed to write config: %s", e)
            status.update(f"[red]Failed to write config: {e}[/red]")
            self.query_one("#btn_install", Button).disabled = False
            return

        # Apply NTP and proxy settings now that config is confirmed
        nm = NetplanManager()
        if state.ntp_servers:
            try:
                nm.apply_ntp(state.ntp_servers)
            except OSError as e:
                log.warning("Failed to write NTP config: %s", e)
        if state.proxy_enabled and state.proxy_host:
            try:
                nm.apply_proxy(
                    state.proxy_host,
                    state.proxy_port,
                    state.proxy_user,
                    state.proxy_password,
                )
            except OSError as e:
                log.warning("Failed to write proxy config: %s", e)

        # Check install script exists
        install = Path(INSTALL_SCRIPT)
        if not install.exists():
            log.warning("Install script not found at %s", INSTALL_SCRIPT)
            status.update(
                f"[yellow]Warning: {INSTALL_SCRIPT} not found. "
                "Configuration saved to /etc/asimily/wizard_config.json.[/yellow]"
            )
            return

        log.info("Launching %s", INSTALL_SCRIPT)
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
                status.update(
                    "[green]✓ Installation completed. The wizard will now exit.[/green]"
                )
                await asyncio.sleep(3)
                self.app.exit()
            else:
                log.error("install.sh exited with code %d", proc.returncode)
                status.update(
                    f"[red]install.sh failed (exit {proc.returncode}). "
                    "Check /var/log/asimily_wizard.log[/red]"
                )
        except Exception as e:
            log.error("Failed to launch install.sh: %s", e)
            status.update(f"[red]Error: {e}[/red]")
