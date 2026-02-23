# screens/s03_network_apply.py
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
    """Step 3: Apply network config via netplan try with 60-second rollback countdown."""

    BINDINGS = [("enter", "confirm_settings", "Confirm")]

    def __init__(self) -> None:
        super().__init__()
        self._netplan = NetplanManager()
        self._proc = None
        self._confirmed = False

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Vertical(id="content"):
            yield Static("Step 3: Applying Network Configuration", classes="title")
            yield Static("Preparing…", id="status_msg")
            yield Static(
                f"[bold]Time remaining to confirm:[/bold] {COUNTDOWN_SECONDS}s",
                id="countdown_label",
            )
            yield ProgressBar(total=COUNTDOWN_SECONDS, id="countdown_bar")
            yield Static(
                "Press [bold]ENTER[/bold] or click [bold]Confirm[/bold] to accept "
                "the new settings.\n"
                "If no action is taken, the old settings will be restored automatically."
            )
            yield Static("", id="err_msg")
        with Container(id="nav_buttons"):
            yield Button("✓ Confirm Settings", id="btn_confirm", variant="success",
                         disabled=True)
            yield Button("← Back to Config", id="btn_back", variant="default",
                         disabled=True)
        yield Footer()

    async def on_mount(self) -> None:
        asyncio.create_task(self._apply_and_countdown())

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
                nm.write_dhcp(
                    iface=state.mgmt_interface,
                    dns=state.dns_servers,
                    ntp=state.ntp_servers,
                )
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
            self.query_one("#btn_confirm").disabled = False

        except Exception as e:
            err.update(f"[red]Error applying config: {e}[/red]")
            self.query_one("#btn_back").disabled = False
            log.error("Step 3 apply failed: %s", e)
            return

        # 60-second countdown
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
            status.update(
                "[yellow]Timeout – rolling back to previous configuration.[/yellow]"
            )
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
        self._netplan.confirm_apply(self._proc)
        log.info("Step 3: network settings confirmed by user")
        self.query_one("#status_msg", Static).update(
            "[green]✓ Configuration confirmed and applied.[/green]"
        )
        self.query_one("#btn_confirm").disabled = True
        asyncio.create_task(self._advance())

    async def _advance(self) -> None:
        await asyncio.sleep(1.5)
        from screens.s04_cloud_ip import CloudIPScreen
        self.app.push_screen(CloudIPScreen())

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn_confirm":
            if not self._confirmed and self._proc:
                self._do_confirm()
        elif event.button.id == "btn_back":
            self.app.pop_screen()
