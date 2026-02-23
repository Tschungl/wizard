# screens/s03_network_apply.py
from __future__ import annotations
import asyncio
from textual.app import ComposeResult
from textual.screen import Screen
from textual.widgets import Footer, Button, Static, ProgressBar
from textual.containers import Container, Vertical
from widgets.asimily_header import AsimilyHeader
from network.netplan import NetplanManager
from network.interfaces import async_iface_status
from logger import log

COUNTDOWN_SECONDS = 60


class NetworkApplyScreen(Screen):
    """Step 3: Apply network config via netplan try with 60-second rollback countdown."""

    BINDINGS = [
        ("enter", "confirm_settings", "Confirm"),
        ("escape", "cancel_and_back", "Cancel"),
    ]

    def __init__(self) -> None:
        super().__init__()
        self._netplan = NetplanManager()
        self._proc = None
        self._confirmed = False
        self._cancelled = False
        self._timed_out = False

    def compose(self) -> ComposeResult:
        yield AsimilyHeader()
        with Vertical(id="content"):
            yield Static("Step 3: Applying Network Configuration", classes="title")
            yield Static("Preparing…", id="status_msg")
            yield Static("", id="iface_status")
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
            yield Button("✗ Cancel / Back", id="btn_back", variant="warning")
        yield Footer()

    async def on_mount(self) -> None:
        asyncio.create_task(self._apply_and_countdown())

    async def _apply_and_countdown(self) -> None:
        state = self.app.state
        nm = self._netplan
        status = self.query_one("#status_msg", Static)
        err = self.query_one("#err_msg", Static)

        loop = asyncio.get_running_loop()
        try:
            status.update("Backing up existing configuration…")
            await loop.run_in_executor(None, nm.backup)

            status.update("Writing new Netplan configuration…")
            if state.use_dhcp:
                await loop.run_in_executor(
                    None,
                    lambda: nm.write_dhcp(
                        iface=state.mgmt_interface,
                        dns=state.dns_servers,
                        ntp=state.ntp_servers,
                    )
                )
            else:
                await loop.run_in_executor(
                    None,
                    lambda: nm.write_static(
                        iface=state.mgmt_interface,
                        ip_cidr=f"{state.ip_address}/{state.prefix_len}",
                        gateway=state.gateway,
                        dns=state.dns_servers,
                        ntp=state.ntp_servers,
                    )
                )

            status.update("Applying with 'netplan try'… waiting for confirmation.")
            self._proc = await loop.run_in_executor(
                None, lambda: nm.apply_try(timeout=COUNTDOWN_SECONDS)
            )
            self.query_one("#btn_confirm").disabled = False

        except Exception as e:
            err.update(f"[red]Error applying config: {e}[/red]")
            log.error("Step 3 apply failed: %s", e)
            return

        # start live-status polling (separate task)
        asyncio.create_task(self._poll_iface_status())

        # 60-second countdown
        bar = self.query_one("#countdown_bar", ProgressBar)
        label = self.query_one("#countdown_label", Static)
        for remaining in range(COUNTDOWN_SECONDS, 0, -1):
            if self._confirmed or self._cancelled:
                break
            label.update(f"[bold]Time remaining to confirm:[/bold] {remaining}s")
            bar.advance(1)
            await asyncio.sleep(1)

        if not self._confirmed and not self._cancelled:
            self._timed_out = True
            self.query_one("#btn_confirm").disabled = True
            log.info("Step 3: countdown expired – netplan will auto-rollback")
            status.update(
                "[yellow]Timeout – rolling back to previous configuration.[/yellow]"
            )
            loop = asyncio.get_running_loop()
            try:
                await loop.run_in_executor(
                    None, lambda: self._proc.wait(timeout=5)
                )
            except Exception:
                pass

    async def _poll_iface_status(self) -> None:
        """Poll interface state every 2 s and update #iface_status."""
        iface = self.app.state.mgmt_interface
        widget = self.query_one("#iface_status", Static)
        while not self._confirmed and not self._cancelled and not self._timed_out:
            operstate, ips = await async_iface_status(iface)
            ip_str = ", ".join(ips) if ips else "—"
            color = "green" if operstate == "up" else "yellow"
            widget.update(
                f"[{color}]Interface {iface}: {operstate.upper()}  "
                f"IP: {ip_str}[/{color}]"
            )
            if self._confirmed or self._cancelled or self._timed_out:
                break
            await asyncio.sleep(2)

    def action_confirm_settings(self) -> None:
        if not self._confirmed and not self._cancelled and not self._timed_out and self._proc:
            self._do_confirm()

    def action_cancel_and_back(self) -> None:
        if self._confirmed or self._timed_out:
            self.app.pop_screen()
        elif not self._cancelled:
            asyncio.create_task(self._cancel_and_back())

    def _do_confirm(self) -> None:
        self._confirmed = True
        self._netplan.confirm_apply(self._proc)
        log.info("Step 3: network settings confirmed by user")
        self.query_one("#status_msg", Static).update(
            "[green]✓ Configuration confirmed and applied.[/green]"
        )
        self.query_one("#btn_confirm").disabled = True
        asyncio.create_task(self._advance())

    async def _cancel_and_back(self) -> None:
        """Kill netplan try (triggers rollback), then return to Step 2."""
        if self._cancelled:
            return
        self._cancelled = True
        log.info("Step 3: user cancelled – forcing netplan rollback")
        if self._proc and self._proc.returncode is None:
            try:
                self._proc.kill()
            except OSError:
                pass
            loop = asyncio.get_running_loop()
            try:
                await loop.run_in_executor(None, lambda: self._proc.wait(timeout=3))
            except Exception:
                pass
        self.app.pop_screen()

    async def _advance(self) -> None:
        await asyncio.sleep(1.5)
        from screens.s04_cloud_ip import CloudIPScreen
        self.app.push_screen(CloudIPScreen())

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn_confirm":
            if not self._confirmed and not self._cancelled and not self._timed_out and self._proc:
                self._do_confirm()
        elif event.button.id == "btn_back":
            if self._timed_out or self._confirmed:
                self.app.pop_screen()
            elif not self._cancelled:
                asyncio.create_task(self._cancel_and_back())
