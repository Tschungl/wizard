# screens/s01_welcome.py
from textual.app import ComposeResult
from textual.screen import Screen
from textual.widgets import Footer, Button, Static, DataTable
from widgets.asimily_header import AsimilyHeader
from textual.containers import Container, Vertical
from network.interfaces import list_interfaces
from logger import log

class WelcomeScreen(Screen):
    """Step 1: Welcome screen showing all network interfaces."""

    BINDINGS = [("n", "next_step", "Next")]

    def compose(self) -> ComposeResult:
        yield AsimilyHeader()
        with Vertical(id="content"):
            yield Static("Detected Network Interfaces", classes="title")
            yield DataTable(id="iface_table")
            yield Static(
                "Press [bold]N[/bold] or click [bold]Next[/bold] to continue."
            )
        with Container(id="footer_buttons"):
            yield Button("Next →", id="btn_next", variant="primary")
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one("#iface_table", DataTable)
        table.add_columns("Interface", "Type", "Speed", "State", "MAC", "IP Addresses")
        ifaces = list_interfaces()
        log.info("Step 1: Found %d interfaces", len(ifaces))
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
