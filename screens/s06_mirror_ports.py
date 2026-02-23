# screens/s06_mirror_ports.py
from textual.app import ComposeResult
from textual.screen import Screen
from textual.widgets import Footer, Button, Static, SelectionList
from widgets.asimily_header import AsimilyHeader
from textual.widgets.selection_list import Selection
from textual.containers import Vertical, Horizontal
from network.interfaces import list_interfaces
from logger import log


class MirrorPortsScreen(Screen):
    """Step 6: Multiselect mirror ports from remaining interfaces."""

    def compose(self) -> ComposeResult:
        yield AsimilyHeader()
        with Vertical(id="content"):
            yield Static("Step 6: Mirror Port Selection", classes="title")
            yield Static(
                "Select interfaces for mirrored/SPAN traffic (PCAP / traffic analysis).\n"
                "Use [bold]Space[/bold] to toggle, [bold]↑↓[/bold] to navigate."
            )
            yield Vertical(id="iface_list_container")
            yield Static("", id="err_msg")
        with Horizontal(id="nav_buttons"):
            yield Button("← Back", id="btn_back", variant="default")
            yield Button("Finish →", id="btn_next", variant="primary")
        yield Footer()

    async def on_mount(self) -> None:
        state = self.app.state
        ifaces = list_interfaces()
        candidates = [i for i in ifaces if i.name != state.mgmt_interface]
        container = self.query_one("#iface_list_container", Vertical)

        if candidates:
            selections = [
                Selection(
                    f"{i.name}  ({i.port_type} {i.speed_label})",
                    i.name,
                    initial_state=False,
                )
                for i in candidates
            ]
            await container.mount(SelectionList(*selections, id="mirror_list"))
        else:
            await container.mount(
                Static(
                    "[yellow]No additional interfaces available.[/yellow]",
                    id="no_ifaces_msg",
                )
            )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn_back":
            self.app.pop_screen()
        elif event.button.id == "btn_next":
            from textual.css.query import NoMatches
            try:
                sel_list = self.query_one("#mirror_list", SelectionList)
                selected = list(sel_list.selected)
            except NoMatches:
                selected = []
            self.app.state.mirror_interfaces = selected
            log.info("Step 6: mirror interfaces = %s", selected)
            from screens.s07_finish import FinishScreen
            self.app.push_screen(FinishScreen())
