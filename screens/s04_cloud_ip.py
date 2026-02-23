# screens/s04_cloud_ip.py
from textual.app import ComposeResult
from textual.screen import Screen
from textual.widgets import Header, Footer, Button, Static, Input, Label
from textual.containers import Vertical, Horizontal
from validators import validate_ip
from logger import log


class CloudIPScreen(Screen):
    """Step 4: Optional Asimily Cloud Server IP."""

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Vertical(id="content"):
            yield Static("Step 4: Asimily Cloud Server IP (Optional)", classes="title")
            yield Static(
                "Enter the unique Asimily Cloud Server IP assigned to your site.\n"
                "Leave empty and click [bold]Skip[/bold] to configure later."
            )
            yield Label("Cloud Server IP Address:")
            yield Input(placeholder="e.g. 203.0.113.10", id="inp_cloud_ip")
            yield Static("", id="err_msg")
        with Horizontal(id="nav_buttons"):
            yield Button("← Back", id="btn_back", variant="default")
            yield Button("Skip →", id="btn_skip", variant="warning")
            yield Button("Next →", id="btn_next", variant="primary")
        yield Footer()

    def _go_next(self) -> None:
        from screens.s05_preflight import PreflightScreen
        self.app.push_screen(PreflightScreen())

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn_back":
            self.app.pop_screen()

        elif event.button.id == "btn_skip":
            self.app.state.cloud_ip = None
            log.info("Step 4: Cloud IP skipped by user")
            self._go_next()

        elif event.button.id == "btn_next":
            ip = self.query_one("#inp_cloud_ip", Input).value.strip()
            if not ip:
                self.app.state.cloud_ip = None
                log.info("Step 4: Cloud IP left empty – treated as skip")
                self._go_next()
                return
            ok, msg = validate_ip(ip)
            if not ok:
                self.query_one("#err_msg", Static).update(f"[red]{msg}[/red]")
                return
            self.app.state.cloud_ip = ip
            log.info("Step 4: Cloud IP set to %s", ip)
            self._go_next()
