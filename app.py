# app.py
from textual.app import App
from state import WizardState
from logger import log


class AsimilyWizard(App):
    """Asimily First Time Setup Wizard."""

    CSS = """
    Screen {
        background: $surface;
    }
    .title {
        text-style: bold;
        color: $accent;
        margin-bottom: 1;
    }
    .hidden {
        display: none;
    }
    #banner {
        color: $primary;
        margin: 1 2;
    }
    #content {
        margin: 1 2;
    }
    #form {
        margin: 1 2;
    }
    #nav_buttons {
        dock: bottom;
        height: 3;
        align: center middle;
        margin: 1 2;
    }
    #footer_buttons {
        dock: bottom;
        height: 3;
        align: center middle;
    }
    Button {
        margin: 0 1;
    }
    #err_msg {
        margin-top: 1;
        color: $error;
    }
    DataTable {
        height: 12;
    }
    ListView {
        height: 20;
        border: solid $primary;
    }
    SelectionList {
        height: 15;
        border: solid $primary;
    }
    Input {
        margin-bottom: 1;
    }
    #countdown_label, #timer_label {
        margin-top: 1;
    }
    ProgressBar {
        margin: 1 0;
    }
    """

    def __init__(self) -> None:
        super().__init__()
        self.state = WizardState()
        log.info("AsimilyWizard started")

    async def on_mount(self) -> None:
        from screens.s01_welcome import WelcomeScreen
        await self.push_screen(WelcomeScreen())
