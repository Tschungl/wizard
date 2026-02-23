# app.py
from textual.app import App
from state import WizardState
from logger import log

class AsimilyWizard(App):
    """Asimily First Time Setup Wizard."""

    CSS = """
    Screen { background: $surface; }
    .title { text-style: bold; color: $accent; }
    """

    def __init__(self):
        super().__init__()
        self.state = WizardState()
        log.info("AsimilyWizard started")

    def on_mount(self) -> None:
        from screens.s01_welcome import WelcomeScreen
        self.push_screen(WelcomeScreen())
