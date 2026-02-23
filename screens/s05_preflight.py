# screens/s05_preflight.py
from __future__ import annotations
import asyncio
from textual.app import ComposeResult
from textual.screen import Screen
from textual.widgets import (
    Footer, Button, Static, ProgressBar,
    ListView, ListItem, Label, Input
)
from widgets.asimily_header import AsimilyHeader
from textual.containers import Vertical, Horizontal
from network.checks import build_check_matrix, run_all_checks, CheckResult
from logger import log

COUNTDOWN = 30


class PreflightScreen(Screen):
    """Step 5: Async pre-flight connectivity checks with 30-second timer."""

    def __init__(self) -> None:
        super().__init__()
        self._results: list[CheckResult] = []
        self._checks_done = False
        self._retry_shown = False

    def compose(self) -> ComposeResult:
        yield AsimilyHeader()
        with Vertical(id="content"):
            yield Static("Step 5: Pre-Flight Network Check", classes="title")
            yield Static(
                f"Running connectivity tests (up to {COUNTDOWN}s)…",
                id="status_msg",
            )
            yield ProgressBar(total=COUNTDOWN, id="timer_bar")
            yield Static("[bold]Elapsed:[/bold] 0s", id="timer_label")
            yield Static("", id="spinner")
            yield ListView(id="results_list")
            yield Static("", id="err_msg")
            yield Static("", id="retry_prompt")
        with Horizontal(id="nav_buttons"):
            yield Button("← Retry Network Config", id="btn_back",
                         variant="default", disabled=True)
            yield Button("Next →", id="btn_next",
                         variant="primary", disabled=True)
        yield Footer()

    async def on_mount(self) -> None:
        asyncio.create_task(self._run_checks())
        asyncio.create_task(self._run_timer())

    async def _run_timer(self) -> None:
        bar = self.query_one("#timer_bar", ProgressBar)
        label = self.query_one("#timer_label", Static)
        for elapsed in range(1, COUNTDOWN + 1):
            await asyncio.sleep(1)
            if self._checks_done:
                break
            bar.advance(1)
            label.update(f"[bold]Elapsed:[/bold] {elapsed}s")

    async def _run_checks(self) -> None:
        self._checks_done = False
        state = self.app.state
        checks = build_check_matrix(cloud_ip=state.cloud_ip)
        spinner_frames = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
        spinner_widget = self.query_one("#spinner", Static)
        frame_idx = 0

        async def progress_cb(done: int, total: int) -> None:
            nonlocal frame_idx
            spinner_widget.update(spinner_frames[frame_idx % len(spinner_frames)])
            frame_idx += 1

        self._results = await run_all_checks(
            checks, timeout=10, progress_callback=progress_cb
        )
        self._checks_done = True

        spinner_widget.update("")
        results_list = self.query_one("#results_list", ListView)
        results_list.clear()

        cloud_failed = False
        general_failed = False

        for r in self._results:
            icon = "[green]✓[/green]" if r.passed else "[red]✗[/red]"
            detail = f"  ({r.error})" if not r.passed else ""
            results_list.append(
                ListItem(Label(f"{icon} {r.label} ({r.target}){detail}"))
            )
            if not r.passed:
                if "Cloud Server" in r.label:
                    cloud_failed = True
                else:
                    general_failed = True

        passed = sum(1 for r in self._results if r.passed)
        log.info("Step 5: %d/%d checks passed", passed, len(self._results))

        err = self.query_one("#err_msg", Static)
        if cloud_failed and state.cloud_ip is not None:
            err.update(
                "[yellow]Cloud Server check failed. "
                "Enter a new IP below or skip:[/yellow]"
            )
            if not self._retry_shown:
                self._retry_shown = True
                await self._show_cloud_retry()
        elif general_failed:
            err.update(
                "[red]Some connectivity checks failed. "
                "Go back to fix network settings or proceed anyway.[/red]"
            )

        self.query_one("#btn_back").disabled = False
        self.query_one("#btn_next").disabled = False
        self.query_one("#status_msg", Static).update("Checks complete.")

    async def _show_cloud_retry(self) -> None:
        self.query_one("#retry_prompt", Static).update(
            "New Cloud Server IP (leave empty to skip):"
        )
        await self.mount(
            Input(placeholder="New Cloud IP or leave empty", id="inp_retry_ip"),
            after="#retry_prompt",
        )
        await self.mount(
            Button("Retry with new IP", id="btn_retry_ip", variant="warning"),
            after="#inp_retry_ip",
        )
        await self.mount(
            Button("Skip Cloud Check", id="btn_skip_cloud", variant="default"),
            after="#btn_retry_ip",
        )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn_back":
            self.app.pop_screen()
        elif event.button.id == "btn_next":
            from screens.s06_mirror_ports import MirrorPortsScreen
            self.app.push_screen(MirrorPortsScreen())
        elif event.button.id == "btn_retry_ip":
            inp = self.query_one("#inp_retry_ip", Input)
            new_ip = inp.value.strip()
            if new_ip:
                self.app.state.cloud_ip = new_ip
                log.info("Step 5: retrying with new cloud IP %s", new_ip)
            else:
                self.app.state.cloud_ip = None
                log.info("Step 5: empty retry IP – treating as skip")
            asyncio.create_task(self._run_checks())
        elif event.button.id == "btn_skip_cloud":
            self.app.state.cloud_ip = None
            log.info("Step 5: Cloud IP check skipped by user")
            asyncio.create_task(self._run_checks())
