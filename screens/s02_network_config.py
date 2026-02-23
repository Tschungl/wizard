# screens/s02_network_config.py
from __future__ import annotations
from textual.app import ComposeResult
from textual.screen import Screen
from textual.widgets import (
    Footer, Button, Static, Select,
    Input, Checkbox, Label
)
from widgets.asimily_header import AsimilyHeader
from textual.containers import Vertical, Horizontal, VerticalScroll
from network.interfaces import list_interfaces
from validators import validate_ip, validate_prefix, validate_gateway_in_subnet, validate_dns
from logger import log


class NetworkConfigScreen(Screen):
    """Step 2: Select management interface and configure IP settings."""

    BINDINGS = [
        ("escape", "go_back", "Back"),
    ]

    def compose(self) -> ComposeResult:
        ifaces = list_interfaces()
        iface_options = [(i.display_str(), i.name) for i in ifaces]

        yield AsimilyHeader()
        with VerticalScroll(id="form"):
            yield Static("Step 2: Management Port Configuration", classes="title")
            yield Label("Select Management Interface:")
            yield Select(options=iface_options, id="sel_iface", prompt="Choose interface…")
            yield Checkbox("Use DHCP", id="chk_dhcp", value=False)
            with Vertical(id="static_fields"):
                yield Label("IP Address:")
                yield Input(placeholder="e.g. 192.168.1.100", id="inp_ip")
                yield Label("Subnet Prefix Length (e.g. 24):")
                yield Input(placeholder="24", id="inp_prefix")
                yield Label("Default Gateway:")
                yield Input(placeholder="e.g. 192.168.1.1", id="inp_gw")
            yield Label("DNS Servers (comma-separated):")
            yield Input(placeholder="8.8.8.8, 8.8.4.4", id="inp_dns")
            yield Label("NTP Servers (comma-separated):")
            yield Input(placeholder="pool.ntp.org", id="inp_ntp")
            yield Checkbox("Use HTTP & HTTPS Proxy", id="chk_proxy", value=False)
            with Vertical(id="proxy_fields"):
                yield Label("Proxy Host / IP:")
                yield Input(id="inp_proxy_host")
                yield Label("Proxy Port:")
                yield Input(id="inp_proxy_port")
                yield Label("Proxy Username:")
                yield Input(id="inp_proxy_user")
                yield Label("Proxy Password:")
                yield Input(id="inp_proxy_pass", password=True)
            yield Static("", id="err_msg")
        with Horizontal(id="nav_buttons"):
            yield Button("← Back", id="btn_back", variant="default")
            yield Button("Skip (keep current settings) →", id="btn_skip", variant="default")
            yield Button("Apply →", id="btn_next", variant="primary")
        yield Footer()

    def on_mount(self) -> None:
        # Hide proxy fields initially
        self.query_one("#proxy_fields").display = False

    def on_screen_resume(self) -> None:
        """Refresh the interface Select whenever s02 becomes active again."""
        sel = self.query_one("#sel_iface", Select)
        previous_value = sel.value  # capture before set_options() resets it
        ifaces = list_interfaces()
        new_options = [(i.display_str(), i.name) for i in ifaces]
        sel.set_options(new_options)
        if previous_value is not Select.BLANK:
            valid_values = {i.name for i in ifaces}
            if previous_value in valid_values:
                sel.value = previous_value
        log.info("Step 2 resume: refreshed %d interfaces in Select", len(ifaces))

    def on_checkbox_changed(self, event: Checkbox.Changed) -> None:
        if event.checkbox.id == "chk_dhcp":
            self.query_one("#static_fields").display = not event.value
        elif event.checkbox.id == "chk_proxy":
            self.query_one("#proxy_fields").display = event.value

    def _collect_and_validate(self) -> bool:
        state = self.app.state
        iface_sel = self.query_one("#sel_iface", Select)
        if iface_sel.value is Select.BLANK:
            self._show_error("Please select a management interface.")
            return False
        state.mgmt_interface = str(iface_sel.value)
        state.use_dhcp = self.query_one("#chk_dhcp", Checkbox).value

        if not state.use_dhcp:
            ip = self.query_one("#inp_ip", Input).value.strip()
            prefix_str = self.query_one("#inp_prefix", Input).value.strip()
            gw = self.query_one("#inp_gw", Input).value.strip()

            try:
                prefix = int(prefix_str)
            except ValueError:
                self._show_error("Prefix length must be a number (e.g. 24).")
                return False

            ok, msg = validate_prefix(prefix)
            if not ok:
                self._show_error(msg)
                return False

            ok, msg = validate_ip(ip, prefix_len=prefix)
            if not ok:
                self._show_error(msg)
                return False

            ok, msg = validate_gateway_in_subnet(gw, ip, prefix)
            if not ok:
                self._show_error(msg)
                return False

            state.ip_address = ip
            state.prefix_len = prefix
            state.gateway = gw

        dns_raw = self.query_one("#inp_dns", Input).value.strip()
        if dns_raw:
            dns_list = [s.strip() for s in dns_raw.split(",") if s.strip()]
            for d in dns_list:
                ok, msg = validate_dns(d)
                if not ok:
                    self._show_error(msg)
                    return False
            state.dns_servers = dns_list
        else:
            state.dns_servers = []

        ntp_raw = self.query_one("#inp_ntp", Input).value.strip()
        state.ntp_servers = [s.strip() for s in ntp_raw.split(",") if s.strip()]

        state.proxy_enabled = self.query_one("#chk_proxy", Checkbox).value
        if state.proxy_enabled:
            state.proxy_host = self.query_one("#inp_proxy_host", Input).value.strip()
            port_str = self.query_one("#inp_proxy_port", Input).value.strip()
            try:
                state.proxy_port = int(port_str)
            except ValueError:
                self._show_error("Proxy port must be a number.")
                return False
            state.proxy_user = self.query_one("#inp_proxy_user", Input).value.strip()
            state.proxy_password = self.query_one("#inp_proxy_pass", Input).value

        if state.use_dhcp:
            log.info(
                "Step 2: config – iface=%s dhcp=True dns=%s",
                state.mgmt_interface, state.dns_servers,
            )
        else:
            log.info(
                "Step 2: config – iface=%s dhcp=False ip=%s/%s gw=%s dns=%s",
                state.mgmt_interface, state.ip_address,
                state.prefix_len, state.gateway, state.dns_servers,
            )
        return True

    def _show_error(self, msg: str) -> None:
        self.query_one("#err_msg", Static).update(f"[red]Error: {msg}[/red]")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn_back":
            self.app.pop_screen()
        elif event.button.id == "btn_skip":
            log.info("Step 2: skipped by user – keeping existing network config")
            from screens.s04_cloud_ip import CloudIPScreen
            self.app.push_screen(CloudIPScreen())
        elif event.button.id == "btn_next":
            if self._collect_and_validate():
                from screens.s03_network_apply import NetworkApplyScreen
                self.app.push_screen(NetworkApplyScreen())

    def action_go_back(self) -> None:
        self.app.pop_screen()
