# tests/test_wizard_e2e.py
"""
End-to-end headless Pilot tests for the Asimily wizard.

All system interactions (netplan, ip, filesystem) are mocked so that
the tests run without root privileges and without touching the host.
"""
from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from textual.widgets import Button, DataTable, Select, Input, Checkbox

from network.interfaces import InterfaceInfo


# ---------------------------------------------------------------------------
# Test data
# ---------------------------------------------------------------------------

FAKE_IFACES = [
    InterfaceInfo(
        name="eno1",
        operstate="up",
        link_speed_mbps=1000,
        port_type="RJ45",
        mac="00:11:22:33:44:55",
        ip_addresses=["192.168.1.10/24"],
    ),
    InterfaceInfo(
        name="eno2",
        operstate="down",
        link_speed_mbps=1000,
        port_type="RJ45",
        mac="00:11:22:33:44:66",
        ip_addresses=[],
    ),
]


class MockProc:
    """Fake subprocess.Popen returned by NetplanManager.apply_try."""
    returncode = None
    stdin = MagicMock()

    def kill(self):
        self.returncode = -9

    def wait(self, timeout=None):
        return 0


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _all_patches():
    """Return a list of patch context managers for all system calls."""
    mock_proc = MockProc()
    return [
        patch("network.interfaces.list_interfaces", return_value=FAKE_IFACES),
        patch(
            "network.interfaces.async_iface_status",
            new=AsyncMock(return_value=("up", ["192.168.1.10/24"])),
        ),
        patch("network.netplan.NetplanManager.backup"),
        patch("network.netplan.NetplanManager.write_static"),
        patch("network.netplan.NetplanManager.write_dhcp"),
        patch("network.netplan.NetplanManager.apply_try", return_value=mock_proc),
        patch("network.netplan.NetplanManager.confirm_apply"),
        patch("network.netplan.NetplanManager.apply_ntp"),
        patch("network.netplan.NetplanManager.apply_proxy"),
        patch("network.netplan.NetplanManager.write_mirror_ports"),
        patch("network.netplan.NetplanManager.configure_mirror_promisc"),
        patch("network.checks.run_all_checks", new=AsyncMock(return_value=[])),
        # s07 filesystem writes
        patch("screens.s07_finish.CONFIG_PATH",
              new_callable=lambda: type("FakePath", (), {
                  "parent": type("FakeParent", (), {
                      "mkdir": MagicMock()})(),
                  "write_text": MagicMock(),
              })()),
        patch("pathlib.Path.exists", return_value=False),
        patch("asyncio.create_subprocess_exec", new=AsyncMock()),
    ]


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_s01_welcome_shows_interface_table():
    """Screen 1 should render the interface DataTable with rows."""
    from app import AsimilyWizard

    with patch("network.interfaces.list_interfaces", return_value=FAKE_IFACES):
        app = AsimilyWizard()
        async with app.run_test(headless=True, size=(120, 40)) as pilot:
            await pilot.pause(0.5)

            screen = pilot.app.screen
            assert type(screen).__name__ == "WelcomeScreen", (
                f"Expected WelcomeScreen, got {type(screen).__name__}"
            )

            table = screen.query_one("#iface_table", DataTable)
            assert table.row_count == len(FAKE_IFACES), (
                f"Expected {len(FAKE_IFACES)} rows, got {table.row_count}"
            )


@pytest.mark.asyncio
async def test_s01_next_pushes_s02():
    """Clicking Next on s01 should push NetworkConfigScreen."""
    from app import AsimilyWizard

    with patch("network.interfaces.list_interfaces", return_value=FAKE_IFACES):
        app = AsimilyWizard()
        async with app.run_test(headless=True, size=(120, 40)) as pilot:
            await pilot.pause(0.3)
            assert type(pilot.app.screen).__name__ == "WelcomeScreen"

            await pilot.click("#btn_next")
            await pilot.pause(0.3)

            assert type(pilot.app.screen).__name__ == "NetworkConfigScreen", (
                f"Expected NetworkConfigScreen, got {type(pilot.app.screen).__name__}"
            )


@pytest.mark.asyncio
async def test_s02_validation_requires_interface_selection():
    """Clicking Apply without selecting an interface should show an error."""
    from app import AsimilyWizard

    with patch("network.interfaces.list_interfaces", return_value=FAKE_IFACES):
        app = AsimilyWizard()
        async with app.run_test(headless=True, size=(120, 40)) as pilot:
            await pilot.pause(0.3)
            await pilot.click("#btn_next")   # go to s02
            await pilot.pause(0.3)

            # Click Apply without selecting anything
            await pilot.click("#btn_next")
            await pilot.pause(0.2)

            from textual.widgets import Static
            err = pilot.app.screen.query_one("#err_msg", Static)
            content = str(err._Static__content)
            assert content != "", (
                "Expected error message for missing interface selection"
            )


@pytest.mark.asyncio
async def test_s02_back_returns_to_s01():
    """Back button on s02 should return to WelcomeScreen."""
    from app import AsimilyWizard

    with patch("network.interfaces.list_interfaces", return_value=FAKE_IFACES):
        app = AsimilyWizard()
        async with app.run_test(headless=True, size=(120, 40)) as pilot:
            await pilot.pause(0.3)
            await pilot.click("#btn_next")   # go to s02
            await pilot.pause(0.3)

            assert type(pilot.app.screen).__name__ == "NetworkConfigScreen"
            await pilot.click("#btn_back")
            await pilot.pause(0.3)

            assert type(pilot.app.screen).__name__ == "WelcomeScreen"


@pytest.mark.asyncio
async def test_s02_dhcp_hides_static_fields():
    """Checking DHCP should hide the static IP fields."""
    from app import AsimilyWizard

    with patch("network.interfaces.list_interfaces", return_value=FAKE_IFACES):
        app = AsimilyWizard()
        async with app.run_test(headless=True, size=(120, 40)) as pilot:
            await pilot.pause(0.3)
            await pilot.click("#btn_next")  # go to s02
            await pilot.pause(0.3)

            static_fields = pilot.app.screen.query_one("#static_fields")
            assert static_fields.display is True, "static_fields should be visible by default"

            # Toggle DHCP on
            await pilot.click("#chk_dhcp")
            await pilot.pause(0.2)

            assert static_fields.display is False, (
                "static_fields should be hidden when DHCP is checked"
            )


@pytest.mark.asyncio
async def test_s04_skip_sets_cloud_ip_none():
    """Skip button on s04 should set cloud_ip to None and advance to s05."""
    from app import AsimilyWizard

    patches = _all_patches()
    with patches[0]:  # list_interfaces
      with patches[1]:  # async_iface_status
       with patches[2]:  # backup
        with patches[3]:  # write_static
         with patches[4]:  # write_dhcp
          with patches[5]:  # apply_try
           with patches[6]:  # confirm_apply
            with patches[11]:  # run_all_checks

                app = AsimilyWizard()
                async with app.run_test(headless=True, size=(120, 40)) as pilot:
                    await pilot.pause(0.3)

                    # s01 → s02
                    await pilot.click("#btn_next")
                    await pilot.pause(0.3)

                    # s02: use DHCP (simplest path), select interface
                    screen = pilot.app.screen
                    sel = screen.query_one("#sel_iface", Select)
                    sel.value = "eno1"
                    await pilot.pause(0.1)

                    chk_dhcp = screen.query_one("#chk_dhcp", Checkbox)
                    if not chk_dhcp.value:
                        await pilot.click("#chk_dhcp")
                    await pilot.pause(0.1)

                    await pilot.click("#btn_next")  # Apply → pushes s03
                    await pilot.pause(0.5)

                    assert type(pilot.app.screen).__name__ == "NetworkApplyScreen", (
                        f"Expected NetworkApplyScreen, got {type(pilot.app.screen).__name__}"
                    )

                    # s03: wait for btn_confirm to become enabled, then click it
                    for _ in range(20):
                        btn = pilot.app.screen.query_one("#btn_confirm", Button)
                        if not btn.disabled:
                            break
                        await pilot.pause(0.1)
                    else:
                        pytest.fail("btn_confirm never became enabled in s03")

                    await pilot.click("#btn_confirm")
                    await pilot.pause(2.0)  # _advance sleeps 1.5s

                    assert type(pilot.app.screen).__name__ == "CloudIPScreen", (
                        f"Expected CloudIPScreen, got {type(pilot.app.screen).__name__}"
                    )

                    # s04: skip
                    await pilot.click("#btn_skip")
                    await pilot.pause(0.3)

                    assert pilot.app.state.cloud_ip is None
                    assert type(pilot.app.screen).__name__ == "PreflightScreen", (
                        f"Expected PreflightScreen, got {type(pilot.app.screen).__name__}"
                    )


@pytest.mark.asyncio
async def test_s05_next_leads_to_s06():
    """After preflight checks complete, Next should push MirrorPortsScreen."""
    from app import AsimilyWizard

    patches = _all_patches()
    with patches[0]:
      with patches[1]:
       with patches[2]:
        with patches[3]:
         with patches[4]:
          with patches[5]:
           with patches[6]:
            with patches[11]:  # run_all_checks

                app = AsimilyWizard()
                async with app.run_test(headless=True, size=(120, 40)) as pilot:
                    await pilot.pause(0.3)

                    # Navigate to s05
                    # s01 → s02
                    await pilot.click("#btn_next")
                    await pilot.pause(0.3)

                    screen = pilot.app.screen
                    screen.query_one("#sel_iface", Select).value = "eno1"
                    chk = screen.query_one("#chk_dhcp", Checkbox)
                    if not chk.value:
                        await pilot.click("#chk_dhcp")
                    await pilot.pause(0.1)
                    await pilot.click("#btn_next")
                    await pilot.pause(0.5)

                    # s03: wait and confirm
                    for _ in range(20):
                        btn = pilot.app.screen.query_one("#btn_confirm", Button)
                        if not btn.disabled:
                            break
                        await pilot.pause(0.1)
                    await pilot.click("#btn_confirm")
                    await pilot.pause(2.0)

                    # s04: skip
                    await pilot.click("#btn_skip")
                    await pilot.pause(0.3)

                    # s05: wait for checks to complete and Next to be enabled
                    for _ in range(30):
                        btn_next = pilot.app.screen.query_one("#btn_next", Button)
                        if not btn_next.disabled:
                            break
                        await pilot.pause(0.2)
                    else:
                        pytest.fail("btn_next on s05 never became enabled")

                    await pilot.click("#btn_next")
                    await pilot.pause(0.3)

                    assert type(pilot.app.screen).__name__ == "MirrorPortsScreen", (
                        f"Expected MirrorPortsScreen, got {type(pilot.app.screen).__name__}"
                    )


@pytest.mark.asyncio
async def test_s06_no_selection_goes_to_s07():
    """With no mirrors selected, Finish → should push FinishScreen."""
    from app import AsimilyWizard

    all_p = _all_patches()
    with all_p[0]:   # list_interfaces
     with all_p[1]:  # async_iface_status
      with all_p[2]:  # backup
       with all_p[3]:  # write_static
        with all_p[4]:  # write_dhcp
         with all_p[5]:  # apply_try
          with all_p[6]:  # confirm_apply
           with all_p[11]:  # run_all_checks
            with all_p[9]:  # write_mirror_ports
             with all_p[10]:  # configure_mirror_promisc

                app = AsimilyWizard()
                async with app.run_test(headless=True, size=(120, 40)) as pilot:
                    await pilot.pause(0.3)

                    # s01→s02
                    await pilot.click("#btn_next")
                    await pilot.pause(0.3)
                    pilot.app.screen.query_one("#sel_iface", Select).value = "eno1"
                    chk = pilot.app.screen.query_one("#chk_dhcp", Checkbox)
                    if not chk.value:
                        await pilot.click("#chk_dhcp")
                    await pilot.pause(0.1)
                    await pilot.click("#btn_next")
                    await pilot.pause(0.5)

                    # s03 confirm
                    for _ in range(20):
                        btn = pilot.app.screen.query_one("#btn_confirm", Button)
                        if not btn.disabled:
                            break
                        await pilot.pause(0.1)
                    await pilot.click("#btn_confirm")
                    await pilot.pause(2.0)

                    # s04 skip
                    await pilot.click("#btn_skip")
                    await pilot.pause(0.3)

                    # s05 next
                    for _ in range(30):
                        btn_next = pilot.app.screen.query_one("#btn_next", Button)
                        if not btn_next.disabled:
                            break
                        await pilot.pause(0.2)
                    await pilot.click("#btn_next")
                    await pilot.pause(0.5)

                    # s06: no selection, click Finish →
                    assert type(pilot.app.screen).__name__ == "MirrorPortsScreen"
                    await pilot.click("#btn_next")
                    await pilot.pause(0.5)

                    assert type(pilot.app.screen).__name__ == "FinishScreen", (
                        f"Expected FinishScreen, got {type(pilot.app.screen).__name__}"
                    )

                    # Verify summary content
                    from textual.widgets import Static
                    summary = pilot.app.screen.query_one("#summary", Static)
                    assert "eno1" in str(summary._Static__content), (
                        "Summary should mention the management interface 'eno1'"
                    )


@pytest.mark.asyncio
async def test_s02_form_is_scrollable():
    """The s02 form container must be a VerticalScroll widget."""
    from app import AsimilyWizard
    from textual.containers import VerticalScroll

    with patch("network.interfaces.list_interfaces", return_value=FAKE_IFACES):
        app = AsimilyWizard()
        async with app.run_test(headless=True, size=(120, 40)) as pilot:
            await pilot.pause(0.3)
            await pilot.click("#btn_next")   # s01 → s02
            await pilot.pause(0.3)

            form = pilot.app.screen.query_one("#form")
            assert isinstance(form, VerticalScroll), (
                f"#form must be VerticalScroll, got {type(form).__name__}"
            )


@pytest.mark.asyncio
async def test_s02_proxy_label_mentions_https():
    """The proxy checkbox label must mention both HTTP and HTTPS."""
    from app import AsimilyWizard
    from textual.widgets import Checkbox

    with patch("network.interfaces.list_interfaces", return_value=FAKE_IFACES):
        app = AsimilyWizard()
        async with app.run_test(headless=True, size=(120, 40)) as pilot:
            await pilot.pause(0.3)
            await pilot.click("#btn_next")
            await pilot.pause(0.3)

            chk = pilot.app.screen.query_one("#chk_proxy", Checkbox)
            label_text = str(chk.label).lower()
            assert "https" in label_text, (
                "Proxy checkbox must mention HTTPS"
            )
