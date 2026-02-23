# Asimily First-Time Setup Wizard

A terminal-based setup wizard for the initial configuration of an Asimily appliance.
It guides the operator step-by-step through network setup, connectivity checks, and
mirror-port configuration — and writes a machine-readable config file consumed by the
Asimily installation script.

---

## Overview

The wizard runs as a full-screen TUI (terminal user interface) directly on the appliance
console or via SSH. It requires no graphical environment. Each step collects one piece of
configuration, validates it, and allows the operator to go back and correct mistakes.
When the final step is confirmed, the wizard writes `/etc/asimily/wizard_config.json`,
optionally launches `/opt/asimily/install.sh`, and exits.

The wizard is designed to run **once** at first boot via a systemd service that
automatically disables itself after the config file exists.

---

## The 7 Steps

| Step | Screen | Purpose |
|------|--------|---------|
| 1 | Welcome | Displays all detected network interfaces so the operator can identify the management port |
| 2 | Network Config | Selects the management interface; configures static IP or DHCP, DNS, NTP, and optional HTTP/HTTPS proxy |
| 3 | Apply Network | Applies the config with `netplan try` and a 60-second rollback countdown; operator confirms or lets it revert |
| 4 | Cloud Server IP | Optionally enters the Asimily Cloud Server IP assigned to the site (can be skipped) |
| 5 | Pre-Flight Check | Runs TCP connectivity checks to Asimily and PKI endpoints; shows pass/fail per host; allows retry |
| 6 | Mirror Ports | Selects one or more interfaces for mirrored/SPAN traffic used by the sensor |
| 7 | Finish | Shows a configuration summary, writes the config JSON, and launches the install script |

---

## Requirements

- **OS:** Ubuntu 20.04+ or Debian 11+ with [Netplan](https://netplan.io/)
- **Python:** 3.10 or newer
- **Privileges:** Must be run as `root` (netplan and systemd interaction)
- **Terminal:** Any terminal with at least 80×24 characters; works on a bare TTY

---

## Quick Start

Run the wizard manually (one-off, no service install):

```bash
# 1. Clone the repository
git clone https://github.com/Tschungl/Wizard.git /opt/asimily/wizard
cd /opt/asimily/wizard

# 2. Install Python dependencies
pip3 install -r requirements.txt

# 3. Run as root
sudo python3 main.py
```

**Keyboard shortcuts available on every screen:**

| Key | Action |
|-----|--------|
| `Q` | Quit wizard immediately |
| `Escape` | Go back to previous step |
| `Enter` | Confirm / proceed |
| `N` | Next (Step 1 only) |

---

## Systemd Service

For first-boot automation, install the wizard as a systemd service. It starts
automatically on `tty1`, and the `ConditionPathExists` directive ensures it only
runs until the config file is written.

```bash
# Install and enable the service
sudo bash install_service.sh

# Start it now (for testing)
sudo systemctl start asimily-wizard

# Check status / logs
sudo systemctl status asimily-wizard
sudo journalctl -u asimily-wizard -f
```

The service definition at `asimily-wizard.service` includes:

```
ConditionPathExists=!/etc/asimily/wizard_config.json
```

Once Step 7 writes the config file the service will not start again on subsequent reboots.

---

## Configuration Output

On completion the wizard writes `/etc/asimily/wizard_config.json`:

```json
{
  "mgmt_interface": "eno1",
  "use_dhcp": false,
  "ip_address": "192.168.1.10",
  "prefix_len": 24,
  "gateway": "192.168.1.1",
  "dns_servers": ["8.8.8.8", "8.8.4.4"],
  "ntp_servers": ["pool.ntp.org"],
  "proxy_enabled": false,
  "proxy_host": "",
  "proxy_port": 0,
  "proxy_user": "",
  "cloud_ip": "203.0.113.10",
  "mirror_interfaces": ["ens4", "ens5"]
}
```

> **Note:** The proxy password is passed directly to the proxy configuration and is
> intentionally **not** persisted in the JSON file.

---

## Development

```bash
# Clone and set up a virtual environment
git clone https://github.com/Tschungl/Wizard.git
cd Wizard
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Run the test suite (no root required)
pytest

# Run a single test file
pytest tests/test_wizard_e2e.py -v
```

The test suite (63 tests) uses [Textual's headless Pilot API](https://textual.textualize.io/guide/testing/)
for end-to-end screen tests and does not require a real network interface or netplan.

---

## Architecture

### Screen stack

The wizard uses Textual's `push_screen` / `pop_screen` stack so the operator can
always navigate backwards. `AppState` (in `state.py`) is a single shared dataclass
attached to the app instance and passed between screens.

```
AsimilyWizard (app.py)
 └── WelcomeScreen          screens/s01_welcome.py
      └── NetworkConfigScreen   screens/s02_network_config.py
           └── NetworkApplyScreen    screens/s03_network_apply.py
                └── CloudIPScreen        screens/s04_cloud_ip.py
                     └── PreflightScreen      screens/s05_preflight.py
                          └── MirrorPortsScreen    screens/s06_mirror_ports.py
                               └── FinishScreen         screens/s07_finish.py
```

### Key files

| Path | Purpose |
|------|---------|
| `main.py` | Entry point; enforces root check |
| `app.py` | `AsimilyWizard` Textual app; holds `WizardState` |
| `state.py` | `WizardState` dataclass — single source of truth for all config |
| `network/interfaces.py` | Reads live interface data from `/sys/class/net` |
| `network/netplan.py` | Writes and applies Netplan YAML; wraps `netplan try` / `netplan apply` |
| `network/checks.py` | Async TCP connectivity checks used in Step 5 |
| `validators.py` | Pure validation helpers (IP, CIDR, hostname) |
| `screens/` | One file per wizard step |
| `widgets/asimily_header.py` | Shared header widget rendered on every screen |
| `tests/` | pytest suite; `test_wizard_e2e.py` contains headless Pilot tests |
