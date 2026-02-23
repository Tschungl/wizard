#!/bin/bash
set -e
INSTALL_DIR="/opt/asimily/wizard"
SERVICE_FILE="/etc/systemd/system/asimily-wizard.service"

echo "Installing Asimily Wizard to ${INSTALL_DIR}..."
mkdir -p "${INSTALL_DIR}"
cp -r . "${INSTALL_DIR}/"

echo "Installing systemd service..."
cp asimily-wizard.service "${SERVICE_FILE}"
systemctl daemon-reload
systemctl enable asimily-wizard.service
echo "Done. Run 'systemctl start asimily-wizard' to test."
