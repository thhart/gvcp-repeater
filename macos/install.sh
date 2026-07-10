#!/bin/sh
# Installs gvcp-repeater as a macOS LaunchDaemon (idempotent).
# Copyright 2026 ITTH GmbH & Co. KG
set -e
cd "$(dirname "$0")"

if [ "$(id -u)" -ne 0 ]; then
    echo "run as root: sudo ./install.sh" >&2
    exit 1
fi

LABEL=com.itth.gvcp-repeater
PLIST=/Library/LaunchDaemons/$LABEL.plist

launchctl bootout system/$LABEL 2>/dev/null || true
mkdir -p /usr/local/bin
install -m 0755 -o root -g wheel gvcp-repeater.py /usr/local/bin/gvcp-repeater.py
install -m 0644 -o root -g wheel $LABEL.plist "$PLIST"
launchctl bootstrap system "$PLIST"

sleep 2
if launchctl print system/$LABEL | grep -q 'state = running'; then
    echo "gvcp-repeater installed and running (log: /var/log/gvcp-repeater.log)"
    tail -3 /var/log/gvcp-repeater.log 2>/dev/null || true
else
    echo "installed, but the daemon is not running — check /var/log/gvcp-repeater.log" >&2
    exit 1
fi
