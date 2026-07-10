#!/bin/sh
# Removes the gvcp-repeater LaunchDaemon and its files.
# Copyright 2026 ITTH GmbH & Co. KG
set -e

if [ "$(id -u)" -ne 0 ]; then
    echo "run as root: sudo ./uninstall.sh" >&2
    exit 1
fi

LABEL=com.itth.gvcp-repeater

launchctl bootout system/$LABEL 2>/dev/null || true
rm -f /Library/LaunchDaemons/$LABEL.plist /usr/local/bin/gvcp-repeater.py
echo "gvcp-repeater removed (log file /var/log/gvcp-repeater.log kept)"
