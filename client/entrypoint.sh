#!/usr/bin/env bash
set -euo pipefail

TUN_DEV="tun0"
TUN_IP="10.0.0.2"
TUN_DEST="10.0.0.1"

echo "[vpn-client] Starting Rust VPN client in background..."
RUST_LOG=debug /usr/local/bin/client &

CLIENT_PID=$!

# Wait until tun0 exists
echo "[vpn-client] Waiting for ${TUN_DEV} to appear..."
for i in {1..10}; do
    if ip link show "$TUN_DEV" &>/dev/null; then
        echo "[vpn-client] ${TUN_DEV} found!"
        break
    fi
    sleep 0.5
done

# Bring up tun0 and assign IP
echo "[vpn-client] Configuring TUN interface ${TUN_DEV}..."
ip link set dev "${TUN_DEV}" up

# Set default route via TUN
ip route del default
ip route add default dev "${TUN_DEV}" || echo "[vpn-client] Default route already exists"

echo "[vpn-client] TUN interface configured: ${TUN_IP} -> ${TUN_DEST}"

# Wait for Rust client to exit (keep container alive)
wait $CLIENT_PID
