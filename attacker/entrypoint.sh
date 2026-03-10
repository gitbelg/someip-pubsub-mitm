#!/bin/bash
set -e

# Wait for network interface to be up
sleep 1

# Add multicast route
route add -net 224.0.0.0 netmask 240.0.0.0 dev eth0 || true

if [ "$ENABLE_DEBUG" = "true" ]; then
    echo "Starting with debugger listener on port 5678 (waiting for attachment)..."
    # Start script via debugpy and WAIT for client to attach
    python3 -m debugpy --listen 0.0.0.0:5678 --wait-for-client someip_mitm_attacker.py
else
    # Run the attack script normally
    python3 someip_mitm_attacker.py
fi
