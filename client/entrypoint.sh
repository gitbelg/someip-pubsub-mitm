#!/bin/bash
set -e

# Wait for network interface to be up
sleep 1

# Add multicast route
route add -net 224.0.0.0 netmask 240.0.0.0 dev eth0 || true

# Start radio client
export VSOMEIP_CONFIGURATION=/app/radio-client.json
export VSOMEIP_APPLICATION_NAME=radio-client
/app/radio_client
