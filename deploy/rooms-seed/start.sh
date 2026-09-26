#!/bin/sh
# Seed validator behind a provider TCP endpoint: the libp2p listener binds
# the wildcard address directly (unlike private-host, consensus peers must
# be dialable). The initialized home survives redeploys and container-IP
# churn untouched on the mounted volume.
set -e
NODE_HOME="${NODE_HOME:-/data/node}"
NODE_PORT="${NODE_PORT:-9473}"
LISTEN="${LISTEN:-0.0.0.0}"
DISCOVERY="${DISCOVERY:-true}"
chmod 700 /data 2>/dev/null || true
if [ ! -f "$NODE_HOME/node.json" ]; then
  rmdir "$NODE_HOME" 2>/dev/null || true
  printf '%s' "$NETWORK_FILE_B64" | base64 -d > /tmp/network.json
  vhalla rooms node-init "$NODE_HOME" \
    --network /tmp/network.json \
    --port "$NODE_PORT" \
    --node-key "$NODE_KEY" \
    --listen "$LISTEN" \
    --peers "$PEERS" \
    --discovery "$DISCOVERY"
  rm -f /tmp/network.json
fi
exec vhalla rooms node "$NODE_HOME"
