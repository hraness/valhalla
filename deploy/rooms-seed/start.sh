#!/bin/sh
# Seed validator behind a provider TCP endpoint: the libp2p listener binds
# the wildcard address directly (unlike private-host, consensus peers must
# be dialable). The initialized home and genesis social store survive
# redeploys and container-IP churn untouched on the mounted volume.
set -e
NODE_HOME="${NODE_HOME:-/data/node}"
SOCIAL_HOME="${SOCIAL_HOME:-/data/social}"
NODE_PORT="${NODE_PORT:-9473}"
LISTEN="${LISTEN:-0.0.0.0}"
DISCOVERY="${DISCOVERY:-true}"
: "${REALM:?REALM (32-hex realm id) is required}"
: "${NETWORK_FILE_B64:?NETWORK_FILE_B64 is required}"
chmod 700 /data 2>/dev/null || true
if [ ! -f "$NODE_HOME/node.json" ] || [ ! -d "$SOCIAL_HOME" ]; then
  rmdir "$NODE_HOME" 2>/dev/null || true
  printf '%s' "$NETWORK_FILE_B64" | base64 -d > /tmp/network.json
  # --social seeds the genesis store before the node.json
  # never-overwrite check, so a re-run completes a half-scaffolded
  # home; the only tolerated failure is both artifacts already existing.
  set -- vhalla rooms node-init "$NODE_HOME" \
    --network /tmp/network.json \
    --port "$NODE_PORT" \
    --node-key "$NODE_KEY" \
    --listen "$LISTEN" \
    --peers "$PEERS" \
    --discovery "$DISCOVERY" \
    --social "$SOCIAL_HOME"
  if [ -n "${ADVERTISE:-}" ]; then
    set -- "$@" --advertise "$ADVERTISE"
  fi
  "$@" || true
  rm -f /tmp/network.json
  [ -f "$NODE_HOME/node.json" ]
  [ -d "$SOCIAL_HOME" ]
fi
set -- vhalla rooms node "$SOCIAL_HOME" "$NODE_HOME" "$REALM" --config "$NODE_HOME/node.json"
# Runtime networking overrides leave persisted identity, genesis and WAL intact.
if [ -n "${ADVERTISE:-}" ]; then
  set -- "$@" --advertise "$ADVERTISE"
fi
exec "$@"
