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
if [ "$NODE_HOME" = /data/node ] || [ "$SOCIAL_HOME" = /data/social ]; then
  if [ -d /data ]; then
    chmod 700 /data
  fi
fi
if [ -e "$NODE_HOME/node.json" ] || [ -L "$NODE_HOME/node.json" ]; then
  if [ ! -f "$NODE_HOME/node.json" ] || [ -L "$NODE_HOME/node.json" ] || [ ! -d "$SOCIAL_HOME" ]; then
    echo 'Existing node config or genesis social store is unavailable; restore the saved artifacts before starting.' >&2
    exit 1
  fi
else
  : "${NODE_KEY:?NODE_KEY (64-hex signing seed) is required for first setup}"
  network_file=$(mktemp)
  trap 'rm -f "$network_file"' 0
  trap 'exit 1' HUP INT TERM
  printf '%s' "$NETWORK_FILE_B64" | base64 -d > "$network_file"
  set -- vhalla rooms node-init "$NODE_HOME" \
    --network "$network_file" \
    --port "$NODE_PORT" \
    --node-key "$NODE_KEY" \
    --listen "$LISTEN" \
    --peers "$PEERS" \
    --discovery "$DISCOVERY"
  # Resume only a verified empty genesis store before the first node boot.
  # node-init refuses application/WAL history and unknown retained files.
  if [ -e "$SOCIAL_HOME" ] || [ -L "$SOCIAL_HOME" ]; then
    set -- "$@" --resume-social "$SOCIAL_HOME"
  else
    set -- "$@" --social "$SOCIAL_HOME"
  fi
  if [ -n "${ADVERTISE:-}" ]; then
    set -- "$@" --advertise "$ADVERTISE"
  fi
  "$@"
  rm -f "$network_file"
  trap - 0 HUP INT TERM
  [ -f "$NODE_HOME/node.json" ]
  [ -d "$SOCIAL_HOME" ]
fi
set -- vhalla rooms node "$SOCIAL_HOME" "$NODE_HOME" "$REALM" --config "$NODE_HOME/node.json"
# Runtime networking overrides leave persisted identity, genesis and WAL intact.
if [ -n "${ADVERTISE:-}" ]; then
  set -- "$@" --advertise "$ADVERTISE"
fi
exec "$@"
