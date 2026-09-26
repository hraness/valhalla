#!/bin/sh
# private-host behind a provider TCP endpoint: the host stays loopback-only
# (its most-tested posture); socat bridges the platform-facing port to it, so
# the initialized home survives redeploys and container-IP churn untouched.
# The bridge uses a distinct port -- a wildcard socat bind on 9473 would
# collide with the host's 127.0.0.1:9473 bind.
set -e
HOME_DIR="${HOME_DIR:-/data/host}"
APP_PORT="${APP_PORT:-19473}"
chmod 700 /data 2>/dev/null || true
if [ ! -f "$HOME_DIR/config.json" ]; then
  rmdir "$HOME_DIR" 2>/dev/null || true
  vhalla private-host init "$HOME_DIR" \
    --listen 127.0.0.1:9473 \
    --tls-name relay.valhalla.invalid \
    --executable /usr/local/bin/vhalla
fi
socat "TCP-LISTEN:${APP_PORT},fork,reuseaddr" TCP:127.0.0.1:9473 &
exec vhalla private-host serve "$HOME_DIR"
