#!/bin/sh
# vhalla installer: download, verify (SHA-256), install, report.
# Usage:  curl -fsSL https://vhalla.com/install.sh | sh
#         curl -fsSL https://vhalla.com/install.sh | sh -s -- --with-menubar
#         (macOS: also installs the menu bar next to vhalla)
# Source: https://github.com/hraness/valhalla
set -eu

with_menubar=0
for arg in "$@"; do
  case "$arg" in
    --with-menubar) with_menubar=1 ;;
    *)
      echo "vhalla install: unknown option $arg (the only option is --with-menubar)." >&2
      exit 2 ;;
  esac
done

VERSION="v0.2.8"
BASE="https://github.com/hraness/valhalla/releases/download/$VERSION"
INSTALL_DIR="${VHALLA_INSTALL_DIR:-$HOME/.local/bin}"

os=$(uname -s)
arch=$(uname -m)
case "$os/$arch" in
  Darwin/arm64)  asset="valhalla-$VERSION-aarch64-apple-darwin.tar.gz" ;;
  Linux/x86_64)  asset="valhalla-$VERSION-x86_64-unknown-linux-gnu.tar.gz" ;;
  *)
    echo "vhalla install: no prebuilt release for $os/$arch." >&2
    echo "Build from source instead: https://vhalla.com/docs/getting-started/" >&2
    exit 1 ;;
esac

if [ "$with_menubar" = 1 ] && [ "$os/$arch" != "Darwin/arm64" ]; then
  echo "vhalla install: the menu bar is only built for Apple Silicon Macs." >&2
  exit 1
fi

tmp=$(mktemp -d "${TMPDIR:-/tmp}/vhalla-install.XXXXXX")
trap 'rm -rf "$tmp"' EXIT

echo "→ Downloading $asset"
curl -fsSL "$BASE/$asset"        -o "$tmp/$asset"
curl -fsSL "$BASE/$asset.sha256" -o "$tmp/$asset.sha256"

menubar="valhalla-menubar-$VERSION-aarch64-apple-darwin.tar.gz"
if [ "$with_menubar" = 1 ]; then
  echo "→ Downloading $menubar"
  curl -fsSL "$BASE/$menubar"        -o "$tmp/$menubar"
  curl -fsSL "$BASE/$menubar.sha256" -o "$tmp/$menubar.sha256"
fi

verify() {
  if command -v sha256sum >/dev/null 2>&1; then
    (cd "$tmp" && sha256sum -c "$1.sha256")
  else
    (cd "$tmp" && shasum -a 256 -c "$1.sha256")
  fi
}

echo "→ Verifying SHA-256"
verify "$asset"
if [ "$with_menubar" = 1 ]; then verify "$menubar"; fi

echo "→ Installing to $INSTALL_DIR"
mkdir -p "$INSTALL_DIR" "$tmp/out"
tar -xzf "$tmp/$asset" --strip-components 1 -C "$tmp/out"
cp "$tmp/out/vhalla" "$INSTALL_DIR/vhalla"
chmod 755 "$INSTALL_DIR/vhalla"
if [ "$with_menubar" = 1 ]; then
  # Next to vhalla, where `vhalla menubar` finds it. A curl download isn't
  # quarantined, so macOS doesn't ask before it first opens.
  mkdir -p "$tmp/menubar"
  tar -xzf "$tmp/$menubar" --strip-components 1 -C "$tmp/menubar"
  cp "$tmp/menubar/vhalla-menubar" "$INSTALL_DIR/vhalla-menubar"
  chmod 755 "$INSTALL_DIR/vhalla-menubar"
fi

"$INSTALL_DIR/vhalla" --help >/dev/null 2>&1 || {
  echo "vhalla install: the binary was installed but \`vhalla --help\` failed. Please report it at https://github.com/hraness/valhalla/issues" >&2
  exit 1
}

echo ""
echo "✓ vhalla $VERSION installed at $INSTALL_DIR/vhalla"
if [ "$with_menubar" = 1 ]; then
  echo "✓ Menu bar installed next to it. Open it now and at every login: vhalla menubar install"
fi
case ":$PATH:" in
  *":$INSTALL_DIR:"*) ;;
  *)
    echo "  Note: $INSTALL_DIR is not on your PATH. Add it:"
    echo "    export PATH=\"$INSTALL_DIR:\$PATH\"" ;;
esac
echo ""
echo "  Try it: vhalla demo, a narrated eight-step tour that runs only on this machine."
echo "  Next: choose a network you trust"
echo "    https://vhalla.com/docs/getting-started/"
