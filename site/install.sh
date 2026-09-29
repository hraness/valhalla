#!/bin/sh
# vhalla installer: download, verify (SHA-256), install, report.
# Usage:  curl -fsSL https://vhalla.com/install.sh | sh
#         (--with-menubar is still accepted; the menu bar is retired and
#         `vhalla status` replaces it, so the flag installs only vhalla.)
# Source: https://github.com/hraness/valhalla
set -eu

with_menubar=0
for arg in "$@"; do
  case "$arg" in
    --with-menubar) with_menubar=1 ;;
    *)
      echo "vhalla install: unknown option $arg (this installer takes no options)." >&2
      exit 2 ;;
  esac
done

VERSION="v0.2.10"
BASE="https://github.com/hraness/valhalla/releases/download/$VERSION"
INSTALL_DIR="${VHALLA_INSTALL_DIR:-$HOME/.local/bin}"

os=$(uname -s)
arch=$(uname -m)
# x86-64 Linux gets the glibc build unless the C library is musl (Alpine and
# similar), which gets the static build. ARM64 Linux only has the static build.
libc=gnu
if [ "$os" = Linux ] && ldd --version 2>&1 | grep -qi musl; then
  libc=musl
fi
case "$os/$arch" in
  Darwin/arm64)          asset="valhalla-$VERSION-aarch64-apple-darwin.tar.gz" ;;
  Linux/x86_64|Linux/amd64)
                         asset="valhalla-$VERSION-x86_64-unknown-linux-$libc.tar.gz" ;;
  Linux/aarch64|Linux/arm64)
                         asset="valhalla-$VERSION-aarch64-unknown-linux-musl.tar.gz" ;;
  *)
    echo "vhalla install: there is no prebuilt vhalla for $os/$arch." >&2
    echo "Prebuilt releases cover Apple Silicon macOS, x86-64 and ARM64 Linux, and x86-64 Windows." >&2
    case "$os" in
      MINGW*|MSYS*|CYGWIN*)
        echo "On Windows, run this in PowerShell instead: irm https://vhalla.com/install.ps1 | iex" >&2 ;;
    esac
    echo "Or build from source: https://vhalla.com/docs/getting-started/" >&2
    exit 1 ;;
esac

tmp=$(mktemp -d "${TMPDIR:-/tmp}/vhalla-install.XXXXXX")
trap 'rm -rf "$tmp"' EXIT

echo "→ Downloading $asset"
curl -fsSL "$BASE/$asset"        -o "$tmp/$asset"
curl -fsSL "$BASE/$asset.sha256" -o "$tmp/$asset.sha256"

verify() {
  if command -v sha256sum >/dev/null 2>&1; then
    (cd "$tmp" && sha256sum -c "$1.sha256")
  else
    (cd "$tmp" && shasum -a 256 -c "$1.sha256")
  fi
}

echo "→ Verifying SHA-256"
verify "$asset"

echo "→ Installing to $INSTALL_DIR"
mkdir -p "$INSTALL_DIR" "$tmp/out"
tar -xzf "$tmp/$asset" --strip-components 1 -C "$tmp/out"
cp "$tmp/out/vhalla" "$INSTALL_DIR/vhalla"
chmod 755 "$INSTALL_DIR/vhalla"

"$INSTALL_DIR/vhalla" --help >/dev/null 2>&1 || {
  echo "vhalla install: the binary was installed but \`vhalla --help\` failed. Please report it at https://github.com/hraness/valhalla/issues" >&2
  exit 1
}

echo ""
echo "✓ vhalla $VERSION installed at $INSTALL_DIR/vhalla"
if [ "$with_menubar" = 1 ]; then
  echo "  The menu bar is retired: vhalla status shows the same rooms and outputs."
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
