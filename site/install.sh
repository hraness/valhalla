#!/bin/sh
# vhalla installer: download, verify (SHA-256), install, report.
# Usage:  curl -fsSL https://vhalla.com/install.sh | sh
#         (--with-menubar is still accepted; the menu bar is retired and
#         `vhalla status` replaces it, so the flag installs only vhalla.)
# Update-enabled releases require authenticated GitHub CLI (gh).
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
VERSION="${VHALLA_VERSION:-$VERSION}"
printf '%s\n' "$VERSION" | LC_ALL=C grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+$' || {
  echo "vhalla install: VHALLA_VERSION must be an exact version tag." >&2; exit 1;
}
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
tmp=$(cd "$tmp" && pwd -P)
trap 'rm -rf "$tmp"' EXIT

echo "→ Downloading $asset"
curl -fsSL "$BASE/$asset"        -o "$tmp/$asset"
curl -fsSL "$BASE/$asset.sha256" -o "$tmp/$asset.sha256"

hash_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | cut -d ' ' -f 1
  else
    shasum -a 256 "$1" | cut -d ' ' -f 1
  fi
}
fail() { printf 'vhalla install: %s\n' "$*" >&2; exit 1; }

echo "→ Verifying SHA-256"
[ "$(cat "$tmp/$asset.sha256")" = "$(hash_file "$tmp/$asset")  $asset" ] \
  || fail "checksum mismatch; nothing was installed"
prefix=${asset%.tar.gz}
listing=$(tar -tzf "$tmp/$asset" | LC_ALL=C sort | tr '\n' ' ')
case "$listing" in
  "$prefix/vhalla "|"$prefix/ $prefix/vhalla ") ;;
  *) fail "unexpected archive entries; nothing was installed" ;;
esac
# Extract only a verified regular-file member, never a directory link.
kind=$(tar -tvzf "$tmp/$asset" "$prefix/vhalla" | cut -c 1)
[ "$kind" = - ] || fail "release executable is not a regular file"
mkdir "$tmp/out"
tar -xzf "$tmp/$asset" -C "$tmp/out" "$prefix/vhalla"
staged="$tmp/out/$prefix/vhalla"
[ -f "$staged" ] && [ ! -L "$staged" ] || fail "invalid release executable"
if [ "$os" = Darwin ]; then
  historical=false
  case "$VERSION" in v0.0.*|v0.1.*|v0.2.[0-9]|v0.2.10) historical=true ;; esac
  if [ "$historical" = false ]; then
    requirement='identifier "dev.hraness.vhalla" and anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] exists and certificate leaf[field.1.2.840.113635.100.6.1.13] exists and certificate leaf[subject.OU] = "8AAP53VTW3"'
    /usr/bin/codesign --verify --strict --check-notarization --test-requirement "=$requirement" "$staged" \
      || fail "Developer ID or Apple notarization verification failed; nothing was installed"
    signature=$(/usr/bin/codesign --display --verbose=4 "$staged" 2>&1) || fail "signature inspection failed"
    printf '%s\n' "$signature" | grep -Eq '^CodeDirectory .*flags=.*\(.*runtime.*\)' || fail "release lacks hardened runtime"
    printf '%s\n' "$signature" | grep -Eq '^Timestamp=.+' || fail "release lacks a secure timestamp"
  fi
fi
chmod 755 "$staged"
"$staged" --help >/dev/null 2>&1 || fail "release smoke failed; nothing was installed"
[ ! -L "$INSTALL_DIR" ] && [ ! -L "$INSTALL_DIR/vhalla" ] || fail "installation target must not be a symlink"
[ ! -e "$INSTALL_DIR/vhalla" ] || [ -f "$INSTALL_DIR/vhalla" ] || fail "installation target must be a regular file"
echo "→ Installing to $INSTALL_DIR"
mkdir -p "$INSTALL_DIR"
modern=$(printf '%s\n' "${VERSION#v}" | awk -F . '{ print ($1 > 0 || $2 > 2 || ($2 == 2 && $3 >= 12)) ? "yes" : "no" }')
if [ "$modern" = yes ]; then
  # The verified binary independently checks canonical release hashes, then
  # owns replacement, rollback and its install record under one activity lock.
  if [ -n "${VHALLA_VERSION:-}" ]; then
    "$staged" __install-release --archive "$tmp/$asset" --checksum "$tmp/$asset.sha256" --install-dir "$INSTALL_DIR" --pinned
  else
    "$staged" __install-release --archive "$tmp/$asset" --checksum "$tmp/$asset.sha256" --install-dir "$INSTALL_DIR"
  fi
else
  [ ! -e "$INSTALL_DIR/.hraness-cli-update-valhalla" ] || fail "this installation uses native update coordination; use vhalla update or install a modern release"
  staging=$(mktemp "$INSTALL_DIR/.vhalla-install.XXXXXX")
  trap 'rm -rf "$tmp"; rm -f "$staging"' EXIT
  cp "$staged" "$staging"
  chmod 755 "$staging"
  mv -f "$staging" "$INSTALL_DIR/vhalla"
fi

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
