#!/usr/bin/env bash
set -euo pipefail

# All four runtime fixture jobs use the same exact browser as the site gate.
# Admit only its executable to Ubuntu's namespace sandbox, then remove this
# job-owned profile after qualification and process cleanup have finished.
: "${RUNNER_TEMP:?GitHub runner temporary directory is required}"
VHALLA_CI_APPARMOR_PROFILE="$RUNNER_TEMP/vhalla-ci-chromium.profile"
case "${1:-}" in
  setup)
    test ! -e "$VHALLA_CI_APPARMOR_PROFILE"
    bun install --frozen-lockfile --ignore-scripts
    bunx --no-install playwright-core install --with-deps chromium
    VHALLA_CI_CHROMIUM="$(node --input-type=module -e 'import {resolvePinnedBrowser} from "./site/tools/browser-contract.mjs"; process.stdout.write((await resolvePinnedBrowser()).executablePath)')"
    [[ "$VHALLA_CI_CHROMIUM" =~ ^/[a-zA-Z0-9_./-]+$ ]]
    cat > "$VHALLA_CI_APPARMOR_PROFILE" <<EOF
abi <abi/4.0>,
include <tunables/global>
profile vhalla-ci-pinned-chromium "$VHALLA_CI_CHROMIUM" flags=(unconfined) {
  userns,
}
EOF
    sudo apparmor_parser --replace "$VHALLA_CI_APPARMOR_PROFILE"
    ;;
  cleanup)
    if [ -f "$VHALLA_CI_APPARMOR_PROFILE" ]; then
      sudo apparmor_parser --remove "$VHALLA_CI_APPARMOR_PROFILE"
      rm "$VHALLA_CI_APPARMOR_PROFILE"
    fi
    ;;
  *) printf 'Usage: pinned_chromium.sh setup|cleanup\n' >&2; exit 2 ;;
esac
