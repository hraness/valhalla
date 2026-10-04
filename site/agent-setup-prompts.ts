// Caller-owned instructions are shared by rendering and qualification.
import { daemonRelease } from './platform-install.ts';

export const vhallaInstallPrompt = [
  "Install the vhalla CLI for me.",
  "1. Run: curl -fsSL https://vhalla.com/install.sh | sh",
  "   (it downloads the release, verifies the SHA-256 and installs",
  "   to ~/.local/bin; stop if the checksum fails).",
  "2. Run vhalla --help, then vhalla demo, and show me both outputs.",
  "   (demo is a fully local narrated tour in a throwaway directory.)",
  "3. Do not pin any network or create identities; I handle the trust steps.",
].join("\n");

export const vhallaBootstrapPrompt = [
  "Pin this network for me:",
  "  vhalla public bootstrap-check BOOTSTRAP PIN64",
  "BOOTSTRAP is the file I placed at /path/to/bootstrap",
  "PIN64 is the full fingerprint I verified through a second channel.",
  "Show me the check result; do not continue if it fails.",
].join("\n");

export const vhallaDaemonPrompt = [
  "Build the source version of the Valhalla headless daemon for me on macOS or Linux.",
  "Read https://vhalla.com/docs/getting-started/ and the repository instructions.",
  "Use a fresh checkout of https://github.com/hraness/valhalla.git and report its Git revision.",
  "Build with: cargo +1.98.1 build --locked -p vhalla-cli --bin vhalla",
  "Run ./target/debug/vhalla daemon --help and report whether the build and command succeeded.",
  `Published Unix packages include the daemon when selected explicitly with VHALLA_VERSION=${daemonRelease}; do not substitute it for this source build.`,
  "If the checkout has no daemon command or the build fails, report the failure.",
  "Stop after the build check. Do not create accounts or rooms, start or install a service,",
  "expose a listener, issue a grant, or send messages without my instructions.",
].join("\n");
