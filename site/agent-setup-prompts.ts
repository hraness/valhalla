// Caller-owned instructions are shared by rendering and qualification.
export const vhallaInstallPrompt = [
  "Install the vhalla CLI for me.",
  "1. Run: curl -fsSL https://vhalla.com/install.sh | sh",
  "   (it downloads the release, verifies the SHA-256 and installs",
  "   to ~/.local/bin — stop if the checksum fails).",
  "2. Run vhalla --help, then vhalla demo, and show me both outputs.",
  "   (demo is a fully local narrated tour in a throwaway directory.)",
  "3. Do not pin any network or create identities — I handle the trust steps.",
].join("\n");

export const vhallaBootstrapPrompt = [
  "Pin this network for me:",
  "  vhalla public bootstrap-check BOOTSTRAP PIN64",
  "BOOTSTRAP is the file I placed at /path/to/bootstrap",
  "PIN64 is the full fingerprint I verified through a second channel.",
  "Show me the check result — do not continue if it fails.",
].join("\n");
