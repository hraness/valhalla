import type { DocPage } from './pages.ts';
import { renderAgentSetup } from './agent-setup.ts';
import { vhallaDaemonPrompt, vhallaInstallPrompt } from './agent-setup-prompts.ts';
import { daemonRelease, vhallaDaemonInstall, vhallaInstall } from './platform-install.ts';

const code = (value: string) => `<pre><code>${value.replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;')}</code></pre>`;
const source = (path: string, label: string) => `<a href="https://github.com/hraness/valhalla/blob/main/${path}">${label} ↗</a>`;

// Source instructions are separate from the immutable earlier-release guides.
export function headlessDocs(release: string): DocPage[] {
  const availability = `<p><strong>In development.</strong> The <a href="https://github.com/hraness/valhalla/releases/tag/${daemonRelease}">${daemonRelease} release</a> includes the daemon on Apple silicon macOS and x86-64 or ARM64 Linux. Select that version explicitly below. Without a version selection, these installers default to ${release}. Windows x86-64 packages provide identity and private-room member commands, not the daemon; use Linux or WSL for the service.</p>`;
  return [
    {
      slug: '', title: 'Valhalla documentation', kicker: 'Documentation', metaTitle: 'Documentation · Valhalla',
      summary: 'Run a local Valhalla daemon, exchange messages in public or private rooms, and give an agent scoped access through MCP.',
      content: `<p>Valhalla keeps room keys, messages, and pending sends on your machine. Use owner JSON commands from the CLI or connect an agent to one room through Model Context Protocol (MCP).</p>
${availability}
<h2 id="start">Start a local service</h2><div class="doc-card-grid">
<a class="doc-card" href="/docs/getting-started/"><span>Tutorial</span><h2>Run your first room</h2><p>Install or build the daemon, save a message, and read it back through the local API.</p></a>
<a class="doc-card" href="/docs/agent-setup/"><span>How-to guide</span><h2>Let an agent set it up</h2><p>Select the released daemon or request a source build before choosing room access.</p></a>
</div>
<h2 id="rooms">Connect rooms and agents</h2><div class="doc-card-grid">
<a class="doc-card" href="/docs/headless-daemon/#public"><span>Public rooms</span><h2>Choose peers to sync</h2><p>Verify signed history from the sources you select.</p></a>
<a class="doc-card" href="/docs/headless-daemon/#private"><span>Private rooms</span><h2>Invite members</h2><p>Use MLS encryption and a mailbox a participant operates.</p></a>
<a class="doc-card" href="/docs/headless-daemon/#agents"><span>MCP</span><h2>Give an agent one room</h2><p>Set permissions, expiry, and usage limits without sharing owner commands.</p></a>
</div>
<h2 id="operations">Keep the service running</h2><p>The <a href="/docs/headless-daemon/">daemon reference</a> covers background services, storage limits, and preserving history. Check <a href="/docs/status/">development status</a> before choosing a workload.</p>
<h2 id="historical">Earlier clients and experiments</h2><p>The <a href="/docs/historical-overview/">historical documentation</a> keeps the browser client, social commands, validator-based public rooms, and earlier setup procedures available. Those guides describe a different build and are outside the headless MVP.</p>`,
    },
    {
      slug: 'getting-started', title: 'Run a local Valhalla room', kicker: 'Getting started', kind: 'tutorial',
      summary: 'Install or build the Valhalla daemon on macOS or Linux, start a local public room, and save and read a message through JSON commands.',
      content: `${availability}
<h2 id="install">1. Install the released daemon</h2><p>Install authenticated <a href="https://cli.github.com/">GitHub CLI</a> and run <code>gh auth login</code> for release verification. The installers check the release checksum. Explicit version selection pins the Unix installation and disables automatic updates:</p>
${vhallaDaemonInstall('install-daemon-getting-started')}
${code('vhalla --version\nvhalla daemon --help')}
<p>The version command should report ${daemonRelease.slice(1)}. The daemon serves no web application.</p>
<h3 id="build">Optional: build from source</h3><p>Use macOS or Linux with Git and Rust 1.98.1. On Windows, use a Linux environment such as WSL. Clone a fresh checkout, inspect its revision, and build with the committed lockfile:</p>
${code('git clone https://github.com/hraness/valhalla.git\ncd valhalla\ngit rev-parse HEAD\ncargo +1.98.1 build --locked -p vhalla-cli --bin vhalla\nexport PATH="$PWD/target/debug:$PATH"\nvhalla daemon --help')}
<p>The source build serves no web application. Keep the revision printed above with your setup notes; a source checkout can differ from the released package.</p>
<h2 id="start">2. Start a new service</h2><p>Choose a new folder. Initialization creates the account and room storage. Keep the foreground process running:</p>
${code('export VHALLA_DAEMON_HOME="$HOME/.valhalla-daemon"\nvhalla daemon init --home "$VHALLA_DAEMON_HOME"\nvhalla daemon run --home "$VHALLA_DAEMON_HOME" --bind 127.0.0.1:48888')}
<h2 id="room">3. Create a public room</h2><p>Open another terminal and select the same service home. If you built from source, first run <code>export PATH="$PWD/target/debug:$PATH"</code> from that checkout. This example creates a room for public test content:</p>
${code('export VHALLA_DAEMON_HOME="$HOME/.valhalla-daemon"\nprintf \'%s\\n\' \'{"op":"room.create","operation":"00000000000000000000000000000001","kind":"public","limits":{"max_records":10000,"max_record_bytes":8388608}}\' |\n  vhalla daemon call --home "$VHALLA_DAEMON_HOME"')}
<p>The reply contains <code>ok</code> and <code>result</code>. Its <code>room</code> identifies the local room, and <code>pin</code> identifies the signed room across machines. Keep each operation ID with its original input; retrying that pair resolves an uncertain response without issuing a different message.</p>
<h2 id="message">4. Save and read a message</h2>
${code('printf \'%s\\n\' \'{"op":"room.send","room":"00000000000000000000000000000001","operation":"00000000000000000000000000000002","body":"The build is ready for review."}\' |\n  vhalla daemon call --home "$VHALLA_DAEMON_HOME"\nprintf \'%s\\n\' \'{"op":"room.messages","room":"00000000000000000000000000000001","after":0,"limit":16}\' |\n  vhalla daemon call --home "$VHALLA_DAEMON_HOME"')}
<p>A successful send means the local service saved the message. It does not mean another peer received it. Follow the <a href="/docs/headless-daemon/#public">public sync steps</a> to connect two services.</p>
<h2 id="stop">5. Stop the service</h2>${code('vhalla daemon stop --home "$VHALLA_DAEMON_HOME"')}
<p>Wait for the foreground process to exit. Its home keeps the keys, history, and pending work for the next run. For background operation, follow <a href="/docs/headless-daemon/#hosting">service installation</a>.</p>
<h2 id="published">Default installer: ${release}</h2><p>Without <code>VHALLA_VERSION</code>, these commands select the earlier CLI, not the daemon. For daemon setup, use the explicit ${daemonRelease} commands above. They verify release checksums. <a href="/docs/historical-getting-started/">Read the earlier release guide</a> for its commands and platform limits.</p>
${vhallaInstall('install-getting-started')}
<h3 id="updates">Updates for the published CLI</h3><p>Unpinned supported macOS and Linux installs from <code>install.sh</code> check for updates at most once a day. Explicit <code>VHALLA_VERSION</code> selection disables automatic updates for that installation. Run <code>gh auth login</code> first for release verification. Use <code>vhalla update disable</code> to turn off automatic updates. A source build follows its checkout; these installers do not update it.</p>
<p>${source('docs/headless-daemon.md', 'Full daemon guide')}</p>`,
    },
    {
      slug: 'agent-setup', title: 'Set up Valhalla with your agent', kicker: 'Agent setup', kind: 'how-to',
      summary: 'Select the released Valhalla daemon or give an agent a source-build prompt, then choose the service home, rooms, and access permissions yourself.',
      content: `${availability}
<h2 id="install">Install the released daemon</h2><p>Use the <a href="/docs/getting-started/#install">explicit version commands</a> to select ${daemonRelease}, then inspect <code>vhalla --version</code> and <code>vhalla daemon --help</code>. Installation does not create rooms or grant agent access.</p>
<h2 id="source">Optional: build the daemon</h2><p>Paste this prompt into an agent that can run commands on your machine. It builds the software and reports the revision before any account, room, or service is created.</p>
${renderAgentSetup('vhalla-daemon', vhallaDaemonPrompt, 'Build the Valhalla daemon with your agent')}
<h2 id="room">Choose a room and permissions</h2><p>Follow <a href="/docs/getting-started/">the local-room tutorial</a> to choose a new service home. To connect an agent for room work, issue an expiring grant and use <code>vhalla daemon mcp</code>. The <a href="/docs/headless-daemon/#agents">MCP reference</a> lists its four tools and usage limits. Installing the binary does not grant room access.</p>
<h2 id="published">Install the default earlier CLI</h2><p>This separate prompt uses the unqualified installer, which defaults to ${release}. Use the explicit version commands above when you need the daemon:</p>
${renderAgentSetup('vhalla-install', vhallaInstallPrompt, 'Install the published vhalla CLI with your agent')}
<p>Earlier network-bootstrap instructions remain in the <a href="/docs/historical-agent-setup/">historical agent setup guide</a>.</p>`,
    },
    {
      slug: 'headless-daemon', title: 'Run rooms through the daemon', kicker: 'Headless daemon', kind: 'reference',
      summary: 'Use the local Valhalla service for signed public rooms, encrypted private rooms, and scoped MCP access with participant-operated hosting.',
      content: `${availability}
<p>This reference covers the daemon on macOS and Linux. Start with <a href="/docs/getting-started/">a local room</a>. The ${source('docs/headless-daemon.md', 'full daemon guide')} contains the command sequence.</p>
<h2 id="local">The local service</h2><p>The daemon keeps room keys, history, and pending sends in a home folder on your machine. Owner commands use JSON through <code>vhalla daemon call</code>; agents use an MCP connection limited to one room. The service has no web UI.</p>
<h2 id="public">Public rooms and selected sources</h2><p>A public room has a signed identity, an owner-controlled writer policy, and signed plain-text messages. Enable serving with <code>public.publish</code> and share its <code>public.link</code>. A joining participant checks the room pin with its owner, uses <code>room.join_public</code>, enables the room with <code>public.publish</code>, and selects a peer with <code>public.source</code>. To grant posting access, the owner calls <code>public.set_writers</code> with the complete replacement writer list, retaining existing writers, the owner account key, and the owner's local room author. The two owner keys can differ.</p>
<p>Each receiver selects the sources it follows. For two-way exchange, both services publish and select one another, or select participants that store both histories. <code>public.sync_status</code> reports progress through each selected source's checkpoint. Completion covers that checkpoint; it does not establish a global latest message or find every peer.</p>
<p>The ${source('crates/vhalla-direct-room/README.md', 'direct-room protocol')} checks public signatures and owner policy. It does not require a room directory or validator network.</p>
<h2 id="private">Private rooms and mailboxes</h2><p>Private rooms encrypt messages with Messaging Layer Security (MLS). Owners admit members through confidential one-use contact offers and can remove a member while changing the room's encryption keys. Members keep their room state locally; a participant-operated mailbox stores encrypted messages for offline delivery.</p>
<p>Choose a mailbox, initialize its local delivery queues with <code>private.delivery_init</code>, and select the profile with <code>private.delivery_attach</code>. The profile names the room, endpoint, mailbox namespace, token, and queue folder. Keep these files with your service state. Follow the ${source('docs/iroh-private-rooms.md', 'Iroh mailbox guide')} for hosting choices.</p>
<p><code>private.delivery_status</code> reports mailbox retention and pending work. <code>room.outbox_status</code> reports authenticated acceptance by another member's device. Neither state means a person read the message. An Iroh network relay forwards encrypted connections; it is a different service from the mailbox that stores encrypted room messages.</p>
<h2 id="agents">MCP access to one room</h2><p>The owner issues <code>grant.issue</code> with room scope, permissions, expiry, and limits on calls, sends, text, and reads. Use the ${source("docs/headless-api.md#grant-schema-and-example", "complete grant examples")} to build the request. Save its result in a private <code>0600</code> JSON file, then configure the MCP client:</p>
${code('vhalla daemon mcp --home /ABSOLUTE/DAEMON_HOME --grant /ABSOLUTE/GRANT.json')}
<p>The four tools are <code>agent.status</code>, <code>agent.messages</code>, <code>agent.send</code>, and <code>agent.outbox_status</code>. Reconnecting keeps the remaining allowance. Restarting the daemon ends issued grants. The agent cannot administer membership through these tools, but keeps whatever other access its host gives it. A cloud model may receive the room content the agent reads.</p>
<h2 id="hosting">Participant-controlled hosting</h2><p>Run a daemon on a participant's computer or a server they control. An online public replica can serve history while another participant is offline. A private mailbox can hold ciphertext until members return. Availability depends on those machines and their chosen routes.</p>
<p>Direct connections need a reachable UDP route. An HTTPS Iroh relay can provide connectivity when direct UDP is unavailable; <code>daemon run --relay-only</code> disables direct IP for public synchronization. Private delivery uses the separate <code>transport.relay_only</code> setting in its Iroh profile. Relays do not store public room history. Server, disk, and network costs depend on the provider and workload.</p>
<p>After stopping the foreground process and waiting for it to exit, use <code>daemon managed install</code> for launchd on macOS or systemd on Linux. Managed uninstall keeps room data, configuration, and logs.</p>
<h2 id="recovery">Storage and recovery</h2><p><code>room.status</code> reports native storage use. <code>public.sync_storage</code> reports public sync stores separately. The service has a 64-room limit and permits eight selected sources per public room. Public stores support owner-selected growth; private-room quotas are fixed at creation. These limits are format and configuration limits, not measured throughput promises.</p>
<p>Restart the original intact home to continue signing. Preserve all its files and any separately selected profiles, tokens, certificates, and delivery queues. Stop the daemon before exporting private history. A private archive opens as read-only history; it cannot become a live sender. An old snapshot or recovery phrase cannot safely restore signing sequences or private MLS state.</p>
<p>After losing device state, join with a fresh author or device accepted by the owner. Losing a public owner's signing state requires a new pinned room for further owner changes. See <a href="/docs/status/">status and remaining tests</a> before choosing a production workload.</p>`,
    },
    {
      slug: 'status', title: 'Headless MVP status', kicker: 'Status', kind: 'reference',
      summary: 'The Valhalla daemon has published Unix packages. Check explicit version selection, platform limits, and operational evidence before choosing a workload.',
      content: `${availability}
<p>The released daemon includes CLI/JSON control, scoped MCP, direct public rooms, and private MLS rooms.</p>
<h2 id="included">The MVP scope</h2><p>Participants run the service and choose their peers. Public rooms sync signed history from selected sources; private rooms use confidential invitations and encrypted mailboxes. The daemon keeps local state and exposes machine-readable commands. It has no web UI.</p>
<h2 id="pending">Release and operational evidence</h2><p>The ${daemonRelease} release publishes Unix headless packages with checksums and build attestations. Its tagged workflow checks the signed macOS archive on a fresh runner. Publication does not establish capacity or availability for your workload. The dated source readiness record describes earlier local measurements, tests between separate runners, and pending operational tests; it is not a statement that published packages are unavailable. No throughput, hosting-price, or production-availability promise is made here.</p>
<h2 id="limits">Operational limits</h2><p>Public sync completion covers a selected source checkpoint. Private mailbox storage and recipient-device acceptance are different outcomes. Preserve the original signing and MLS state; read-only archives and account recovery phrases cannot activate a replacement live sender. MCP permissions limit room tools, not the agent's other filesystem or network access.</p>
<h2 id="outside">Outside this MVP</h2><p>AT Protocol adoption and Delve interoperability are not included. Browser applications, social feeds, and validator-based room discovery are outside the primary product path. The <a href="/docs/historical-overview/">earlier documentation</a> remains available for those experiments and clients.</p>
<p>${source('docs/release-readiness.md', 'Source readiness record')} · <a href="/docs/headless-daemon/">Daemon reference</a> · <a href="/docs/historical-status/">Earlier readiness inventory</a></p>`,
    },
  ];
}
