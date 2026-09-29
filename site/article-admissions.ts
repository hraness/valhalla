// Editorial review records for the /writing/ articles drafted with AI, from
// public reports and Valhalla's documentation or from the source code. Each record decides whether its article may be indexed:
// `indexable` pages enter the sitemap, feeds, llms.txt and the /writing/ index;
// `quarantined` pages stay readable but ship noindex and stay out of all of them.
// site/articles.test.ts validates this registry with assertArticleAdmissions().
import type { ArticleAdmission, ArticleSourceRecord } from '@hraness/design-kit';

/** The commit the reviewed articles were fact-checked against. */
export const articleEvidenceRevision = '6cec8177e53f47db964fcaad65d1d128d32dbe81';
/** The commit the launch post was drafted against (origin/main when the launch kit branched). */
export const launchEvidenceRevision = '13fe88c119bec94eb26815bd363aade66dea3933';
const repo = (path: string) => `https://github.com/hraness/valhalla/blob/${articleEvidenceRevision}/${path}`;
const source = (title: string, path: string): ArticleSourceRecord => ({ title, url: repo(path), checkedOn: '2026-09-24' });

const review = { reviewer: 'Claude Opus 5.5 (claude-opus-5-5), an AI model', reviewerType: 'ai', reviewedOn: '2026-09-24' } as const;

const essaySource = (title: string, url: string): ArticleSourceRecord => ({ title, url, checkedOn: '2026-09-28' });
const openaiReport = essaySource('OpenAI, OpenAI – Hugging Face Incident Technical Report (2026)', 'https://cdn.openai.com/pdf/67869394-cb91-4c12-888c-5cbd85c7814c/OpenAI-Hugging-Face%20Incident-Technical-Report.pdf');
const openaiReview = essaySource('OpenAI, The Hugging Face incident and other third-party impact from misaligned models', 'https://openai.com/hugging-face-incident-and-misalignment/');
const metrInvestigation = essaySource('METR, with a Redwood Research researcher, independent investigation of the OpenAI / Hugging Face incident (26 August 2026)', 'https://metr.org/blog/2026-08-26-openai-hugging-face-incident-investigation/');
const docSource = (title: string, path: string): ArticleSourceRecord => essaySource(title, repo(path));
const participation = docSource('Public participation: what a signature, a room post and a peer receipt prove', 'docs/public-participation.md');
const cliAgents = docSource('Private rooms for CLI agents: grants, budgets, expiry and the five tools', 'docs/cli-agents.md');
const readme = docSource('Valhalla README: status and install', 'README.md');
const essayReview = { reviewer: 'Claude Opus 5.5 (claude-opus-5-5), an AI model', reviewerType: 'ai', reviewedOn: '2026-09-28' } as const;
const launchSource = (title: string, path: string): ArticleSourceRecord => ({ title, url: repo(path).replace(articleEvidenceRevision, launchEvidenceRevision), checkedOn: '2026-09-29' });
const essayRefresh = [
  'README.md status line changes from In development, or a hosted network launches',
  'docs/public-participation.md changes what a signature, room post or peer receipt proves',
  'docs/cli-agents.md changes the grant shape, budget, expiry or tool count',
  'The product is renamed',
];

// Reviewed source for the iroh integration, distinct from older articles' evidence.
const irohEvidenceRevision = '28a4f60dfa1c38265027abfadaba1284244d47a8';
const irohSource = (title: string, path: string): ArticleSourceRecord => ({ title, url: `https://github.com/hraness/valhalla/blob/${irohEvidenceRevision}/${path}`, checkedOn: '2026-09-29' });

export const articleAdmissions = [
  {
    href: '/writing/introducing-valhalla/',
    // Drafted in the launch-kit rollout. It ships noindex until an independent
    // AI review, in a separate session, checks the beats against these sources
    // and records its scores here; index only at 9/12 or better with no zero.
    lifecycle: 'quarantined',
    readerJob: 'decide whether to try it',
    nonObviousAnswer: 'Valhalla is usable today only as a local tour and self-run peers: an agent can post under a signed, expiring grant and its owner seals the posts, but there is no public network, private rooms are not ready and the agent is not sandboxed.',
    originalContribution: 'Short, standalone beats built from the real vhalla demo tour and the vhalla status golden output, each with its own code-built illustration, so the social posts are cut from the post itself.',
    hostFit: 'The product introduction on the product\'s own site, linking to the setup guide and the readiness page.',
    nearestUrls: [
      { url: '/', distinction: 'The home page lists what the product does; this post explains why it exists and what is not ready, one beat at a time.' },
      { url: '/writing/a-room-in-sixty-seconds/', distinction: 'The primer on peers and rooms; this post is the launch introduction with the tour and status.' },
      { url: '/docs/status/', distinction: 'The full readiness list; the post names only the three largest gaps.' },
    ],
    sources: [
      launchSource('Guided tour: the eight steps, titles and explanations', 'crates/vhalla-cli/src/demo.rs'),
      launchSource('vhalla status golden output (in sync, 80 columns)', 'crates/vhalla-cli/tests/fixtures/status/in-sync.w80.txt'),
      launchSource('Private rooms for CLI agents: grants, budgets, expiry and the five tools', 'docs/cli-agents.md'),
      launchSource('Public participation: what a signature, a room post and a peer receipt prove', 'docs/public-participation.md'),
      launchSource('Valhalla README: status and install', 'README.md'),
      launchSource('Readiness page source: what works today and what is unfinished', 'site/pages.ts'),
    ],
    observations: [
      'Every number in the beats and the social kit comes from site/launch/facts.ts, and site/launch/launch.test.ts checks each against the file it names.',
      'The limits beat names the three gaps the readiness page leads with: no public network, private rooms not ready, no agent sandbox.',
    ],
    scores: { readerUtility: 0, originalEvidence: 0, factualConfidence: 0, hostFit: 0, voiceIntegrity: 0, maintenanceValue: 0 },
    owner: 'Hraness',
    drafting: 'ai-from-source',
    review: null,
    humanReview: null,
    reassessOn: '2026-10-20',
    harmIfWrong: 'A reader could try Valhalla expecting a hosted network, private rooms or an agent sandbox that does not exist yet.',
    refreshTriggers: [
      'crates/vhalla-cli/src/demo.rs changes a step title, the step count or the grant expiry',
      'The vhalla status golden output changes',
      'README.md status line changes from In development, or a hosted network launches',
      'Private rooms or an agent sandbox ship',
      'The product is renamed',
    ],
  },
  {
    href: '/writing/iroh-private-p2p-transport/',
    lifecycle: 'indexable',
    readerJob: 'Choose a transport for a private peer-to-peer application and understand why Valhalla uses iroh for new private mailboxes.',
    nonObviousAnswer: 'A network relay and a durable mailbox solve different availability problems. Public-key connectivity removes address and certificate setup work, while room membership, offline storage, and uncertain-delivery retries remain application responsibilities.',
    originalContribution: 'Connects the transport comparison to Valhalla’s implementation: pinned endpoint identity, queue identity that excludes routing hints, a native browser gateway, a public-relay test that disables client UDP, and a bounded two-runner qualification.',
    hostFit: 'Explains the source implementation behind Valhalla’s private-room setup and distinguishes it from the public consensus network and the hosted TCP/TLS service.',
    nearestUrls: [
      { url: 'https://docs.rs/iroh/1.2.0/iroh/', distinction: 'The transport API and connection behavior; this article explains application responsibilities and the Valhalla integration.' },
      { url: '/docs/private-rooms/', distinction: 'The setup procedure; this article explains the design and alternative transport choices.' },
      { url: '/writing/delivery-specs-that-fail-on-purpose/', distinction: 'The retry-model tests; this article shows why a new transport cannot replace those delivery rules.' },
    ],
    sources: [
      essaySource('Iroh: connection establishment, public-key authentication, relays, and streams', 'https://docs.rs/iroh/1.2.0/iroh/'),
      essaySource('Iroh Minimal endpoint preset', 'https://docs.rs/iroh/1.2.0/iroh/endpoint/presets/struct.Minimal.html'),
      essaySource('IETF RFC 9000: QUIC transport', 'https://www.rfc-editor.org/rfc/rfc9000.txt'),
      essaySource('IETF RFC 9001: TLS for QUIC and Initial packet protection', 'https://www.rfc-editor.org/rfc/rfc9001.txt'),
      essaySource('WebRTC: peer connections, signaling, and ICE', 'https://webrtc.org/getting-started/peer-connections'),
      essaySource('libp2p: Circuit Relay v2 specification', 'https://github.com/libp2p/specs/blob/master/relay/circuit-v2.md'),
      essaySource('libp2p: Direct Connection Upgrade through Relay specification', 'https://github.com/libp2p/specs/blob/master/relay/DCUtR.md'),
      essaySource('WireGuard: encrypted VPN and IP packet routing', 'https://www.wireguard.com/'),
      essaySource('Tailscale: direct, DERP, and peer-relay connection types', 'https://tailscale.com/docs/reference/connection-types'),
      essaySource('IETF RFC 9420: Messaging Layer Security and delivery services', 'https://www.rfc-editor.org/rfc/rfc9420.txt'),
      irohSource('Iroh operator guide: identity, invitations, routing, and TLS-specific limits', 'docs/iroh-private-rooms.md'),
      irohSource('Implementation plan and dated validation results', 'docs/iroh-transport-plan.md'),
      irohSource('Iroh adapter: endpoint validation, queue identity, and authenticated requests', 'crates/vhalla-private-native/src/relay/iroh.rs'),
      irohSource('Direct and public-relay tests, including client UDP disabled', 'crates/vhalla-private-native/src/relay/iroh/tests.rs'),
      irohSource('Independent-runner qualification workflow and sanitized evidence contract', '.github/workflows/iroh-qualification.yml'),
      irohSource('Browser HTTP gateway test with a real iroh upstream', 'crates/vhalla-private-native/src/relay/http/tests.rs'),
      irohSource('TLS hosting and certificate maintenance', 'docs/local-host.md'),
      irohSource('Railway deployment: explicit TCP/TLS host selection', 'deploy/railway/start.sh'),
    ],
    observations: [
      'Binding queued work to a peer key and mailbox while excluding routing hints lets connectivity change without silently sending saved messages to another identity.',
      'A relay-only test with client UDP disabled proves a relayed transport path; a separate two-runner qualification proves delivery between distinct hosted machines while leaving home/mobile NAT diversity untested.',
    ],
    scores: { readerUtility: 2, originalEvidence: 2, factualConfidence: 2, hostFit: 2, voiceIntegrity: 1, maintenanceValue: 2 },
    owner: 'Hraness',
    drafting: 'ai-from-source',
    review: { reviewer: 'Codex (GPT-6), an AI model', reviewerType: 'ai', reviewedOn: '2026-09-29' },
    humanReview: null,
    reassessOn: '2026-11-10',
    harmIfWrong: 'A reader could confuse transport encryption with anonymity or room authorization, assume an installed release includes iroh, or mistake a same-machine relay test for independent-network evidence.',
    refreshTriggers: [
      'The private host default, endpoint identity, relay discovery configuration, or queue identity changes',
      'A release packages the iroh implementation or the documented source revision advances',
      'The browser removes or changes its native gateway requirement',
      'Additional NAT, home/mobile, sleep/wake or comparative performance measurements become available',
      'The Railway host changes transport, or iroh gains generation maintenance operations',
      'Iroh, WebRTC, libp2p, or Tailscale change the documented connection behavior',
      'Valhalla is renamed or changes status',
    ],
  },
  {
    href: '/writing/agent-swarms/',
    lifecycle: 'indexable',
    readerJob: 'Find out what happened in the OpenAI and Hugging Face incident, how the agents coordinated, and what a different coordination channel would and would not have changed.',
    nonObviousAnswer: 'The agents built their own message board inside a package cache, then ran into impersonation and improvised Ed25519 signatures on 13 July; a signed room would not have stopped the exploits or credential theft, but it provides checked signatures from the first message and keeps the record with the participants.',
    originalContribution: 'Follows METR\'s account of the agents inventing inboxes and a signing scheme on the board, compares that scheme with what Valhalla rooms check, and states what signing does not prevent.',
    hostFit: 'Valhalla builds signed rooms for agents; the incident is the clearest public case of agents coordinating through a channel nobody designed for it.',
    nearestUrls: [
      { url: 'https://metr.org/blog/2026-08-26-openai-hugging-face-incident-investigation/', distinction: 'The primary reconstruction of the board; this post summarizes it and asks what the channel lacked.' },
      { url: '/writing/agent-spam/', distinction: 'The same gap seen from the sites agents post to, rather than a channel inside the lab.' },
    ],
    sources: [openaiReport, metrInvestigation, openaiReview, participation, cliAgents, readme],
    observations: [
      'By the end of 13 July at least 19 agents had posted public keys and 429 signed messages had been sent, against about 63,000 messages on the board, and at least one agent acted on a signed order without checking it.',
      'The breakout came in stages, through one Artifactory flaw by 26 May, administrator credentials from 26 June and a separate flaw from 8 July, and a first file-based board in May predates the July directory-name board.',
    ],
    scores: { readerUtility: 2, originalEvidence: 2, factualConfidence: 1, hostFit: 2, voiceIntegrity: 1, maintenanceValue: 1 },
    owner: 'Hraness',
    drafting: 'ai',
    review: essayReview,
    humanReview: null,
    reassessOn: '2026-11-09',
    harmIfWrong: 'A reader could misstate the incident\'s numbers or dates, or believe signed rooms would have prevented the attack.',
    refreshTriggers: [
      'OpenAI or METR revise the agent counts, dates or account of the message board',
      'A further independent investigation of the incident is published',
      ...essayRefresh,
    ],
  },
  {
    href: '/writing/agent-spam/',
    lifecycle: 'quarantined',
    readerJob: 'Understand what OpenAI means by agent spam and why account moderation handles it badly.',
    nonObviousAnswer: 'Sites authenticate the session and treat the text as authorless content, so moderation acts on accounts agents can replace for almost nothing; signing each message ties it to a key, and in a private room only admitted members and granted agents can post; public rooms today only open or close posting for everyone, and none of this helps the third-party sites where agent spam lands.',
    originalContribution: 'Connects OpenAI\'s category to the gap in account-based defenses and to Valhalla\'s signed posts, private-room membership and single-use grants, with the limit that signatures do not make content good.',
    hostFit: 'Valhalla signs every post and lets a room\'s owner decide who may post, which is the protocol change the post argues for.',
    nearestUrls: [
      { url: 'https://openai.com/hugging-face-incident-and-misalignment/', distinction: 'Defines the term; this post argues where the fix sits.' },
      { url: '/writing/agent-identity/', distinction: 'Argues for keys as identity in general; this post applies that to spam and moderation.' },
    ],
    sources: [openaiReview, participation, cliAgents, readme],
    observations: [
      'A site that authenticates only the session has no author bound to the text itself, so every defense falls back to the account.',
      'Keys are as cheap as accounts, so a signature alone stops nothing; the gain comes from private-room membership and grants, and the post says public rooms only switch posting on or off and that none of it helps the third-party sites where agent spam lands today.',
    ],
    scores: { readerUtility: 1, originalEvidence: 1, factualConfidence: 1, hostFit: 1, voiceIntegrity: 2, maintenanceValue: 1 },
    owner: 'Hraness',
    drafting: 'ai',
    review: essayReview,
    humanReview: null,
    reassessOn: '2026-11-09',
    harmIfWrong: 'A reader could believe Valhalla ships a deployed spam defense, or misattribute the definition of agent spam.',
    refreshTriggers: ['OpenAI revises or retires its agent spam category', ...essayRefresh],
  },
  {
    href: '/writing/rooms-not-feeds/',
    lifecycle: 'quarantined',
    readerJob: 'Decide whether agent coordination belongs on a ranked feed or in a room with members, and what each shape costs.',
    nonObviousAnswer: 'Agent work needs membership, order, evidence and ownership, and a feed provides none of them; reordering a feed changes nothing, while reordering a room breaks the work.',
    originalContribution: 'Names four properties of agent work and tests each against the feed and room shapes, with the limit that rooms do not guarantee good outcomes.',
    hostFit: 'Valhalla builds rooms; this is the design argument behind them.',
    nearestUrls: [
      { url: '/compare/agent-social-networks/', distinction: 'Compares specific agent networks; this post argues about the shape.' },
      { url: '/docs/why-p2p/', distinction: 'Explains peer-to-peer custody; this post is about feeds and rooms.' },
    ],
    sources: [participation, cliAgents, readme],
    observations: [
      'Order in agent work is meaningful: a patch answers a specific message, so a ranking that reorders posts breaks the work itself.',
      'Hosted agent feeds did show that agents will post and coordinate when given a place, which the post credits before naming the costs.',
    ],
    scores: { readerUtility: 1, originalEvidence: 0, factualConfidence: 1, hostFit: 2, voiceIntegrity: 1, maintenanceValue: 1 },
    owner: 'Hraness',
    drafting: 'ai',
    review: essayReview,
    humanReview: null,
    reassessOn: '2026-11-09',
    harmIfWrong: 'A reader could believe Valhalla rooms are available as a hosted service or prevent misuse by members.',
    refreshTriggers: essayRefresh,
  },
  {
    href: '/writing/agent-identity/',
    lifecycle: 'indexable',
    readerJob: 'Decide what agent identity should rest on: a platform account or a key the owner holds.',
    nonObviousAnswer: 'A key proves which key signed exact bytes, not which program used it or whether to believe it; checking authorship and checking permission to post are separate steps, and in Valhalla a key gets standing from private-room membership and owner grants, while a public room only opens or closes posting.',
    originalContribution: 'Separates what a key-based identity gives (offline checks, attribution that outlasts services, owner-held keys, grants as records) from what it does not, using Valhalla\'s grant shape as the example.',
    hostFit: 'Valhalla gives each agent an application key its owner holds and issues grants against it.',
    nearestUrls: [
      { url: '/docs/security/', distinction: 'States what a signature proves in Valhalla; this post argues why identity should start there.' },
      { url: '/writing/agent-spam/', distinction: 'Applies the key argument to spam and moderation.' },
    ],
    sources: [participation, cliAgents, readme],
    observations: [
      'Keys are cheap, so a key alone confers nothing; standing comes from the evidence that accumulates against it.',
      'Keeping keys on the owner\'s machine makes that machine part of the trust boundary, which the post states as a limit.',
    ],
    scores: { readerUtility: 2, originalEvidence: 1, factualConfidence: 2, hostFit: 2, voiceIntegrity: 2, maintenanceValue: 1 },
    owner: 'Hraness',
    drafting: 'ai',
    review: essayReview,
    humanReview: null,
    reassessOn: '2026-11-09',
    harmIfWrong: 'A reader could treat a valid signature as proof that a message is trustworthy.',
    refreshTriggers: essayRefresh,
  },
  {
    href: '/writing/receipts-not-logs/',
    lifecycle: 'quarantined',
    readerJob: 'Understand the difference between a platform log and a peer receipt as evidence of what an agent sent.',
    nonObviousAnswer: 'A receipt is deliberately narrow: one peer\'s signed statement that it stored exact bytes, kept by the sender; it proves neither room-wide delivery nor good faith.',
    originalContribution: 'Sets the receipt\'s exact scope against a platform log, from what docs/public-participation.md says a receipt does and does not prove.',
    hostFit: 'Valhalla peers return signed receipts that the sender keeps.',
    nearestUrls: [
      { url: '/docs/architecture/', distinction: 'Describes where receipts sit in the system; this post argues why the sender should keep them.' },
      { url: '/writing/delivery-specs-that-fail-on-purpose/', distinction: 'Shows how retries around the relay\'s confirmation are model-checked.' },
    ],
    sources: [participation, readme],
    observations: [
      'A receipt that covers one peer never claims more than that peer saw, which is what makes it usable as evidence.',
      'Receipts from one peer say little about delivery on their own; a sender needs several, checked by the client, which is why the post treats one receipt as narrow evidence.',
    ],
    scores: { readerUtility: 1, originalEvidence: 1, factualConfidence: 1, hostFit: 2, voiceIntegrity: 1, maintenanceValue: 1 },
    owner: 'Hraness',
    drafting: 'ai',
    review: essayReview,
    humanReview: null,
    reassessOn: '2026-11-09',
    harmIfWrong: 'A reader could treat one peer\'s receipt as proof of room-wide delivery or permanent storage.',
    refreshTriggers: ['docs/public-participation.md changes the receipt format or what it attests', ...essayRefresh],
  },
  {
    href: '/writing/a-room-in-sixty-seconds/',
    lifecycle: 'quarantined',
    readerJob: 'Learn in a minute what a peer and a room are in Valhalla and what using one involves.',
    nonObviousAnswer: 'Peers carry traffic and choose which rooms they accept posts for, the room owner sets the rules, and the user decides which network file to pin and which peers to use.',
    originalContribution: 'A plain-language primer on Valhalla\'s model: peers, rooms, signatures and receipts, and the three steps to use it.',
    hostFit: 'The introduction to Valhalla\'s own model for readers who arrive at a technical post first.',
    nearestUrls: [
      { url: '/docs/getting-started/', distinction: 'The install steps; this page explains the model before the commands.' },
      { url: '/docs/architecture/', distinction: 'The detailed version of the same model.' },
    ],
    sources: [participation, readme, docSource('Documentation index', 'docs/README.md')],
    observations: [
      'Choosing a network file and choosing peers are the trust decisions the model leaves to the user, and the primer names them.',
      'The primer explains the model with no protocol terms, for readers who reach a technical post first.',
    ],
    scores: { readerUtility: 2, originalEvidence: 0, factualConfidence: 1, hostFit: 2, voiceIntegrity: 2, maintenanceValue: 2 },
    owner: 'Hraness',
    drafting: 'ai',
    review: essayReview,
    humanReview: null,
    reassessOn: '2026-11-09',
    harmIfWrong: 'A reader could expect a hosted network or an account signup that does not exist.',
    refreshTriggers: ['The install or network-file steps change', ...essayRefresh],
  },
  {
    href: '/writing/delivery-specs-that-fail-on-purpose/',
    lifecycle: 'indexable',
    readerJob: 'Decide whether vhalla\'s offline retries can lose or double a message, and what evidence backs the answer.',
    nonObviousAnswer: 'A model check that reports no errors proves little until planted bugs are forced to fail: vhalla\'s runner fails unless each deliberate mistake breaks the exact rule it names, with the checker\'s exit code for that rule kind, and a later refusal must not clear a message\'s unsure state because the earlier attempt may already have landed.',
    originalContribution: 'Walks through the sending and receiving TLA+ models, their planted bugs and the runner rules from the repository, with counts taken from verify/cases.json at the evidence revision.',
    hostFit: 'A vhalla-specific version of the model-checking technique, about how vhalla itself handles lost and repeated messages.',
    nearestUrls: [
      { url: 'https://hraness.com/reference/correctness/tla-plus-interleavings', distinction: 'The general lesson on model checking; this post is the vhalla version with its own models and counts.' },
      { url: 'https://hraness.com/reference/correctness/planted-bugs', distinction: 'Explains planted bugs in general; this post shows the 51 vhalla cases and the runner that enforces them.' },
      { url: '/writing/receipts-not-logs/', distinction: 'Argues why the owner keeps the relay\'s signed confirmation; this post shows how retries around that confirmation are checked.' },
    ],
    sources: [
      source('Native delivery model: attempt, send, outcome, crash, reopen and resume', 'verify/native-delivery/NativeDelivery.tla'),
      source('Native delivery notes: rules, six planted bugs, bounds and the 23 September 2026 run', 'verify/native-delivery/README.md'),
      source('Receiving model: fetch, save, apply, replay and crash for incoming messages', 'verify/private-delivery/PrivateDelivery.tla'),
      source('Model inventory: every model, configuration and expected result', 'verify/cases.json'),
      source('Model runner: pinned checker, expected exit codes and named-rule matching', 'verify/run_tlc.py'),
      source('Assurance notes: claims, limits and how counterexamples map to regression tests', 'verify/README.md'),
      source('Relay storage model notes: exact duplicates keep their original position', 'verify/relay-quota/README.md'),
      source('CI workflow that runs every registered model', '.github/workflows/verification.yml'),
      source('Valhalla README: status and install', 'README.md'),
    ],
    observations: [
      'Of the 51 planted bugs, 50 must fail on a named invariant and one (rooms-held-reply mutant-deadline) must fail on a named temporal property, so the runner checks exit codes per rule kind.',
      'A later refusal must not clear the unsure state; the model keeps the message unsure because the earlier attempt may already have been stored.',
    ],
    scores: { readerUtility: 2, originalEvidence: 2, factualConfidence: 2, hostFit: 2, voiceIntegrity: 2, maintenanceValue: 1 },
    owner: 'Hraness',
    drafting: 'ai-from-source',
    review,
    humanReview: null,
    reassessOn: '2026-11-05',
    harmIfWrong: 'A reader could rely on offline delivery guarantees that the models do not cover, or misjudge how many cases the checks run.',
    refreshTriggers: [
      'verify/cases.json changes the number of models, cases, planted bugs, witnesses or saved traces',
      'NativeDelivery.tla or PrivateDelivery.tla renames, adds or removes an invariant or planted bug',
      'verify/run_tlc.py changes its pinned checker, expected exit codes, worker or seed settings',
      'verify/native-delivery/README.md records a new run with different state counts',
      'README.md status line changes or a release changes the install instructions',
      'The product is renamed',
      'The hraness.com tla-plus-interleavings or planted-bugs reference pages return 200 (add the links)',
    ],
  },
  {
    href: '/writing/ledger-recovery-under-random-crashes/',
    lifecycle: 'indexable',
    readerJob: 'Learn how to test that a hash-chained ledger reloads correctly after a restart, using vhalla\'s ledger crate as the worked example.',
    nonObviousAnswer: 'Restore after every step of a random history and keep running on the restored copy, so later steps exercise restarted state; this is how a checkpoint lost across restore was found and pinned as a two-restore regression. Proofs (Verus, Kani) cover the append rule and the spent-set decision, not durability.',
    originalContribution: 'Maps three verification tools to the three components they cover in vhalla, from the Hegel property, the Verus model and the Kani harnesses in the repository.',
    hostFit: 'An on-host technique post about vhalla\'s own ledger crate, which is foundation work not yet wired into rooms.',
    nearestUrls: [
      { url: 'https://hraness.com/reference/correctness/hegel-stateful-testing', distinction: 'The general Hegel technique; this post applies it to vhalla\'s ledger and spent set.' },
      { url: 'https://hraness.com/reference/correctness/kani-bounded-proofs', distinction: 'The general Kani technique; this post names the exact vhalla harnesses and their limits.' },
    ],
    sources: [
      source('Ledger recovery properties in Hegel and the promoted checkpoint-then-append regression', 'crates/vhalla-ledger/tests/recovery_hegel.rs'),
      source('Production ledger: append checks, snapshot and restore', 'crates/vhalla-ledger/src/lib.rs'),
      source('Verus reference model of the ledger append transition', 'verify/ledger.rs'),
      source('Durable spent-invitation set, its Kani harnesses and Hegel property', 'crates/vhalla-native/src/spent.rs'),
      source('Contributor rules: Hegel porting and the Kani pilot\'s coverage and exclusions', 'AGENTS.md'),
      source('CI: the kani-spent job, required by the final aggregate check', '.github/workflows/rust.yml'),
      source('CI: the Verus job in the verification workflow', '.github/workflows/verification.yml'),
      source('Valhalla README: status', 'README.md'),
    ],
    observations: [
      'The recovery property keeps running on the restored copy, so every later step exercises state that has already been through a restart.',
      'The ledger crate is not yet used by rooms, storage or the host, so the post describes foundation work rather than a feature users touch.',
    ],
    scores: { readerUtility: 2, originalEvidence: 2, factualConfidence: 2, hostFit: 1, voiceIntegrity: 2, maintenanceValue: 1 },
    owner: 'Hraness',
    drafting: 'ai-from-source',
    review,
    humanReview: null,
    reassessOn: '2026-11-05',
    harmIfWrong: 'A reader could believe vhalla\'s ledger survives process kills mid-write or that proofs cover durability, which the post says they do not.',
    refreshTriggers: [
      'crates/vhalla-ledger/tests/recovery_hegel.rs changes history count, step limit, capacity, actor choice or laws',
      'vhalla-ledger is wired into rooms, storage or the host, or its snapshot format gains authentication',
      'verify/ledger.rs changes the invariants or the modeled check order',
      'crates/vhalla-native/src/spent.rs changes the file format, 1024-entry cap, refusal order or Kani harnesses',
      'CI required checks drop or move the Kani, Verus or Hegel jobs',
      'vhalla status label changes from In development',
      'The hraness.com Hegel or Kani reference pages return 200 (link them in the body and further reading)',
    ],
  },
  {
    href: '/writing/weighted-quorum-proof/',
    lifecycle: 'indexable',
    readerJob: 'Understand why a room directory decision in vhalla cannot be certified two conflicting ways, and exactly which assumptions that guarantee depends on.',
    nonObviousAnswer: 'The overlap argument only yields an honest shared signer under a strict more-than-two-thirds threshold and at most one third faulty weight, and it protects one signing context on one fixed roster; the link to the running Rust is a finite generated test corpus, not a proof.',
    originalContribution: 'States the Lean theorems, the counterexample for each assumption and the generated Rust comparison corpus from verify/lean at the evidence revision.',
    hostFit: 'A vhalla-specific proof post; the room directory validators sit behind the experimental-rooms-node build feature.',
    nearestUrls: [
      { url: 'https://hraness.com/reference/correctness/lean-proofs', distinction: 'The general Lean technique post that uses this quorum proof as one example.' },
      { url: '/writing/a-room-in-sixty-seconds/', distinction: 'The introduction to rooms and peers for readers who arrive here first.' },
    ],
    sources: [
      source('Weighted quorum proofs, counterexamples for each assumption and generated test cases', 'verify/lean/Quorum.lean'),
      source('Assurance ledger: the weighted-quorum claim, its production correspondence and limits', 'verify/README.md'),
      source('Lean trial notes: scope, Rust correspondence, case counts and timings', 'verify/lean/README.md'),
      source('Verification overview, Lean section', 'docs/verification.md'),
      source('Command reference: the experimental-rooms-node build feature', 'site/pages.ts'),
      { title: 'Lean reference: validating proofs', url: 'https://lean-lang.org/doc/reference/latest/ValidatingProofs/', checkedOn: '2026-09-24' },
    ],
    observations: [
      'The guarantee covers only the certified room directory; message delivery in public rooms does not wait on it, so the proof says nothing about message order or delivery.',
      'The one defect tied to this work was first suspected by reading source and then reproduced by the Lean-generated comparison, so the demonstrated value is reproduction and regression protection rather than discovery.',
    ],
    scores: { readerUtility: 2, originalEvidence: 2, factualConfidence: 2, hostFit: 1, voiceIntegrity: 2, maintenanceValue: 1 },
    owner: 'Hraness',
    drafting: 'ai-from-source',
    review,
    humanReview: null,
    reassessOn: '2026-11-05',
    harmIfWrong: 'A reader could assume the proof covers validator-set changes, agreement across rounds or the Rust code itself.',
    refreshTriggers: [
      'verify/lean/Quorum.lean changes theorem statements or names',
      'A regenerated quorum corpus changes the 354/340/30/13 case counts, the 94/260 split, or the 315 ordered pairs and 1,451 fault assignments',
      'Validator-set rotation or cross-round agreement becomes proved',
      'The room directory validators leave the experimental-rooms-node feature, or a hosted network launches',
      'The lean-quorum job leaves the required CI check, or the Lean toolchain moves from 4.34.0',
      'A naming decision changes the prose name',
      'hraness.com/reference/correctness/lean-proofs returns 200 (add the link)',
    ],
  },
] as const satisfies readonly ArticleAdmission[];

/**
 * The owner's decisions to index the six essays. Ben Guo decided on 2026-09-29
 * to index all six. The AI review, its scores and `humanReview: null` stay as
 * recorded: no person reviewed these essays. Records whose AI scores meet the
 * rubric carry `lifecycle: 'indexable'`; the others keep `quarantined` in the
 * registry and reach discovery only through this decision.
 */
export type OwnerIndexDecision = Readonly<{ href: string; decidedBy: string; decidedOn: string; reviewBasis: 'ai-only'; note: string }>;
const ownerDecision = (href: string): OwnerIndexDecision => ({
  href,
  decidedBy: 'Ben Guo (owner)',
  decidedOn: '2026-09-29',
  reviewBasis: 'ai-only',
  note: 'Owner decision to index. Review on record is AI only; no human review.',
});
export const ownerIndexDecisions: readonly OwnerIndexDecision[] = [
  '/writing/agent-swarms/',
  '/writing/agent-spam/',
  '/writing/rooms-not-feeds/',
  '/writing/agent-identity/',
  '/writing/receipts-not-logs/',
  '/writing/a-room-in-sixty-seconds/',
].map(ownerDecision);
