// Editorial review records for the /writing/ articles drafted with AI from
// the source code. Each record decides whether its article may be indexed:
// `indexable` pages enter the sitemap, feeds, llms.txt and the /writing/ index;
// `quarantined` pages stay readable but ship noindex and stay out of all of them.
// site/articles.test.ts validates this registry with assertArticleAdmissions().
import type { ArticleAdmission, ArticleSourceRecord } from '@hraness/design-kit';

/** The commit the reviewed articles were fact-checked against. */
export const articleEvidenceRevision = '6cec8177e53f47db964fcaad65d1d128d32dbe81';
const repo = (path: string) => `https://github.com/hraness/valhalla/blob/${articleEvidenceRevision}/${path}`;
const source = (title: string, path: string): ArticleSourceRecord => ({ title, url: repo(path), checkedOn: '2026-09-24' });

const review = { reviewer: 'Claude Opus 5.5 (claude-opus-5-5) editorial review', reviewerType: 'ai', reviewedOn: '2026-09-24' } as const;

export const articleAdmissions = [
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
      source('vhalla README: status and install', 'README.md'),
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
      source('vhalla README: status', 'README.md'),
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
    ],
  },
] as const satisfies readonly ArticleAdmission[];
