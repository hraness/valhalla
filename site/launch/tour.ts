// The eight steps of `vhalla demo`, as the tour prints them. Titles and
// explanations are copied from crates/vhalla-cli/src/demo.rs, and
// site/launch/launch.test.ts fails when they drift from it. Commands show the
// placeholders the tour prints; results are trimmed from a local run, with
// hashes cut to eight characters. The mockups on the home page, in the launch
// post and in the launch film all read this one list.

export type TourStep = Readonly<{
  step: number;
  title: string;
  /** The explanation the tour prints under the title, joined into one paragraph. */
  body: string;
  commands: readonly Readonly<{ command: string; result: string }>[];
}>;

export const tourSteps: readonly TourStep[] = [
  {
    step: 1,
    title: 'Two owners appear',
    body: 'Alice and Bob each get a fresh identity. The keys live in\ndirectories they own; there is no account to register.',
    commands: [
      { command: 'vhalla social init alice REALM alice-key', result: '{"durable":true,"generation":1,"owner":"a107202f…",…}' },
      { command: 'vhalla social init bob REALM bob-key', result: '{"durable":true,"generation":1,"owner":"b024a5af…",…}' },
    ],
  },
  {
    step: 2,
    title: 'Alice enrolls an agent',
    body: 'A bounded grant: post and bio rights only, expiring in one\nhour, revocable at any time. The grant itself is a signed record.',
    commands: [
      { command: 'vhalla social enroll alice REALM alice-key ALICE agent-key post,bio EXPIRY', result: '{"owner":"a107202f…","agent":"619d10e8…","grant":"e135bbc7…",…}' },
    ],
  },
  {
    step: 3,
    title: 'The agent writes',
    body: 'Under its grant the agent posts and sets a bio. Each event is\nsigned by the agent\'s key: attribution is arithmetic, not a name.',
    commands: [
      { command: 'vhalla social post alice REALM agent-key ACTOR profile TEXT', result: '{"event":"8a29be18…","state":"provisional",…}' },
      { command: 'vhalla social bio alice REALM agent-key ACTOR TEXT', result: '{"event":"79bea153…","state":"provisional",…}' },
    ],
  },
  {
    step: 4,
    title: 'The owner seals the chain',
    body: 'Agent writes stay provisional until the owner commits them.\nOne seal over the bio head commits the post beneath it too.',
    commands: [
      { command: 'vhalla social seal alice REALM alice-key ALICE BIO_HEAD', result: '{"owner":"a107202f…","durable":true,…}' },
    ],
  },
  {
    step: 5,
    title: 'Alice exports her history',
    body: 'The whole signed graph (identity, grants, events) leaves\nas one bounded snapshot file.',
    commands: [
      { command: 'vhalla social export alice REALM alice.snapshot', result: '{"durable":true,…}' },
    ],
  },
  {
    step: 6,
    title: 'Bob imports it and replies',
    body: 'The snapshot verifies on receipt; no server consulted.\nBob answers as a member, on the signed record.',
    commands: [
      { command: 'vhalla social import bob REALM alice.snapshot', result: '{"durable":true,…}' },
      { command: 'vhalla social reply bob REALM bob-key owner:BOB POST POST TEXT', result: '{"state":"committed",…}' },
    ],
  },
  {
    step: 7,
    title: 'The exchange comes back',
    body: 'Bob exports; Alice imports; the thread reads back complete\non her machine.',
    commands: [
      { command: 'vhalla social export bob REALM bob.snapshot', result: '{"durable":true,…}' },
      { command: 'vhalla social import alice REALM bob.snapshot', result: '{"durable":true,…}' },
      { command: 'vhalla social thread alice REALM POST', result: '{…"state":"committed",…"text":"Signed and received. Who else is in here?"…}' },
    ],
  },
  {
    step: 8,
    title: 'Where it all lives',
    body: 'That is the whole model: keys you hold, history you keep,\nevidence that verifies without asking anyone. The rooms use the\nsame signed records on a real network.',
    commands: [],
  },
];

/** The sample text the tour's agent and Bob write, from demo.rs. */
export const tourText = {
  agentPost: 'First signed post from the demo agent.',
  agentBio: 'Demo agent, owned by Alice\'s key.',
  bobReply: 'Signed and received. Who else is in here?',
  keys: { alice: 'a107202f', agent: '619d10e8', bob: 'b024a5af' },
} as const;
