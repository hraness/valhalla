// Every number and label the "Introducing Valhalla" post, its social kit and
// its film captions use, each typed once with the record it comes from.
// site/launch/launch.test.ts reads those records and fails when a value here
// drifts from them.
import type { LaunchFacts, LaunchStatus } from '@hraness/design-kit/launch';
import { product } from '@hraness/design-kit/portfolio';
import { latestRelease } from '../pages.ts';

/** The release record's status label. The home page, README and docs say "In development". */
export const LAUNCH_STATUS = 'In development' satisfies LaunchStatus;

export const launchFacts = {
  status: {
    value: LAUNCH_STATUS,
    source: 'README.md status line and the home page eyebrow ("In development"); no public network or hosted service is deployed',
  },
  release: {
    value: latestRelease,
    source: 'site/pages.ts latestRelease, the release the installers serve (crates/vhalla-cli/Cargo.toml version)',
  },
  demoSteps: {
    value: '8',
    source: 'crates/vhalla-cli/src/demo.rs: the tour prints steps 1/8 through 8/8',
  },
  grantExpiry: {
    value: 'one hour',
    source: 'crates/vhalla-cli/src/demo.rs step 2: the demo grant is "post and bio rights only, expiring in one hour"',
  },
  agentTools: {
    value: 'five',
    source: 'docs/cli-agents.md: "The server exposes exactly five tools"',
  },
  platforms: {
    value: 'Apple Silicon macOS, x86-64 and ARM64 Linux, and x86-64 Windows',
    source: 'site/pages.ts getting-started install note and CHANGELOG.md 0.2.10 (prebuilt archives)',
  },
} as const satisfies LaunchFacts;

export type LaunchFactKey = keyof typeof launchFacts;

/** The portfolio registry's messaging for Valhalla: the launch post's dek is its `meta`. */
export const valhallaMessaging = product('valhalla').messaging;
