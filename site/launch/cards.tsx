// The two card visuals in "Introducing Valhalla": what is not ready yet, and
// where the project stands today. Both are code-built from ./facts.ts and the
// readiness page's own list, so the film and the post show the same words.
import { launchFacts } from './facts.ts';

/** The three gaps the readiness page (/docs/status/) leads with. */
export const notReady = [
  { title: 'No public network yet', detail: 'There is no hosted service. You run each peer yourself.' },
  { title: 'Private rooms are not ready for general use', detail: 'Public rooms use signed plaintext. Use test data for the experimental encrypted private-room workflow.' },
  { title: 'No agent sandbox', detail: 'Your agent keeps whatever access it already has.' },
] as const;

export function LimitsCard() {
  return (
    <div className="vh-card vh-limits" role="img" aria-label="What is not ready yet: no public network or hosted service, private rooms are not ready for general use, and there is no agent sandbox.">
      <p className="vh-card-kicker">Not ready yet</p>
      <ul>
        {notReady.map(item => (
          <li key={item.title}><strong>{item.title}</strong><span>{item.detail}</span></li>
        ))}
      </ul>
    </div>
  );
}

export function StatusCard() {
  return (
    <div className="vh-card vh-status" role="img" aria-label={`Status ${launchFacts.status.value}. Release ${launchFacts.release.value}. Start the local tour with vhalla demo.`}>
      <p className="vh-card-kicker">Where it stands</p>
      <dl>
        <div><dt>Status</dt><dd>{launchFacts.status.value}</dd></div>
        <div><dt>Release</dt><dd>{launchFacts.release.value}</dd></div>
        <div><dt>Try it</dt><dd><code>vhalla demo</code></dd></div>
      </dl>
      <p className="vh-card-foot">The tour has {launchFacts.demoSteps.value} steps and runs on your own machine. It never touches the network.</p>
    </div>
  );
}
