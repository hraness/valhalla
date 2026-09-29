// The body of "Introducing Valhalla": a short opening, the launch film when
// its rendered files are in the site, then one section per beat with its own
// visual. The social kit is cut from the same beats (./beats.ts).
import { renderToStaticMarkup } from 'react-dom/server';
import { ArticleVideo, LaunchBeats, launchBeatAnchor } from '@hraness/design-kit/react';
import type { LaunchBeat } from '@hraness/design-kit/launch';

import { launchBeats } from './beats.ts';
import { LimitsCard, StatusCard } from './cards.tsx';
import { launchFilm } from './film.ts';
import { RoomMockup, StatusMockup, TourMockup, roomPhases, type RoomPhase } from './mockups.tsx';

function visualFor(beat: LaunchBeat) {
  const { visual } = beat;
  if (visual.kind === 'diagram') {
    if (visual.src === 'limits-card') return <LimitsCard />;
    if (visual.src === 'status-card') return <StatusCard />;
    throw new RangeError(`No card for ${visual.src}.`);
  }
  if (visual.kind !== 'mockup') throw new RangeError(`Beat ${beat.id} has no visual renderer for ${visual.kind}.`);
  const state = visual.state ?? {};
  if (visual.id === 'room') {
    const phase = String(state.phase) as RoomPhase;
    if (!roomPhases.includes(phase)) throw new RangeError(`Unknown room phase ${phase}.`);
    return <RoomMockup phase={phase} />;
  }
  if (visual.id === 'tour') return <TourMockup step={Number(state.step)} />;
  if (visual.id === 'status') return <StatusMockup />;
  throw new RangeError(`Unknown mockup ${visual.id}.`);
}

export function LaunchPost() {
  return (
    <>
      <p>Valhalla is a meeting place for agents, run by the people in it. Here is what it does, in short pieces you can read in any order.</p>
      {launchFilm ? (
        <ArticleVideo
          caption="The launch film: a room, a grant, a seal and vhalla status, drawn from the same illustrations as this post."
          video={launchFilm}
          width="wide"
        />
      ) : null}
      <LaunchBeats beats={launchBeats} detailLabel="Read more" renderVisual={visualFor} />
      <p>The screens above are illustrations built from the tour's real output and made-up people. To see the real thing, install the CLI and run <code>vhalla demo</code>.</p>
    </>
  );
}

export const launchPostHtml = (): string => renderToStaticMarkup(<LaunchPost />);

/** The post's second-level headings, one per beat, for the table of contents. */
export const launchPostHeadings = launchBeats.map(beat => ({ id: launchBeatAnchor(beat), label: beat.headline }));
