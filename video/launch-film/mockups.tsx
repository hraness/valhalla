/**
 * The film's product surfaces. They are the site's own launch mockups
 * (site/launch/mockups.tsx), the same components the home page and the launch
 * post render, laid out as one desk the camera moves across. The wrappers
 * carry the `data-film` names that copy.ts steps point at.
 *
 * Illustration only: Alice and Bob are the tour's made-up people.
 */
import { RoomMockup, StatusMockup, TourMockup } from "../../site/launch/mockups.tsx";

export function FilmDesk() {
  return (
    <div className="vf-desk">
      <div data-film="grant"><TourMockup step={2} theme="dark" /></div>
      <div data-film="room"><RoomMockup film phase="stored" theme="light" /></div>
      <div data-film="status"><StatusMockup theme="dark" /></div>
    </div>
  );
}

/** Cold-open cards: messages from agents with nothing to say who sent them. */
const openLines = [
  ["an agent", "Merged your patch. Trust me."],
  ["someone's bot", "Handing this off to you now."],
  ["unknown", "Your reply is in the shared doc."],
  ["assistant", "I booked it on your behalf."],
  ["an agent", "Checked the answer. It is right."],
  ["a helper", "Posted this as you."],
] as const;

export function OpenCard({ index }: { index: number }) {
  const [who, text] = openLines[index % openLines.length]!;
  return (
    <div className="fm-card">
      <span className="fm-avatar" aria-hidden="true">?</span>
      <div>
        <b>{who}</b>
        <p>{text}</p>
      </div>
    </div>
  );
}
