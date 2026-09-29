// Code-built illustrations of Valhalla's real screens: the `vhalla demo` tour
// in a terminal, a room as the browser client shows it, and `vhalla status`.
// The home page, the launch post and the launch film all render these, so the
// three always show the same thing. Text comes from site/launch/tour.ts (the
// tour in demo.rs) and the status goldens under crates/vhalla-cli/tests; names
// are the tour's made-up Alice and Bob.
//
// The site's CSP allows no inline style attributes, so these use only mockup
// parts that render without one (no Avatar, no fixed heights), and the step
// controls are radio buttons styled in site/launch/launch.css, with no script.
import { readFileSync } from 'node:fs';
import type { ReactNode } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { BrowserWindow, MockupRoot, TerminalFrame, type MockupTheme, type TerminalLine } from '@hraness/design-kit/mockups';
import { tourSteps, tourText, type TourStep } from './tour.ts';

/** Where the status goldens live; the status mockup shows one verbatim. */
/**
 * A copy of crates/vhalla-cli/tests/fixtures/status/in-sync.w80.txt, kept in site/
 * because the Vercel build uploads site/ without crates/. launch.test.ts fails
 * when the copy drifts from the CLI golden.
 */
export const statusGoldenPath = new URL('./fixtures/status-in-sync.w80.txt', import.meta.url);

export function tourLines(step: TourStep): TerminalLine[] {
  const lines: TerminalLine[] = [{ kind: 'comment', text: `${step.step}/${tourSteps.length} · ${step.title}`, beat: `step-${step.step}` }];
  for (const text of step.body.split('\n')) lines.push({ kind: 'output', text, tone: 'muted' });
  for (const { command, result } of step.commands) {
    lines.push({ kind: 'input', text: command });
    lines.push({ kind: 'output', text: result });
  }
  if (step.commands.length === 0) {
    lines.push({ kind: 'output', text: 'Delete that directory and every trace is gone.' });
  }
  return lines;
}

export function TourMockup({ step, theme }: { step: number; theme?: MockupTheme }) {
  const found = tourSteps.find(item => item.step === step);
  if (!found) throw new RangeError(`The tour has no step ${step}.`);
  return (
    <TerminalFrame
      describe={`Illustration of step ${step} of the vhalla demo tour in a terminal: ${found.title.toLowerCase()}.`}
      lines={tourLines(found)}
      title="vhalla demo"
      {...(theme ? { theme } : {})}
    />
  );
}

/**
 * All eight tour steps behind one set of step buttons. Each button is a radio
 * input, so the stepper works with the keyboard and without JavaScript; with
 * CSS off every step shows in order.
 */
export function TourStepper({ id }: { id: string }) {
  return (
    <div className="vh-tour" data-vh-tour={id}>
      <fieldset className="vh-tour-controls">
        <legend>Step through the tour</legend>
        {tourSteps.map(step => (
          <span className="vh-tour-choice" key={step.step}>
            <input defaultChecked={step.step === 1} id={`${id}-${step.step}`} name={id} type="radio" value={String(step.step)} />
            <label htmlFor={`${id}-${step.step}`} title={step.title}>
              <span className="vh-tour-number">{step.step}</span>
              <span className="vh-tour-label">{step.title}</span>
            </label>
          </span>
        ))}
      </fieldset>
      <div className="vh-tour-panels">
        {tourSteps.map(step => (
          <div className="vh-tour-panel" data-vh-step={step.step} key={step.step}>
            <TourMockup step={step.step} />
          </div>
        ))}
      </div>
    </div>
  );
}

export const roomPhases = ['grant', 'provisional', 'sealed', 'reply', 'stored'] as const;
export type RoomPhase = (typeof roomPhases)[number];

const phaseDescription: Record<RoomPhase, string> = {
  grant: 'Alice gives her agent a signed grant to post and set a bio for one hour.',
  provisional: 'The agent\'s signed post waits, marked provisional, until Alice seals it.',
  sealed: 'Alice seals the agent\'s post, and it shows as committed with both keys.',
  reply: 'Bob replies from his own machine, signed with his own key.',
  stored: 'A peer Alice chose confirms, in a signed note, that it stored the thread.',
};

function Badge({ tone, children }: { tone: 'ok' | 'wait' | 'key'; children: ReactNode }) {
  return <span className="vh-badge" data-vh-tone={tone}>{children}</span>;
}

function Post({ name, role, keyId, children, state, detail, film }: { name: string; role: string; keyId: string; children: ReactNode; state?: ReactNode; detail?: ReactNode; film?: string }) {
  return (
    <li className="vh-post" data-film={film}>
      <span aria-hidden="true" className="vh-post-mark" data-vh-role={role}>{name.slice(0, 1)}</span>
      <div className="vh-post-body">
        <p className="vh-post-meta">
          <strong>{name}</strong>
          <span className="vh-post-role">{role}</span>
          <Badge tone="key">signed · {keyId}…</Badge>
          {state}
        </p>
        <p className="vh-post-text">{children}</p>
        {detail}
      </div>
    </li>
  );
}

/**
 * A room in the browser client, at one moment of the tour's story. Every post
 * shows the key that signed it; the agent's post shows whether Alice has
 * sealed it yet.
 */
export function RoomMockup({ phase, theme, film = false }: { phase: RoomPhase; theme?: MockupTheme; film?: boolean }) {
  const at = roomPhases.indexOf(phase);
  if (at < 0) throw new RangeError(`Unknown room phase ${JSON.stringify(phase)}.`);
  const sealed = at >= roomPhases.indexOf('sealed');
  return (
    <MockupRoot describe={`Illustration of a Valhalla room in a browser, with made-up people. ${phaseDescription[phase]}`} kind="vh-room" {...(theme ? { theme } : {})}>
      <BrowserWindow url="localhost/rooms/demo">
        <div className="vh-room">
          <div className="vh-room-head">
            <span className="vh-room-name"># demo</span>
            <span className="vh-room-members">Alice · Alice's agent · Bob</span>
          </div>
          {phase === 'grant' ? (
            <div className="vh-grant">
              <p className="vh-grant-title">Grant for Alice's agent</p>
              <dl>
                <div><dt>Can</dt><dd>post, set bio</dd></div>
                <div><dt>Expires</dt><dd>in 1 hour</dd></div>
                <div><dt>Signed by</dt><dd>Alice · {tourText.keys.alice}…</dd></div>
              </dl>
              <p className="vh-grant-foot">Alice can revoke it at any time.</p>
            </div>
          ) : (
            <ol className="vh-posts">
              <Post
                keyId={tourText.keys.agent}
                name="Alice's agent"
                role="agent"
                state={film ? (
                  // The film seals the post on screen: both badges render, and
                  // video/launch-film/film.css shows one by the post's film state.
                  <><Badge tone="wait">provisional · waiting for Alice</Badge><Badge tone="ok">committed · sealed by Alice</Badge></>
                ) : sealed ? <Badge tone="ok">committed · sealed by Alice</Badge> : <Badge tone="wait">provisional · waiting for Alice</Badge>}
                {...(film ? { film: 'agent-post' } : {})}
              >
                {tourText.agentPost}
              </Post>
              {at >= roomPhases.indexOf('reply') ? (
                <Post
                  keyId={tourText.keys.bob}
                  name="Bob"
                  role="owner"
                  {...(film ? { film: 'bob-post' } : {})}
                  state={<Badge tone="ok">committed</Badge>}
                  detail={phase === 'stored' ? (
                    <p className="vh-stored" data-film={film ? 'stored' : undefined}>
                      <strong>Stored by peer-2</strong>
                      <span>Signed note from the peer: it holds this thread. Alice keeps a copy on her machine.</span>
                    </p>
                  ) : undefined}
                >
                  {tourText.bobReply}
                </Post>
              ) : null}
            </ol>
          )}
          <div aria-hidden="true" className="vh-composer">Write as Alice · signs with {tourText.keys.alice}…</div>
        </div>
      </BrowserWindow>
    </MockupRoot>
  );
}

export function statusLines(): TerminalLine[] {
  const golden = readFileSync(statusGoldenPath, 'utf8').trimEnd().split('\n');
  const end = golden.indexOf('');
  return [
    { kind: 'input', text: 'vhalla status' },
    ...golden.slice(0, end < 0 ? undefined : end).map(text => ({ kind: 'output' as const, text })),
  ];
}

/** `vhalla status` with every room in sync, from the CLI's own golden output. */
export function StatusMockup({ theme }: { theme?: MockupTheme }) {
  return (
    <TerminalFrame
      describe="Illustration of vhalla status in a terminal: four rooms in sync, nothing waiting, and the newest agent outputs."
      lines={statusLines()}
      title="vhalla status"
      {...(theme ? { theme } : {})}
    />
  );
}

export const renderMockup = (node: ReactNode) => renderToStaticMarkup(<>{node}</>);

/** The home page's two illustrations, as HTML for the string-built page. */
export const homeTourHtml = () => renderMockup(<TourStepper id="home-tour" />);
export const homeRoomHtml = () => renderMockup(<RoomMockup phase="stored" />);
