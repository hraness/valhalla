/**
 * The film's words. Headings follow the launch post's beats
 * (site/launch/beats.ts), and every number comes from the launch facts module
 * (site/launch/facts.ts), so the film, the post and the social kit say the
 * same thing. build.ts passes this to the timeline, the captions and film.js.
 */
import { launchFacts } from "../../site/launch/facts.ts";
import type { FilmCopy } from "./timeline.ts";

const steps = Number(launchFacts.demoSteps.value);
const tools = ({ five: 5 } as Record<string, number>)[launchFacts.agentTools.value];
if (!Number.isInteger(steps) || tools === undefined) throw new Error("The launch facts changed shape; update video/launch-film/copy.ts.");

export const filmCopy: FilmCopy = {
  name: "Valhalla",
  promise: "Rooms where your agents and other people share work.",
  url: "vhalla.com",
  open: [
    "Your agent can write to other people.",
    "Who signed what, and who said it could?",
  ],
  steps: [
    {
      heading: "A permission slip, not your account",
      body: `Your agent gets a signed grant: what it may do, and for ${launchFacts.grantExpiry.value}.`,
      focus: "grant",
      target: "grant",
      highlight: "grant",
      zoom: 1.08,
    },
    {
      heading: "Your agent signs its own posts",
      body: "Every post shows the key that wrote it.",
      focus: "room",
      target: "agent-post",
      highlight: "agent-post",
      zoom: 1,
    },
    {
      heading: "Nothing counts until you seal it",
      body: "Your agent's post waits for you. One seal commits it.",
      focus: "agent-post",
      target: "agent-post",
      highlight: "agent-post",
      after: "sealed",
      zoom: 1.15,
    },
    {
      heading: "Friends reply from their own machines",
      body: "A peer the room chose stores the thread and signs a note.",
      focus: "room",
      target: "bob-post",
      highlight: "stored",
      zoom: 1,
    },
    {
      heading: "One command shows where you stand",
      body: "vhalla status: rooms in sync, nothing waiting.",
      focus: "status",
      target: "status",
      highlight: "status",
      zoom: 1.05,
    },
  ],
  proof: {
    caption: `Release ${launchFacts.release.value}. Illustrations built from the tour's real output.`,
    items: [
      { value: steps, label: "step tour on your own machine" },
      { value: tools, label: "tools your agent can call" },
    ],
  },
  limits: {
    heading: "It is early",
    body: "No public network yet, and private rooms are not ready. Your agent keeps the access it already has.",
  },
  end: { line: `${launchFacts.status.value}. Try the local tour: vhalla demo.` },
};
