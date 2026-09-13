---
name: Valhalla marketing
description: A quiet, readable introduction to an early protocol project.
colors:
  paper: "#f3f1e9"
  ink: "#272b25"
  muted: "#606258"
  accent: "#9a402f"
  line: "#d2d3c7"
  selected: "#e9cebf"
typography:
  display:
    fontFamily: "Instrument Serif, Georgia, serif"
    fontSize: "clamp(64px, 6.8vw, 96px)"
    fontWeight: 400
    lineHeight: 0.99
    letterSpacing: "-0.025em"
  body:
    fontFamily: "-apple-system, BlinkMacSystemFont, Segoe UI, sans-serif"
    fontSize: "16px"
    lineHeight: 1.6
spacing:
  mobile-inset: "24px"
  desktop-inset: "64px"
components:
  primary-link:
    textColor: "{colors.accent}"
---

## Overview

Keep the marketing page as a brief introduction while the protocol evolves.
A large, readable headline sits alongside one explicitly imagined conversation.
The source and design documents are the destinations. No signup or app-like UI.

## Colors

Paper, dark ink, and a restrained rust accent. The muted text color remains
readable against the paper. Selection and keyboard focus use the same palette.

## Typography

Self-host Instrument Serif for the headline, system sans for prose, and
monospace only for channel and participant identifiers. The font is OFL licensed.

## Layout

At desktop widths, use a two-column introduction inside a 1,248px page.
At 640px and below, stack the conversation after the introduction. Content
remains visible without animation or JavaScript. Rules separate status and footer.

## Elevation & Depth

Flat surfaces, no shadows. One-pixel rules carry grouping.

## Components

Use ordinary links with visible keyboard focus. The room example is a definition
list with an explicit illustrative label. The status section states that the
network and client are still in development.

## Do's and Don'ts

Keep copy brief, retain the prototype status, and link to source evidence.
Avoid invented adoption metrics, live activity, install claims, and feature grids.
This visual pass was inspected locally; an independent finish reviewer was
unavailable after the parallel workers reached the account usage limit.
