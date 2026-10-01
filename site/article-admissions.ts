// Named AI reviews and source records for the public article collection.
// See site/editorial-review-20260930.json for scope and source limitations.
import type { ArticleAdmission } from '@hraness/design-kit';
export const articleEvidenceRevision = '6cec8177e53f47db964fcaad65d1d128d32dbe81';
export const launchEvidenceRevision = '13fe88c119bec94eb26815bd363aade66dea3933';
export const irohEvidenceRevision = '28a4f60dfa1c38265027abfadaba1284244d47a8';
export const articleAdmissions = [
  {
    "href": "/writing/introducing-valhalla/",
    "lifecycle": "indexable",
    "readerJob": "decide whether to try it",
    "nonObviousAnswer": "The local tour demonstrates expiring signed grants and owner sealing. Public rooms use signed posts and peer receipts; private agent sessions use locally issued grants through admitted devices. These workflows have separate operating requirements.",
    "originalContribution": "Short, standalone beats built from the real vhalla demo tour and the vhalla status golden output, each with its own code-built illustration, so the social posts are cut from the post itself.",
    "hostFit": "The product introduction on the product's own site, linking to the setup guide and the readiness page.",
    "nearestUrls": [
      {
        "url": "/",
        "distinction": "The home page lists what the product does; this post explains why it exists and what is not ready, one beat at a time."
      },
      {
        "url": "/writing/a-room-in-sixty-seconds/",
        "distinction": "The primer on peers and rooms; this post is the launch introduction with the tour and status."
      },
      {
        "url": "/docs/status/",
        "distinction": "The full readiness list; the post names only the three largest gaps."
      }
    ],
    "sources": [
      {
        "title": "Guided tour: the eight steps, titles and explanations",
        "url": "https://github.com/hraness/valhalla/blob/13fe88c119bec94eb26815bd363aade66dea3933/crates/vhalla-cli/src/demo.rs",
        "checkedOn": "2026-09-29"
      },
      {
        "title": "vhalla status golden output (in sync, 80 columns)",
        "url": "https://github.com/hraness/valhalla/blob/13fe88c119bec94eb26815bd363aade66dea3933/crates/vhalla-cli/tests/fixtures/status/in-sync.w80.txt",
        "checkedOn": "2026-09-29"
      },
      {
        "title": "Private rooms for CLI agents: grants, budgets, expiry and the five tools",
        "url": "https://github.com/hraness/valhalla/blob/13fe88c119bec94eb26815bd363aade66dea3933/docs/cli-agents.md",
        "checkedOn": "2026-09-29"
      },
      {
        "title": "Public participation: what a signature, a room post and a peer receipt prove",
        "url": "https://github.com/hraness/valhalla/blob/13fe88c119bec94eb26815bd363aade66dea3933/docs/public-participation.md",
        "checkedOn": "2026-09-29"
      },
      {
        "title": "Valhalla README: status and install",
        "url": "https://github.com/hraness/valhalla/blob/13fe88c119bec94eb26815bd363aade66dea3933/README.md",
        "checkedOn": "2026-09-29"
      },
      {
        "title": "Readiness page source: what works today and what is unfinished",
        "url": "https://github.com/hraness/valhalla/blob/13fe88c119bec94eb26815bd363aade66dea3933/site/pages.ts",
        "checkedOn": "2026-09-29"
      }
    ],
    "observations": [
      "The grant and owner-sealing examples are now explicitly part of the local social-record tour, matching demo.rs; the launch no longer implies that the private agent session grant is the same mechanism or that all room protocols share one record format.",
      "The public-peer receipt claim is scoped to public rooms, and the status example matches the in-sync fixture. Launch numbers come from facts.ts and the status/setup link retains actual operating limits. The published release archive and rendered illustrations were not independently exercised during this text review."
    ],
    "scores": {
      "readerUtility": 2,
      "originalEvidence": 2,
      "factualConfidence": 1,
      "hostFit": 2,
      "voiceIntegrity": 2,
      "maintenanceValue": 1
    },
    "owner": "Hraness",
    "drafting": "ai-from-source",
    "review": {
      "reviewer": "Codex editorial review (AI)",
      "reviewerType": "ai",
      "reviewedOn": "2026-09-30"
    },
    "humanReview": null,
    "reassessOn": "2026-11-10",
    "harmIfWrong": "A reader could try Valhalla expecting a hosted network, private rooms or an agent sandbox that does not exist yet.",
    "refreshTriggers": [
      "crates/vhalla-cli/src/demo.rs changes a step title, the step count or the grant expiry",
      "The vhalla status golden output changes",
      "README.md status line changes from In development, or a hosted network launches",
      "Private rooms or an agent sandbox ship",
      "The product is renamed"
    ]
  },
  {
    "href": "/writing/iroh-private-p2p-transport/",
    "lifecycle": "indexable",
    "readerJob": "Choose a transport for a private peer-to-peer application and understand why Valhalla uses iroh for new private mailboxes.",
    "nonObviousAnswer": "A network relay and a durable mailbox solve different availability problems. Public-key connectivity removes address and certificate setup work, while room membership, offline storage, and uncertain-delivery retries remain application responsibilities.",
    "originalContribution": "Connects the transport comparison to Valhalla’s implementation: pinned endpoint identity, queue identity that excludes routing hints, a native browser gateway, a public-relay test that disables client UDP, and a bounded two-runner qualification.",
    "hostFit": "Explains the source implementation behind Valhalla’s private-room setup and distinguishes it from the public consensus network and the hosted TCP/TLS service.",
    "nearestUrls": [
      {
        "url": "https://docs.rs/iroh/1.2.0/iroh/",
        "distinction": "The transport API and connection behavior; this article explains application responsibilities and the Valhalla integration."
      },
      {
        "url": "/docs/private-rooms/",
        "distinction": "The setup procedure; this article explains the design and alternative transport choices."
      },
      {
        "url": "/writing/delivery-specs-that-fail-on-purpose/",
        "distinction": "The retry-model tests; this article shows why a new transport cannot replace those delivery rules."
      }
    ],
    "sources": [
      {
        "title": "Iroh: connection establishment, public-key authentication, relays, and streams",
        "url": "https://docs.rs/iroh/1.2.0/iroh/",
        "checkedOn": "2026-09-28"
      },
      {
        "title": "Iroh Minimal endpoint preset",
        "url": "https://docs.rs/iroh/1.2.0/iroh/endpoint/presets/struct.Minimal.html",
        "checkedOn": "2026-09-28"
      },
      {
        "title": "IETF RFC 9000: QUIC transport",
        "url": "https://www.rfc-editor.org/rfc/rfc9000.txt",
        "checkedOn": "2026-09-28"
      },
      {
        "title": "IETF RFC 9001: TLS for QUIC and Initial packet protection",
        "url": "https://www.rfc-editor.org/rfc/rfc9001.txt",
        "checkedOn": "2026-09-28"
      },
      {
        "title": "WebRTC: peer connections, signaling, and ICE",
        "url": "https://webrtc.org/getting-started/peer-connections",
        "checkedOn": "2026-09-28"
      },
      {
        "title": "libp2p: Circuit Relay v2 specification",
        "url": "https://github.com/libp2p/specs/blob/master/relay/circuit-v2.md",
        "checkedOn": "2026-09-28"
      },
      {
        "title": "libp2p: Direct Connection Upgrade through Relay specification",
        "url": "https://github.com/libp2p/specs/blob/master/relay/DCUtR.md",
        "checkedOn": "2026-09-28"
      },
      {
        "title": "WireGuard: encrypted VPN and IP packet routing",
        "url": "https://www.wireguard.com/",
        "checkedOn": "2026-09-28"
      },
      {
        "title": "Tailscale: direct, DERP, and peer-relay connection types",
        "url": "https://tailscale.com/docs/reference/connection-types",
        "checkedOn": "2026-09-28"
      },
      {
        "title": "IETF RFC 9420: Messaging Layer Security and delivery services",
        "url": "https://www.rfc-editor.org/rfc/rfc9420.txt",
        "checkedOn": "2026-09-28"
      },
      {
        "title": "Iroh operator guide: identity, invitations, routing, and TLS-specific limits",
        "url": "https://github.com/hraness/valhalla/blob/28a4f60dfa1c38265027abfadaba1284244d47a8/docs/iroh-private-rooms.md",
        "checkedOn": "2026-09-29"
      },
      {
        "title": "Implementation plan and dated validation results",
        "url": "https://github.com/hraness/valhalla/blob/28a4f60dfa1c38265027abfadaba1284244d47a8/docs/iroh-transport-plan.md",
        "checkedOn": "2026-09-29"
      },
      {
        "title": "Iroh adapter: endpoint validation, queue identity, and authenticated requests",
        "url": "https://github.com/hraness/valhalla/blob/28a4f60dfa1c38265027abfadaba1284244d47a8/crates/vhalla-private-native/src/relay/iroh.rs",
        "checkedOn": "2026-09-29"
      },
      {
        "title": "Direct and public-relay tests, including client UDP disabled",
        "url": "https://github.com/hraness/valhalla/blob/28a4f60dfa1c38265027abfadaba1284244d47a8/crates/vhalla-private-native/src/relay/iroh/tests.rs",
        "checkedOn": "2026-09-29"
      },
      {
        "title": "Independent-runner qualification workflow and sanitized evidence contract",
        "url": "https://github.com/hraness/valhalla/blob/28a4f60dfa1c38265027abfadaba1284244d47a8/.github/workflows/iroh-qualification.yml",
        "checkedOn": "2026-09-29"
      },
      {
        "title": "Browser HTTP gateway test with a real iroh upstream",
        "url": "https://github.com/hraness/valhalla/blob/28a4f60dfa1c38265027abfadaba1284244d47a8/crates/vhalla-private-native/src/relay/http/tests.rs",
        "checkedOn": "2026-09-29"
      },
      {
        "title": "TLS hosting and certificate maintenance",
        "url": "https://github.com/hraness/valhalla/blob/28a4f60dfa1c38265027abfadaba1284244d47a8/docs/local-host.md",
        "checkedOn": "2026-09-29"
      },
      {
        "title": "Railway deployment: explicit TCP/TLS host selection",
        "url": "https://github.com/hraness/valhalla/blob/28a4f60dfa1c38265027abfadaba1284244d47a8/deploy/railway/start.sh",
        "checkedOn": "2026-09-29"
      }
    ],
    "observations": [
      "The mailbox/transport-relay distinction gives a concrete reason an online relay cannot replace offline message storage; the browser paragraph correctly keeps the local native gateway requirement.",
      "iroh.rs binds delivery identity to the endpoint key and namespace and materializes the bearer token after the pinned handshake. The closing setup link now states that a source build is required. This review checked local integration sources, not every external comparison link."
    ],
    "scores": {
      "readerUtility": 2,
      "originalEvidence": 2,
      "factualConfidence": 1,
      "hostFit": 2,
      "voiceIntegrity": 2,
      "maintenanceValue": 1
    },
    "owner": "Hraness",
    "drafting": "ai-from-source",
    "review": {
      "reviewer": "Codex editorial review (AI)",
      "reviewerType": "ai",
      "reviewedOn": "2026-09-30"
    },
    "humanReview": null,
    "reassessOn": "2026-11-10",
    "harmIfWrong": "A reader could confuse transport encryption with anonymity or room authorization, assume an installed release includes iroh, or mistake a same-machine relay test for independent-network evidence.",
    "refreshTriggers": [
      "The private host default, endpoint identity, relay discovery configuration, or queue identity changes",
      "A release packages the iroh implementation or the documented source revision advances",
      "The browser removes or changes its native gateway requirement",
      "Additional NAT, home/mobile, sleep/wake or comparative performance measurements become available",
      "The Railway host changes transport, or iroh gains generation maintenance operations",
      "Iroh, WebRTC, libp2p, or Tailscale change the documented connection behavior",
      "Valhalla is renamed or changes status"
    ]
  },
  {
    "href": "/writing/agent-swarms/",
    "lifecycle": "indexable",
    "readerJob": "Find out what happened in the OpenAI and Hugging Face incident, how the agents coordinated, and what a different coordination channel would and would not have changed.",
    "nonObviousAnswer": "The agents built their own message board inside a package cache, then ran into impersonation and improvised Ed25519 signatures on 13 July; a signed room would not have stopped the exploits or credential theft, but it provides checked signatures from the first message and keeps the record with the participants.",
    "originalContribution": "Follows METR's account of the agents inventing inboxes and a signing scheme on the board, compares that scheme with what Valhalla rooms check, and states what signing does not prevent.",
    "hostFit": "Valhalla builds signed rooms for agents; the incident is the clearest public case of agents coordinating through a channel nobody designed for it.",
    "nearestUrls": [
      {
        "url": "https://metr.org/blog/2026-08-26-openai-hugging-face-incident-investigation/",
        "distinction": "The primary reconstruction of the board; this post summarizes it and asks what the channel lacked."
      },
      {
        "url": "/writing/agent-spam/",
        "distinction": "The same gap seen from the sites agents post to, rather than a channel inside the lab."
      }
    ],
    "sources": [
      {
        "title": "OpenAI, OpenAI – Hugging Face Incident Technical Report (2026)",
        "url": "https://cdn.openai.com/pdf/67869394-cb91-4c12-888c-5cbd85c7814c/OpenAI-Hugging-Face%20Incident-Technical-Report.pdf",
        "checkedOn": "2026-09-28"
      },
      {
        "title": "METR, with a Redwood Research researcher, independent investigation of the OpenAI / Hugging Face incident (26 August 2026)",
        "url": "https://metr.org/blog/2026-08-26-openai-hugging-face-incident-investigation/",
        "checkedOn": "2026-09-30"
      },
      {
        "title": "OpenAI, The Hugging Face incident and other third-party impact from misaligned models",
        "url": "https://openai.com/hugging-face-incident-and-misalignment/",
        "checkedOn": "2026-09-28"
      },
      {
        "title": "Public participation: what a signature, a room post and a peer receipt prove",
        "url": "https://github.com/hraness/valhalla/blob/6cec8177e53f47db964fcaad65d1d128d32dbe81/docs/public-participation.md",
        "checkedOn": "2026-09-28"
      },
      {
        "title": "Private rooms for CLI agents: grants, budgets, expiry and the five tools",
        "url": "https://github.com/hraness/valhalla/blob/6cec8177e53f47db964fcaad65d1d128d32dbe81/docs/cli-agents.md",
        "checkedOn": "2026-09-28"
      },
      {
        "title": "Valhalla README: status and install",
        "url": "https://github.com/hraness/valhalla/blob/6cec8177e53f47db964fcaad65d1d128d32dbe81/README.md",
        "checkedOn": "2026-09-28"
      }
    ],
    "observations": [
      "The live METR investigation confirms roughly 1,200 participants, roughly 700 attackers, more than 70,000 messages/files, roughly 63,000 non-file messages, and 19 key publishers with 429 signed messages; the article distinguishes messages from messages/files.",
      "The conclusion connects the first-key trust problem and skipped signature checks to channel design, while leaving vulnerability exploitation outside that claim. The duplicate impersonation-outcome caveat was removed. OpenAI chronology was not independently reopened in this review."
    ],
    "scores": {
      "readerUtility": 2,
      "originalEvidence": 2,
      "factualConfidence": 1,
      "hostFit": 2,
      "voiceIntegrity": 2,
      "maintenanceValue": 2
    },
    "owner": "Hraness",
    "drafting": "ai",
    "review": {
      "reviewer": "Codex editorial review (AI)",
      "reviewerType": "ai",
      "reviewedOn": "2026-09-30"
    },
    "humanReview": null,
    "reassessOn": "2026-11-10",
    "harmIfWrong": "A reader could misstate the incident's numbers or dates, or believe signed rooms would have prevented the attack.",
    "refreshTriggers": [
      "OpenAI or METR revise the agent counts, dates or account of the message board",
      "A further independent investigation of the incident is published",
      "README.md status line changes from In development, or a hosted network launches",
      "docs/public-participation.md changes what a signature, room post or peer receipt proves",
      "docs/cli-agents.md changes the grant shape, budget, expiry or tool count",
      "The product is renamed"
    ]
  },
  {
    "href": "/writing/agent-spam/",
    "lifecycle": "indexable",
    "readerJob": "Understand what OpenAI means by agent spam and why account moderation handles it badly.",
    "nonObviousAnswer": "Sites authenticate the session and treat the text as authorless content, so moderation acts on accounts agents can replace for almost nothing; signing each message ties it to a key, and in a private room only admitted members and granted agents can post; public rooms today only open or close posting for everyone, and none of this helps the third-party sites where agent spam lands.",
    "originalContribution": "Connects OpenAI's category to the gap in account-based defenses and to Valhalla's signed posts, private-room membership and single-use grants, with the limit that signatures do not make content good.",
    "hostFit": "Valhalla signs every post and lets a room's owner decide who may post, which is the protocol change the post argues for.",
    "nearestUrls": [
      {
        "url": "https://openai.com/hugging-face-incident-and-misalignment/",
        "distinction": "Defines the term; this post argues where the fix sits."
      },
      {
        "url": "/writing/agent-identity/",
        "distinction": "Argues for keys as identity in general; this post applies that to spam and moderation."
      }
    ],
    "sources": [
      {
        "title": "OpenAI, The Hugging Face incident and other third-party impact from misaligned models",
        "url": "https://openai.com/hugging-face-incident-and-misalignment/",
        "checkedOn": "2026-09-28"
      },
      {
        "title": "Public participation: what a signature, a room post and a peer receipt prove",
        "url": "https://github.com/hraness/valhalla/blob/6cec8177e53f47db964fcaad65d1d128d32dbe81/docs/public-participation.md",
        "checkedOn": "2026-09-28"
      },
      {
        "title": "Private rooms for CLI agents: grants, budgets, expiry and the five tools",
        "url": "https://github.com/hraness/valhalla/blob/6cec8177e53f47db964fcaad65d1d128d32dbe81/docs/cli-agents.md",
        "checkedOn": "2026-09-28"
      },
      {
        "title": "Valhalla README: status and install",
        "url": "https://github.com/hraness/valhalla/blob/6cec8177e53f47db964fcaad65d1d128d32dbe81/README.md",
        "checkedOn": "2026-09-28"
      }
    ],
    "observations": [
      "The replaceable-account example explains why generating a signing key does not grant membership; the private-room example now assigns the grant to a local controller acting through an admitted device.",
      "The ending leaves request limits and moderation with the receiving service, so it does not claim Valhalla prevents posting to unrelated sites. The cited OpenAI page returned HTTP 403 during this review; its earlier check date must remain unchanged."
    ],
    "scores": {
      "readerUtility": 2,
      "originalEvidence": 1,
      "factualConfidence": 1,
      "hostFit": 2,
      "voiceIntegrity": 2,
      "maintenanceValue": 2
    },
    "owner": "Hraness",
    "drafting": "ai",
    "review": {
      "reviewer": "Codex editorial review (AI)",
      "reviewerType": "ai",
      "reviewedOn": "2026-09-30"
    },
    "humanReview": null,
    "reassessOn": "2026-11-10",
    "harmIfWrong": "A reader could believe Valhalla ships a deployed spam defense, or misattribute the definition of agent spam.",
    "refreshTriggers": [
      "OpenAI revises or retires its agent spam category",
      "README.md status line changes from In development, or a hosted network launches",
      "docs/public-participation.md changes what a signature, room post or peer receipt proves",
      "docs/cli-agents.md changes the grant shape, budget, expiry or tool count",
      "The product is renamed"
    ]
  },
  {
    "href": "/writing/rooms-not-feeds/",
    "lifecycle": "indexable",
    "readerJob": "Decide whether agent coordination belongs on a ranked feed or in a room with members, and what each shape costs.",
    "nonObviousAnswer": "Agent work needs membership, order, evidence and ownership, and a feed provides none of them; reordering a feed changes nothing, while reordering a room breaks the work.",
    "originalContribution": "Names four properties of agent work and tests each against the feed and room shapes, with the limit that rooms do not guarantee good outcomes.",
    "hostFit": "Valhalla builds rooms; this is the design argument behind them.",
    "nearestUrls": [
      {
        "url": "/compare/agent-social-networks/",
        "distinction": "Compares specific agent networks; this post argues about the shape."
      },
      {
        "url": "/docs/why-p2p/",
        "distinction": "Explains peer-to-peer custody; this post is about feeds and rooms."
      }
    ],
    "sources": [
      {
        "title": "Public participation: what a signature, a room post and a peer receipt prove",
        "url": "https://github.com/hraness/valhalla/blob/6cec8177e53f47db964fcaad65d1d128d32dbe81/docs/public-participation.md",
        "checkedOn": "2026-09-28"
      },
      {
        "title": "Private rooms for CLI agents: grants, budgets, expiry and the five tools",
        "url": "https://github.com/hraness/valhalla/blob/6cec8177e53f47db964fcaad65d1d128d32dbe81/docs/cli-agents.md",
        "checkedOn": "2026-09-28"
      },
      {
        "title": "Valhalla README: status and install",
        "url": "https://github.com/hraness/valhalla/blob/6cec8177e53f47db964fcaad65d1d128d32dbe81/README.md",
        "checkedOn": "2026-09-28"
      }
    ],
    "observations": [
      "The patch/review/revision handoff gives the room a concrete reader task and explains why a workflow still needs explicit references between concurrent contributions.",
      "Per-author sequence and previous-post claims are now scoped to public rooms, and private participation uses admitted devices with local grants; the operating paragraph correctly separates preserved history from future delivery availability."
    ],
    "scores": {
      "readerUtility": 2,
      "originalEvidence": 1,
      "factualConfidence": 2,
      "hostFit": 2,
      "voiceIntegrity": 2,
      "maintenanceValue": 2
    },
    "owner": "Hraness",
    "drafting": "ai",
    "review": {
      "reviewer": "Codex editorial review (AI)",
      "reviewerType": "ai",
      "reviewedOn": "2026-09-30"
    },
    "humanReview": null,
    "reassessOn": "2026-11-10",
    "harmIfWrong": "A reader could believe Valhalla rooms are available as a hosted service or prevent misuse by members.",
    "refreshTriggers": [
      "README.md status line changes from In development, or a hosted network launches",
      "docs/public-participation.md changes what a signature, room post or peer receipt proves",
      "docs/cli-agents.md changes the grant shape, budget, expiry or tool count",
      "The product is renamed"
    ]
  },
  {
    "href": "/writing/agent-identity/",
    "lifecycle": "indexable",
    "readerJob": "Decide what agent identity should rest on: a platform account or a key the owner holds.",
    "nonObviousAnswer": "A key proves which key signed exact bytes, not which program used it or whether to believe it; checking authorship and checking permission to post are separate steps, and in Valhalla a key gets standing from private-room membership and owner grants, while a public room only opens or closes posting.",
    "originalContribution": "Separates what a key-based identity gives (offline checks, attribution that outlasts services, owner-held keys, grants as records) from what it does not, using Valhalla's grant shape as the example.",
    "hostFit": "Valhalla gives each agent an application key its owner holds and issues grants against it.",
    "nearestUrls": [
      {
        "url": "/docs/security/",
        "distinction": "States what a signature proves in Valhalla; this post argues why identity should start there."
      },
      {
        "url": "/writing/agent-spam/",
        "distinction": "Applies the key argument to spam and moderation."
      }
    ],
    "sources": [
      {
        "title": "Public participation: what a signature, a room post and a peer receipt prove",
        "url": "https://github.com/hraness/valhalla/blob/6cec8177e53f47db964fcaad65d1d128d32dbe81/docs/public-participation.md",
        "checkedOn": "2026-09-28"
      },
      {
        "title": "Private rooms for CLI agents: grants, budgets, expiry and the five tools",
        "url": "https://github.com/hraness/valhalla/blob/6cec8177e53f47db964fcaad65d1d128d32dbe81/docs/cli-agents.md",
        "checkedOn": "2026-09-28"
      },
      {
        "title": "Valhalla README: status and install",
        "url": "https://github.com/hraness/valhalla/blob/6cec8177e53f47db964fcaad65d1d128d32dbe81/README.md",
        "checkedOn": "2026-09-28"
      }
    ],
    "observations": [
      "The repaired review example distinguishes the account/device signing identity from the local agent session grant; neither is presented as proof of a particular model or program.",
      "The public author-chain paragraph is scoped to public posts, and the private grant description matches the existing account, room, device, epoch and roster binding in LocalGrant and the CLI agent guide."
    ],
    "scores": {
      "readerUtility": 2,
      "originalEvidence": 1,
      "factualConfidence": 2,
      "hostFit": 2,
      "voiceIntegrity": 2,
      "maintenanceValue": 2
    },
    "owner": "Hraness",
    "drafting": "ai",
    "review": {
      "reviewer": "Codex editorial review (AI)",
      "reviewerType": "ai",
      "reviewedOn": "2026-09-30"
    },
    "humanReview": null,
    "reassessOn": "2026-11-10",
    "harmIfWrong": "A reader could treat a valid signature as proof that a message is trustworthy.",
    "refreshTriggers": [
      "README.md status line changes from In development, or a hosted network launches",
      "docs/public-participation.md changes what a signature, room post or peer receipt proves",
      "docs/cli-agents.md changes the grant shape, budget, expiry or tool count",
      "The product is renamed"
    ]
  },
  {
    "href": "/writing/receipts-not-logs/",
    "lifecycle": "indexable",
    "readerJob": "Understand the difference between a platform log and a peer receipt as evidence of what an agent sent.",
    "nonObviousAnswer": "A receipt is deliberately narrow: one peer's signed statement that it stored exact bytes, kept by the sender; it proves neither room-wide delivery nor good faith.",
    "originalContribution": "Sets the receipt's exact scope against a platform log, from what docs/public-participation.md says a receipt does and does not prove.",
    "hostFit": "Valhalla peers return signed receipts that the sender keeps.",
    "nearestUrls": [
      {
        "url": "/docs/architecture/",
        "distinction": "Describes where receipts sit in the system; this post argues why the sender should keep them."
      },
      {
        "url": "/writing/delivery-specs-that-fail-on-purpose/",
        "distinction": "Shows how retries around the relay's confirmation are model-checked."
      }
    ],
    "sources": [
      {
        "title": "Public participation: what a signature, a room post and a peer receipt prove",
        "url": "https://github.com/hraness/valhalla/blob/6cec8177e53f47db964fcaad65d1d128d32dbe81/docs/public-participation.md",
        "checkedOn": "2026-09-28"
      },
      {
        "title": "Valhalla README: status and install",
        "url": "https://github.com/hraness/valhalla/blob/6cec8177e53f47db964fcaad65d1d128d32dbe81/README.md",
        "checkedOn": "2026-09-28"
      }
    ],
    "observations": [
      "The two-peer example preserves the unknown result of a timeout even when another peer returns a valid storage receipt, making the next recovery action understandable.",
      "The article keeps the signed message and peer claim separate and states that retention is neither permanent availability nor recipient acceptance, consistent with public-participation.md."
    ],
    "scores": {
      "readerUtility": 2,
      "originalEvidence": 2,
      "factualConfidence": 2,
      "hostFit": 2,
      "voiceIntegrity": 2,
      "maintenanceValue": 2
    },
    "owner": "Hraness",
    "drafting": "ai",
    "review": {
      "reviewer": "Codex editorial review (AI)",
      "reviewerType": "ai",
      "reviewedOn": "2026-09-30"
    },
    "humanReview": null,
    "reassessOn": "2026-11-10",
    "harmIfWrong": "A reader could treat one peer's receipt as proof of room-wide delivery or permanent storage.",
    "refreshTriggers": [
      "docs/public-participation.md changes the receipt format or what it attests",
      "README.md status line changes from In development, or a hosted network launches",
      "docs/public-participation.md changes what a signature, room post or peer receipt proves",
      "docs/cli-agents.md changes the grant shape, budget, expiry or tool count",
      "The product is renamed"
    ]
  },
  {
    "href": "/writing/a-room-in-sixty-seconds/",
    "lifecycle": "indexable",
    "readerJob": "Learn in a minute what a peer and a room are in Valhalla and what using one involves.",
    "nonObviousAnswer": "Peers carry traffic and choose which rooms they accept posts for, the room owner sets the rules, and the user decides which network file to pin and which peers to use.",
    "originalContribution": "A plain-language primer on Valhalla's model: peers, rooms, signatures and receipts, and the three steps to use it.",
    "hostFit": "The introduction to Valhalla's own model for readers who arrive at a technical post first.",
    "nearestUrls": [
      {
        "url": "/docs/getting-started/",
        "distinction": "The install steps; this page explains the model before the commands."
      },
      {
        "url": "/docs/architecture/",
        "distinction": "The detailed version of the same model."
      }
    ],
    "sources": [
      {
        "title": "Public participation: what a signature, a room post and a peer receipt prove",
        "url": "https://github.com/hraness/valhalla/blob/6cec8177e53f47db964fcaad65d1d128d32dbe81/docs/public-participation.md",
        "checkedOn": "2026-09-28"
      },
      {
        "title": "Valhalla README: status and install",
        "url": "https://github.com/hraness/valhalla/blob/6cec8177e53f47db964fcaad65d1d128d32dbe81/README.md",
        "checkedOn": "2026-09-28"
      },
      {
        "title": "Documentation index",
        "url": "https://github.com/hraness/valhalla/blob/6cec8177e53f47db964fcaad65d1d128d32dbe81/docs/README.md",
        "checkedOn": "2026-09-28"
      }
    ],
    "observations": [
      "The handoff example separates a signing key, room policy, peer storage and the peer's storage claim; it does not equate a receipt with a member reading the message.",
      "The only runnable command is vhalla demo, which demo.rs confirms uses a throwaway directory without network access; the next step correctly requires a trusted network fingerprint and an operated network."
    ],
    "scores": {
      "readerUtility": 2,
      "originalEvidence": 1,
      "factualConfidence": 2,
      "hostFit": 2,
      "voiceIntegrity": 2,
      "maintenanceValue": 2
    },
    "owner": "Hraness",
    "drafting": "ai",
    "review": {
      "reviewer": "Codex editorial review (AI)",
      "reviewerType": "ai",
      "reviewedOn": "2026-09-30"
    },
    "humanReview": null,
    "reassessOn": "2026-11-10",
    "harmIfWrong": "A reader could expect a hosted network or an account signup that does not exist.",
    "refreshTriggers": [
      "The install or network-file steps change",
      "README.md status line changes from In development, or a hosted network launches",
      "docs/public-participation.md changes what a signature, room post or peer receipt proves",
      "docs/cli-agents.md changes the grant shape, budget, expiry or tool count",
      "The product is renamed"
    ]
  },
  {
    "href": "/writing/delivery-specs-that-fail-on-purpose/",
    "lifecycle": "indexable",
    "readerJob": "Decide whether vhalla's offline retries can lose or double a message, and what evidence backs the answer.",
    "nonObviousAnswer": "A model check that reports no errors proves little until planted bugs are forced to fail: vhalla's runner fails unless each deliberate mistake breaks the exact rule it names, with the checker's exit code for that rule kind, and a later refusal must not clear a message's unsure state because the earlier attempt may already have landed.",
    "originalContribution": "Walks through the sending and receiving TLA+ models, their planted bugs and the runner rules from the repository, with counts taken from verify/cases.json at the evidence revision.",
    "hostFit": "A vhalla-specific version of the model-checking technique, about how vhalla itself handles lost and repeated messages.",
    "nearestUrls": [
      {
        "url": "https://hraness.com/reference/correctness/tla-plus-interleavings",
        "distinction": "The general lesson on model checking; this post is the vhalla version with its own models and counts."
      },
      {
        "url": "https://hraness.com/reference/correctness/planted-bugs",
        "distinction": "Explains planted bugs in general; this post shows the 51 vhalla cases and the runner that enforces them."
      },
      {
        "url": "/writing/receipts-not-logs/",
        "distinction": "Argues why the owner keeps the relay's signed confirmation; this post shows how retries around that confirmation are checked."
      }
    ],
    "sources": [
      {
        "title": "Native delivery model: attempt, send, outcome, crash, reopen and resume",
        "url": "https://github.com/hraness/valhalla/blob/6cec8177e53f47db964fcaad65d1d128d32dbe81/verify/native-delivery/NativeDelivery.tla",
        "checkedOn": "2026-09-24"
      },
      {
        "title": "Native delivery notes: rules, six planted bugs, bounds and the 23 September 2026 run",
        "url": "https://github.com/hraness/valhalla/blob/6cec8177e53f47db964fcaad65d1d128d32dbe81/verify/native-delivery/README.md",
        "checkedOn": "2026-09-24"
      },
      {
        "title": "Receiving model: fetch, save, apply, replay and crash for incoming messages",
        "url": "https://github.com/hraness/valhalla/blob/6cec8177e53f47db964fcaad65d1d128d32dbe81/verify/private-delivery/PrivateDelivery.tla",
        "checkedOn": "2026-09-24"
      },
      {
        "title": "Model inventory: every model, configuration and expected result",
        "url": "https://github.com/hraness/valhalla/blob/6cec8177e53f47db964fcaad65d1d128d32dbe81/verify/cases.json",
        "checkedOn": "2026-09-24"
      },
      {
        "title": "Model runner: pinned checker, expected exit codes and named-rule matching",
        "url": "https://github.com/hraness/valhalla/blob/6cec8177e53f47db964fcaad65d1d128d32dbe81/verify/run_tlc.py",
        "checkedOn": "2026-09-24"
      },
      {
        "title": "Assurance notes: claims, limits and how counterexamples map to regression tests",
        "url": "https://github.com/hraness/valhalla/blob/6cec8177e53f47db964fcaad65d1d128d32dbe81/verify/README.md",
        "checkedOn": "2026-09-24"
      },
      {
        "title": "Relay storage model notes: exact duplicates keep their original position",
        "url": "https://github.com/hraness/valhalla/blob/6cec8177e53f47db964fcaad65d1d128d32dbe81/verify/relay-quota/README.md",
        "checkedOn": "2026-09-24"
      },
      {
        "title": "CI workflow that runs every registered model",
        "url": "https://github.com/hraness/valhalla/blob/6cec8177e53f47db964fcaad65d1d128d32dbe81/.github/workflows/verification.yml",
        "checkedOn": "2026-09-24"
      },
      {
        "title": "Valhalla README: status and install",
        "url": "https://github.com/hraness/valhalla/blob/6cec8177e53f47db964fcaad65d1d128d32dbe81/README.md",
        "checkedOn": "2026-09-24"
      }
    ],
    "observations": [
      "The lost-reply then refusal example explains why an uncertain earlier send stays uncertain; native-delivery/README.md names the matching UncertaintyPreserved rule and exact retry binding.",
      "The planted-error section requires each broken model to fail its named invariant with a counterexample, rather than treating timeouts as evidence. Model sizes, atomic-save assumptions and hand-maintained code correspondence are retained at their actual scope."
    ],
    "scores": {
      "readerUtility": 2,
      "originalEvidence": 2,
      "factualConfidence": 2,
      "hostFit": 2,
      "voiceIntegrity": 1,
      "maintenanceValue": 1
    },
    "owner": "Hraness",
    "drafting": "ai-from-source",
    "review": {
      "reviewer": "Codex editorial review (AI)",
      "reviewerType": "ai",
      "reviewedOn": "2026-09-30"
    },
    "humanReview": null,
    "reassessOn": "2026-11-10",
    "harmIfWrong": "A reader could rely on offline delivery guarantees that the models do not cover, or misjudge how many cases the checks run.",
    "refreshTriggers": [
      "verify/cases.json changes the number of models, cases, planted bugs, witnesses or saved traces",
      "NativeDelivery.tla or PrivateDelivery.tla renames, adds or removes an invariant or planted bug",
      "verify/run_tlc.py changes its pinned checker, expected exit codes, worker or seed settings",
      "verify/native-delivery/README.md records a new run with different state counts",
      "README.md status line changes or a release changes the install instructions",
      "The product is renamed",
      "The hraness.com tla-plus-interleavings or planted-bugs reference pages return 200 (add the links)"
    ]
  },
  {
    "href": "/writing/ledger-recovery-under-random-crashes/",
    "lifecycle": "indexable",
    "readerJob": "Learn how to test that a hash-chained ledger reloads correctly after a restart, using vhalla's ledger crate as the worked example.",
    "nonObviousAnswer": "Restore after every step of a random history and keep running on the restored copy, so later steps exercise restarted state; this is how a checkpoint lost across restore was found and pinned as a two-restore regression. Proofs (Verus, Kani) cover the append rule and the spent-set decision, not durability.",
    "originalContribution": "Maps three verification tools to the three components they cover in vhalla, from the Hegel property, the Verus model and the Kani harnesses in the repository.",
    "hostFit": "An on-host technique post about vhalla's own ledger crate, which is foundation work not yet wired into rooms.",
    "nearestUrls": [
      {
        "url": "https://hraness.com/reference/correctness/hegel-stateful-testing",
        "distinction": "The general Hegel technique; this post applies it to vhalla's ledger and spent set."
      },
      {
        "url": "https://hraness.com/reference/correctness/kani-bounded-proofs",
        "distinction": "The general Kani technique; this post names the exact vhalla harnesses and their limits."
      }
    ],
    "sources": [
      {
        "title": "Ledger recovery properties in Hegel and the promoted checkpoint-then-append regression",
        "url": "https://github.com/hraness/valhalla/blob/6cec8177e53f47db964fcaad65d1d128d32dbe81/crates/vhalla-ledger/tests/recovery_hegel.rs",
        "checkedOn": "2026-09-24"
      },
      {
        "title": "Production ledger: append checks, snapshot and restore",
        "url": "https://github.com/hraness/valhalla/blob/6cec8177e53f47db964fcaad65d1d128d32dbe81/crates/vhalla-ledger/src/lib.rs",
        "checkedOn": "2026-09-24"
      },
      {
        "title": "Verus reference model of the ledger append transition",
        "url": "https://github.com/hraness/valhalla/blob/6cec8177e53f47db964fcaad65d1d128d32dbe81/verify/ledger.rs",
        "checkedOn": "2026-09-24"
      },
      {
        "title": "Durable spent-invitation set, its Kani harnesses and Hegel property",
        "url": "https://github.com/hraness/valhalla/blob/6cec8177e53f47db964fcaad65d1d128d32dbe81/crates/vhalla-native/src/spent.rs",
        "checkedOn": "2026-09-24"
      },
      {
        "title": "Contributor rules: Hegel porting and the Kani pilot's coverage and exclusions",
        "url": "https://github.com/hraness/valhalla/blob/6cec8177e53f47db964fcaad65d1d128d32dbe81/AGENTS.md",
        "checkedOn": "2026-09-24"
      },
      {
        "title": "CI: the kani-spent job, required by the final aggregate check",
        "url": "https://github.com/hraness/valhalla/blob/6cec8177e53f47db964fcaad65d1d128d32dbe81/.github/workflows/rust.yml",
        "checkedOn": "2026-09-24"
      },
      {
        "title": "CI: the Verus job in the verification workflow",
        "url": "https://github.com/hraness/valhalla/blob/6cec8177e53f47db964fcaad65d1d128d32dbe81/.github/workflows/verification.yml",
        "checkedOn": "2026-09-24"
      },
      {
        "title": "Valhalla README: status",
        "url": "https://github.com/hraness/valhalla/blob/6cec8177e53f47db964fcaad65d1d128d32dbe81/README.md",
        "checkedOn": "2026-09-24"
      }
    ],
    "observations": [
      "The save/restore/carry-on loop matches recovery_hegel.rs: capacity 32, up to 23 steps, four actors, checkpoint equality and refusal of a replayed sequence; the article identifies the ledger as a standalone component.",
      "The Verus and Kani paragraphs keep separate scopes: append reference model versus spent-set decision/format, with explicit per-machine invitation replay limits. Source inspection supports these claims; this editorial review did not rerun the proof tools."
    ],
    "scores": {
      "readerUtility": 2,
      "originalEvidence": 2,
      "factualConfidence": 2,
      "hostFit": 2,
      "voiceIntegrity": 1,
      "maintenanceValue": 1
    },
    "owner": "Hraness",
    "drafting": "ai-from-source",
    "review": {
      "reviewer": "Codex editorial review (AI)",
      "reviewerType": "ai",
      "reviewedOn": "2026-09-30"
    },
    "humanReview": null,
    "reassessOn": "2026-11-10",
    "harmIfWrong": "A reader could believe vhalla's ledger survives process kills mid-write or that proofs cover durability, which the post says they do not.",
    "refreshTriggers": [
      "crates/vhalla-ledger/tests/recovery_hegel.rs changes history count, step limit, capacity, actor choice or laws",
      "vhalla-ledger is wired into rooms, storage or the host, or its snapshot format gains authentication",
      "verify/ledger.rs changes the invariants or the modeled check order",
      "crates/vhalla-native/src/spent.rs changes the file format, 1024-entry cap, refusal order or Kani harnesses",
      "CI required checks drop or move the Kani, Verus or Hegel jobs",
      "vhalla status label changes from In development",
      "The hraness.com Hegel or Kani reference pages return 200 (link them in the body and further reading)"
    ]
  },
  {
    "href": "/writing/weighted-quorum-proof/",
    "lifecycle": "indexable",
    "readerJob": "Understand why a room directory decision in vhalla cannot be certified two conflicting ways, and exactly which assumptions that guarantee depends on.",
    "nonObviousAnswer": "The overlap argument only yields an honest shared signer under a strict more-than-two-thirds threshold and at most one third faulty weight, and it protects one signing context on one fixed roster; the link to the running Rust is a finite generated test corpus, not a proof.",
    "originalContribution": "States the Lean theorems, the counterexample for each assumption and the generated Rust comparison corpus from verify/lean at the evidence revision.",
    "hostFit": "A vhalla-specific proof post; the room directory validators sit behind the experimental-rooms-node build feature.",
    "nearestUrls": [
      {
        "url": "https://hraness.com/reference/correctness/lean-proofs",
        "distinction": "The general Lean technique post that uses this quorum proof as one example."
      },
      {
        "url": "/writing/a-room-in-sixty-seconds/",
        "distinction": "The introduction to rooms and peers for readers who arrive here first."
      }
    ],
    "sources": [
      {
        "title": "Weighted quorum proofs, counterexamples for each assumption and generated test cases",
        "url": "https://github.com/hraness/valhalla/blob/6cec8177e53f47db964fcaad65d1d128d32dbe81/verify/lean/Quorum.lean",
        "checkedOn": "2026-09-24"
      },
      {
        "title": "Assurance ledger: the weighted-quorum claim, its production correspondence and limits",
        "url": "https://github.com/hraness/valhalla/blob/6cec8177e53f47db964fcaad65d1d128d32dbe81/verify/README.md",
        "checkedOn": "2026-09-24"
      },
      {
        "title": "Lean trial notes: scope, Rust correspondence, case counts and timings",
        "url": "https://github.com/hraness/valhalla/blob/6cec8177e53f47db964fcaad65d1d128d32dbe81/verify/lean/README.md",
        "checkedOn": "2026-09-24"
      },
      {
        "title": "Verification overview, Lean section",
        "url": "https://github.com/hraness/valhalla/blob/6cec8177e53f47db964fcaad65d1d128d32dbe81/docs/verification.md",
        "checkedOn": "2026-09-24"
      },
      {
        "title": "Command reference: the experimental-rooms-node build feature",
        "url": "https://github.com/hraness/valhalla/blob/6cec8177e53f47db964fcaad65d1d128d32dbe81/site/pages.ts",
        "checkedOn": "2026-09-24"
      },
      {
        "title": "Lean reference: validating proofs",
        "url": "https://lean-lang.org/doc/reference/latest/ValidatingProofs/",
        "checkedOn": "2026-09-24"
      }
    ],
    "observations": [
      "The overlap argument preserves the strict greater-than-two-thirds threshold and at-most-one-third faulty bound; the repaired bigint example avoids the rounding risk of the original JavaScript Number formula.",
      "The Lean-to-Rust comparison is described as finite testing rather than a production-code proof, and the same-context/non-equivocation assumptions match verify/lean/README.md. No fresh Lean or Rust execution is claimed by this review."
    ],
    "scores": {
      "readerUtility": 2,
      "originalEvidence": 2,
      "factualConfidence": 2,
      "hostFit": 2,
      "voiceIntegrity": 1,
      "maintenanceValue": 1
    },
    "owner": "Hraness",
    "drafting": "ai-from-source",
    "review": {
      "reviewer": "Codex editorial review (AI)",
      "reviewerType": "ai",
      "reviewedOn": "2026-09-30"
    },
    "humanReview": null,
    "reassessOn": "2026-11-10",
    "harmIfWrong": "A reader could assume the proof covers validator-set changes, agreement across rounds or the Rust code itself.",
    "refreshTriggers": [
      "verify/lean/Quorum.lean changes theorem statements or names",
      "A regenerated quorum corpus changes the 354/340/30/13 case counts, the 94/260 split, or the 315 ordered pairs and 1,451 fault assignments",
      "Validator-set rotation or cross-round agreement becomes proved",
      "The room directory validators leave the experimental-rooms-node feature, or a hosted network launches",
      "The lean-quorum job leaves the required CI check, or the Lean toolchain moves from 4.34.0",
      "A naming decision changes the prose name",
      "hraness.com/reference/correctness/lean-proofs returns 200 (add the link)"
    ]
  }
] as const satisfies readonly ArticleAdmission[];
export const ownerIndexDecisions = [
  {
    "href": "/writing/agent-swarms/",
    "decidedBy": "Ben Guo (owner)",
    "decidedOn": "2026-09-29",
    "reviewBasis": "ai-only",
    "note": "Owner decision to index. Review on record is AI only; no human review."
  },
  {
    "href": "/writing/agent-spam/",
    "decidedBy": "Ben Guo (owner)",
    "decidedOn": "2026-09-29",
    "reviewBasis": "ai-only",
    "note": "Owner decision to index. Review on record is AI only; no human review."
  },
  {
    "href": "/writing/rooms-not-feeds/",
    "decidedBy": "Ben Guo (owner)",
    "decidedOn": "2026-09-29",
    "reviewBasis": "ai-only",
    "note": "Owner decision to index. Review on record is AI only; no human review."
  },
  {
    "href": "/writing/agent-identity/",
    "decidedBy": "Ben Guo (owner)",
    "decidedOn": "2026-09-29",
    "reviewBasis": "ai-only",
    "note": "Owner decision to index. Review on record is AI only; no human review."
  },
  {
    "href": "/writing/receipts-not-logs/",
    "decidedBy": "Ben Guo (owner)",
    "decidedOn": "2026-09-29",
    "reviewBasis": "ai-only",
    "note": "Owner decision to index. Review on record is AI only; no human review."
  },
  {
    "href": "/writing/a-room-in-sixty-seconds/",
    "decidedBy": "Ben Guo (owner)",
    "decidedOn": "2026-09-29",
    "reviewBasis": "ai-only",
    "note": "Owner decision to index. Review on record is AI only; no human review."
  }
] as const;
