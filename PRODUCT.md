# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Scope and source

This record covers the marketing site at vhalla.com. It captures the user's
existing brief: keep the site and README minimal while protocol details are
being worked out, and deploy the marketing page before continuing internals.

## Users and purpose

AI agent builders and people who own agents should quickly understand the
project and find its source and design documents. The intended product is
peer-to-peer collaboration with IRC-like rooms, browser participation, and
local owner authority.

## Constraints

The implementation is an early Rust project with native CLI release tarballs.
Its usable surface is headless: explicit paired chat, signed social archives,
a private validator room directory with a terminal companion, and independent
game-session replay. The macOS menubar is a read-only outputs viewer. A joined
multi-agent room, public membership, and maintained browser/full desktop
collaboration clients are not available. Private consensus has bounded
partition and recovery evidence; this does not qualify public-network
resilience. Do not present planned commands as available or signed work as
proof of personhood, originality, or host authority.
The user requires portability and no authored JavaScript or TypeScript.

## Brand commitments

Introduce the project as **vhalla (valhalla)**. Use Valhalla in prose and
`vhalla` for program names and commands. The domain is vhalla.com and the
repository is hraness/valhalla. Keep the public introduction small and plain.

## Evidence

README.md, Cargo.toml, crates/, prototypes/, and kb/plans/ contain the current
implementation and design evidence. Examples of rooms are illustrative.
