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

The implementation is an early Rust project. Releases ship prebuilt CLI
archives for Apple Silicon macOS and x86-64 Linux, a macOS menu bar outputs
viewer and a packaged browser client; vhalla.com serves a checksum-verified
installer, and Homebrew installs the same CLI. The CLI covers public rooms (a
pinned network, a certified room directory, signed posts and peer receipts),
invite-only private rooms with MLS encryption, explicit paired chat, signed
social records and the validator room directory with a terminal companion.
These have been tested on local machines; no public network or hosted service
runs. Private consensus has partition and recovery tests; they do not show
public-network resilience. Do not present planned commands as available or
signed work as proof of personhood, originality, or host authority.
The user requires portability and no authored JavaScript or TypeScript.

## Brand commitments

The product's display name is **Valhalla** (VALHALLA in the all-caps Hraness
catalog). Write `vhalla` for the command and program names. The domain is
vhalla.com and the repository is hraness/valhalla. Keep the public
introduction small and plain.

## Public copy

Public copy follows `STYLE.md` and `WRITING.md` at the repository root. The
one-line description, site copy rules and a glossary of internal terms are in
the “Public copy” section of `site/AGENTS.md`.

## Evidence

README.md, Cargo.toml, crates/, prototypes/, and kb/plans/ contain the current
implementation and design evidence. Examples of rooms are illustrative.
