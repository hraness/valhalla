//! Botcaptcha witness mode: challenge admission over `vhalla-witness`.
//!
//! A verifier issues a signed `Challenge` naming a subject key, a realm, a
//! room, a purpose, a task manifest, and a work contract. The subject runs its
//! programs on that manifest, seals a receipt under the challenge, and returns
//! a signed `Response`. `WitnessVerifier::verify_response` re-derives every
//! fact: it replays the run, compares the receipt bit for bit, checks the
//! contract, and consumes the challenge once. The result, `VerifiedWitness`,
//! proves bounded replayable work on that task for that challenge and nothing
//! else: never identity, personhood, safety, or host authority.
//!
//! Entropy and the clock are injected; the crate reads neither. Nothing here
//! executes network-supplied code: programs are data interpreted by
//! `vhalla-witness`. Hashcash mode is reserved and not implemented here.
#![no_std]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

extern crate alloc;

pub mod admit;
pub mod challenge;
pub mod response;
pub mod window;

/// Encoding version shared by the challenge and the response.
pub const VERSION: u8 = 1;
/// Longest accepted challenge lifetime in seconds.
pub const MAX_CHALLENGE_LIFETIME: u64 = 15 * 60;
/// Signing domain for a challenge transcript.
pub const CHALLENGE_DOMAIN: &[u8] = b"vhalla/botcaptcha/challenge/v1";
/// Signing domain for a response transcript.
pub const RESPONSE_DOMAIN: &[u8] = b"vhalla/botcaptcha/response/v1";
/// Digest domain for the dedup scope `issuer_key || challenge_id || subject_key`.
pub const DEDUP_DOMAIN: &[u8] = b"vhalla/botcaptcha/dedup/v1";
/// Digest domain for the reward `scope_key || response_hash`.
pub const REWARD_DOMAIN: &[u8] = b"vhalla/botcaptcha/reward/v1";

/// `domain || u32 length || bytes`: the message a key signs.
#[must_use]
pub fn transcript(domain: &[u8], body: &[u8]) -> alloc::vec::Vec<u8> {
    let len = u32::try_from(body.len()).unwrap_or(u32::MAX);
    let mut out = alloc::vec::Vec::with_capacity(domain.len() + 4 + body.len());
    out.extend_from_slice(domain);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(body);
    out
}
