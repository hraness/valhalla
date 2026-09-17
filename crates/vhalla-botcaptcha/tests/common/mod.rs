//! Shared fixtures: a manifest and candidate from a committed vector, keys,
//! and a challenge issued for them.
#![allow(dead_code)]

use std::fs;
use std::path::Path;

use ed25519_dalek::SigningKey;
use vhalla_botcaptcha::challenge::{Challenge, ChallengeContext, ChallengeIssuer, Purpose};
use vhalla_core::{RealmId, RoomId};
use vhalla_witness::codec;
use vhalla_witness::manifest::{TaskManifest, ValidManifest, WorkContract};
use vhalla_witness::model::Program;
use vhalla_witness::platform::WorkAllowance;
use vhalla_witness::vectors::{parse, Vector};

pub const ISSUER_SEED: [u8; 32] = [7; 32];
pub const SUBJECT_SEED: [u8; 32] = [11; 32];
pub const ENTROPY: [u8; 32] = [42; 32];
pub const REALM: RealmId = RealmId(1);
pub const ROOM: RoomId = RoomId(2);
pub const NOW: u64 = 1_000_000;
pub const LIFETIME: u64 = 600;

pub fn vector(id: &str) -> Vector {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(format!("tests/vectors/{id}.txt"));
    parse(&fs::read_to_string(&path).unwrap()).unwrap()
}

pub struct Fixture {
    pub manifest: TaskManifest,
    pub valid: ValidManifest,
    pub candidate: Vec<(u16, Program)>,
    pub issuer: ChallengeIssuer,
    pub subject: SigningKey,
    pub allowance: WorkAllowance,
}

impl Fixture {
    pub fn new(id: &str) -> Self {
        let vector = vector(id);
        let manifest = codec::decode_manifest(&vector.manifest).unwrap();
        let valid = ValidManifest::validate(manifest.clone()).unwrap();
        let allowance = WorkAllowance {
            max_total: valid.fuel_total(),
        };
        Self {
            manifest,
            valid,
            candidate: codec::decode_candidate(&vector.assignment).unwrap(),
            issuer: ChallengeIssuer::from_seed(ISSUER_SEED),
            subject: SigningKey::from_bytes(&SUBJECT_SEED),
            allowance,
        }
    }
    pub fn subject_key(&self) -> [u8; 32] {
        self.subject.verifying_key().to_bytes()
    }
    pub fn context(&self) -> ChallengeContext {
        ChallengeContext {
            issuer_key: self.issuer.verifying_key(),
            subject_key: self.subject_key(),
            realm: REALM,
            room: ROOM,
            purpose: Purpose::RateLimitRelief,
        }
    }
    pub fn contract(&self) -> WorkContract {
        self.valid.contract()
    }
    pub fn issue(&self, entropy: [u8; 32], now: u64) -> Challenge {
        self.issuer
            .issue(
                entropy,
                now,
                LIFETIME,
                self.subject_key(),
                REALM,
                ROOM,
                Purpose::RateLimitRelief,
                self.valid.hash(),
                self.contract(),
            )
            .unwrap()
    }
}
