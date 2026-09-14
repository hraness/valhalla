//! Deterministic mature social awards from committed evidence.
//!
//! A credit award is derived, never claimed: the adapter authenticates that a
//! retained social record is an owner-sealed up-reaction on an original post,
//! attributes the source owner and the post's beneficiary from the borrowed
//! control view, and binds the activity epoch to the directory's own first
//! acceptance of the evidence — never to a receiver's clock, a snapshot
//! envelope or a producer timestamp. The registry owns deduplication; this
//! layer only produces the exact `(source, beneficiary, epoch, evidence)`
//! tuple a finalized award commits.

use alloc::collections::BTreeSet;
use vhalla_social::{
    control::{ControlView, SocialStatus},
    wire::VerifiedRecord,
    Body, Operation, OwnerId, Reaction, RecordId,
};

/// Closed award-assessment failures. A denial never implies a zero score;
/// it means this evidence cannot justify an award.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AwardDenial {
    /// The record is not an up-reaction on an original post.
    NotSupport,
    /// The record's history is not owner-sealed under the borrowed view.
    NotCommitted,
    /// The reacted post is absent from the retained archive.
    UnknownPost,
    /// The referenced record is not an original post.
    NotPost,
    /// The post's own authority is not committed.
    PostNotCommitted,
    /// Source and beneficiary are the same owner.
    SelfSupport,
    /// The source owner is outside the policy's eligible source set.
    Ineligible,
    /// The epoch anchor is in the future or the epoch length is zero.
    Epoch,
}

/// The authenticated award facts a directory ledger deduplicates. Plain data;
/// constructing it confers no credit by itself.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SupportAward {
    /// Attributed owner whose committed record carries the reaction.
    pub source_owner: OwnerId,
    /// Owner of the original post the reaction rewards.
    pub beneficiary: OwnerId,
    /// Immutable accounting epoch derived from the first directory-accepted
    /// commitment of this exact evidence record.
    pub activity_epoch: u64,
    /// The exact committed social record justifying this award.
    pub evidence_id: RecordId,
}

/// Derive one award candidate from one retained record. `eligible` is the
/// directory policy's source-owner set; `accepted_at` is the directory's own
/// agreed clock at first acceptance of this evidence; `now` is the evaluation
/// clock. The record must be a committed up-reaction on a committed original
/// post, attributed to distinct source and beneficiary owners.
pub fn assess_support(
    record: &VerifiedRecord,
    view: &ControlView<'_>,
    eligible: &BTreeSet<OwnerId>,
    epoch_seconds: u64,
    accepted_at: u64,
    now: u64,
) -> Result<SupportAward, AwardDenial> {
    if epoch_seconds == 0 || accepted_at > now {
        return Err(AwardDenial::Epoch);
    }
    if view.social_status(record.id()) != SocialStatus::Committed {
        return Err(AwardDenial::NotCommitted);
    }
    let Body::Social {
        actor,
        operation:
            Operation::React {
                post,
                reaction: Reaction::Up(_),
                ..
            },
        ..
    } = record.body()
    else {
        return Err(AwardDenial::NotSupport);
    };
    let post_record = view.archive().get(*post).ok_or(AwardDenial::UnknownPost)?;
    let Body::Social {
        actor: post_actor,
        operation: Operation::Post { .. } | Operation::PostFaceted { .. },
        ..
    } = post_record.body()
    else {
        return Err(AwardDenial::NotPost);
    };
    if view.social_status(*post) != SocialStatus::Committed {
        return Err(AwardDenial::PostNotCommitted);
    }
    let source_owner = actor.owner();
    let beneficiary = post_actor.owner();
    if source_owner == beneficiary {
        return Err(AwardDenial::SelfSupport);
    }
    if !eligible.contains(&source_owner) {
        return Err(AwardDenial::Ineligible);
    }
    Ok(SupportAward {
        source_owner,
        beneficiary,
        activity_epoch: accepted_at / epoch_seconds,
        evidence_id: record.id(),
    })
}
