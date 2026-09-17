//! Public-boundary regressions for authenticated requests and host-owned grants.

use hegel::generators as gs;
use hegel::TestCase;
use vhalla_core::{Epoch, EventId, PeerId, RealmId, RoomId, Sequence};
use vhalla_crypto::{
    peer_id_from_seed, sign, verifying_key_from_seed, ReplayWindow, SessionId, VerificationContext,
    VerifiedEnvelope,
};
use vhalla_host::{HostError, MemoryHost};
use vhalla_policy::{
    Denied, LocalPolicy, Operation, RemoteRequest, Scope, KIND_READ_MEMORY_REQUEST,
};
use vhalla_wire::Envelope;

fn context(epoch: u64) -> VerificationContext {
    VerificationContext {
        audience: PeerId(1),
        realm: RealmId(2),
        room: RoomId(3),
        epoch: Epoch(epoch),
        session: SessionId(4),
    }
}
fn key(seed: u8) -> [u8; 32] {
    verifying_key_from_seed([seed; 32]).to_bytes()
}
fn policy(context: VerificationContext, seed: u8, resource: u32) -> LocalPolicy {
    LocalPolicy::read_memory(context, key(seed), resource)
}
fn verified(
    context: VerificationContext,
    seed: u8,
    kind: u8,
    expiry: u64,
    body: &[u8],
) -> VerifiedEnvelope {
    let envelope = Envelope::new(
        kind,
        peer_id_from_seed([seed; 32]),
        context.realm,
        context.room,
        EventId(9),
        Sequence(1),
        body,
    )
    .unwrap();
    let signed = sign(
        envelope,
        context.audience,
        context.epoch,
        context.session,
        expiry,
        [seed; 32],
    )
    .unwrap();
    ReplayWindow::new(context, 1)
        .unwrap()
        .verify_and_accept(signed, &verifying_key_from_seed([seed; 32]), 50)
        .unwrap()
}
fn request(context: VerificationContext, seed: u8, resource: u32, expiry: u64) -> RemoteRequest {
    RemoteRequest::from_verified(
        verified(
            context,
            seed,
            KIND_READ_MEMORY_REQUEST,
            expiry,
            b"untrusted peer text",
        ),
        Scope {
            operation: Operation::ReadMemory,
            resource,
        },
    )
    .unwrap()
}

#[test]
fn only_explicit_full_key_and_scope_grants_mint_capabilities() {
    let context = context(1);
    let host = MemoryHost::new(policy(context, 7, 11));
    assert_eq!(
        host.authorize(request(context, 8, 11, 100)).unwrap_err(),
        Denied::Requester
    );
    assert_eq!(
        host.authorize(request(context, 7, 12, 100)).unwrap_err(),
        Denied::Scope
    );
    assert!(host.authorize(request(context, 7, 11, 100)).is_ok());
    assert_eq!(host.reads(), 0);
}

#[test]
fn every_context_coordinate_is_checked_at_authorization() {
    let base = context(1);
    let host = MemoryHost::new(policy(base, 7, 11));
    for (changed, expected) in [
        (
            VerificationContext {
                audience: PeerId(99),
                ..base
            },
            Denied::Owner,
        ),
        (
            VerificationContext {
                realm: RealmId(99),
                ..base
            },
            Denied::Context,
        ),
        (
            VerificationContext {
                room: RoomId(99),
                ..base
            },
            Denied::Context,
        ),
        (
            VerificationContext {
                session: SessionId(99),
                ..base
            },
            Denied::Context,
        ),
        (
            VerificationContext {
                epoch: Epoch(99),
                ..base
            },
            Denied::Epoch,
        ),
    ] {
        assert_eq!(
            host.authorize(request(changed, 7, 11, 100)).unwrap_err(),
            expected
        );
    }
    assert_eq!(host.reads(), 0);
}

#[test]
fn chat_and_unknown_kinds_cannot_become_effect_requests() {
    for kind in [1, 3, u8::MAX] {
        let proof = verified(context(1), 7, kind, 100, b"read resource 11");
        assert_eq!(
            RemoteRequest::from_verified(
                proof,
                Scope {
                    operation: Operation::ReadMemory,
                    resource: 11
                }
            )
            .unwrap_err(),
            Denied::Kind
        );
    }
}

#[test]
fn execution_uses_actual_host_context_key_scope_and_expiry() {
    let base = context(1);
    let mint = MemoryHost::new(policy(base, 7, 11));
    for (target, expected) in [
        (
            policy(
                VerificationContext {
                    audience: PeerId(2),
                    ..base
                },
                7,
                11,
            ),
            Denied::Owner,
        ),
        (
            policy(
                VerificationContext {
                    room: RoomId(4),
                    ..base
                },
                7,
                11,
            ),
            Denied::Context,
        ),
        (policy(base, 8, 11), Denied::Requester),
        (policy(base, 7, 12), Denied::Scope),
    ] {
        let capability = mint.authorize(request(base, 7, 11, 100)).unwrap();
        let mut other_host = MemoryHost::new(target);
        assert_eq!(
            other_host.execute(capability, 75),
            Err(HostError::Denied(expected))
        );
        assert_eq!(other_host.reads(), 0);
    }
    let mut host = MemoryHost::new(policy(base, 7, 11));
    let expired = host.authorize(request(base, 7, 11, 100)).unwrap();
    assert_eq!(
        host.execute(expired, 101),
        Err(HostError::Denied(Denied::Expired))
    );
    assert_eq!(host.reads(), 0);
    let at_expiry = host.authorize(request(base, 7, 11, 100)).unwrap();
    assert_eq!(host.execute(at_expiry, 100).unwrap().event_id, EventId(9));
    assert_eq!(host.reads(), 1);
}

#[test]
fn advancing_policy_revokes_prepared_capabilities_and_old_requesters() {
    let old = context(1);
    let new = context(2);
    let mut host = MemoryHost::new(policy(old, 7, 11));
    let stale = host.authorize(request(old, 7, 11, 100)).unwrap();
    host.replace_policy(policy(new, 8, 12)).unwrap();
    assert_eq!(
        host.execute(stale, 75),
        Err(HostError::Denied(Denied::Epoch))
    );
    assert_eq!(
        host.authorize(request(new, 7, 12, 100)).unwrap_err(),
        Denied::Requester
    );
    assert_eq!(
        host.authorize(request(old, 8, 12, 100)).unwrap_err(),
        Denied::Epoch
    );
    let current = host.authorize(request(new, 8, 12, 100)).unwrap();
    host.execute(current, 75).unwrap();
    assert_eq!(host.reads(), 1);
}

#[test]
fn rejected_policy_replacements_preserve_current_grant() {
    let base = context(7);
    let mut host = MemoryHost::new(policy(base, 7, 11));
    for (replacement, expected) in [
        (
            VerificationContext {
                epoch: Epoch(6),
                ..base
            },
            Denied::Epoch,
        ),
        (base, Denied::Epoch),
        (
            VerificationContext {
                audience: PeerId(2),
                epoch: Epoch(8),
                ..base
            },
            Denied::Owner,
        ),
        (
            VerificationContext {
                realm: RealmId(4),
                epoch: Epoch(8),
                ..base
            },
            Denied::Context,
        ),
        (
            VerificationContext {
                room: RoomId(5),
                epoch: Epoch(8),
                ..base
            },
            Denied::Context,
        ),
        (
            VerificationContext {
                session: SessionId(6),
                epoch: Epoch(8),
                ..base
            },
            Denied::Context,
        ),
    ] {
        assert_eq!(
            host.replace_policy(policy(replacement, 8, 12)),
            Err(expected)
        );
    }
    let retained = host.authorize(request(base, 7, 11, 100)).unwrap();
    host.execute(retained, 75).unwrap();
    assert_eq!(host.reads(), 1);
    let mut exhausted = MemoryHost::new(policy(context(u64::MAX), 7, 11));
    assert_eq!(
        exhausted.replace_policy(policy(context(0), 8, 12)),
        Err(Denied::Epoch)
    );
}

#[hegel::test(test_cases = 64)]
fn arbitrary_peer_prose_cannot_expand_scope(tc: TestCase) {
    let body = tc.draw(gs::vecs(gs::integers::<u8>()).max_size(1023));
    let resource = tc.draw(gs::integers::<u32>().max_value(999));
    let base = context(1);
    let mut host = MemoryHost::new(policy(base, 7, resource));
    let proof = verified(base, 7, KIND_READ_MEMORY_REQUEST, 100, &body);
    let hostile = RemoteRequest::from_verified(
        proof,
        Scope {
            operation: Operation::ReadMemory,
            resource: resource + 1,
        },
    )
    .unwrap();
    assert_eq!(hostile.content(), body.as_slice());
    assert_eq!(host.authorize(hostile).unwrap_err(), Denied::Scope);
    assert_eq!(host.reads(), 0);
    let valid = host.authorize(request(base, 7, resource, 100)).unwrap();
    host.execute(valid, 75).unwrap();
    assert_eq!(host.reads(), 1);
}

#[hegel::test(test_cases = 64)]
fn generated_policy_advancement_always_revokes_prepared_work(tc: TestCase) {
    let epoch = tc.draw(gs::integers::<u64>().min_value(1).max_value(999));
    let advance = tc.draw(gs::integers::<u64>().min_value(1).max_value(999));
    let replacement_resource = tc.draw(gs::integers::<u32>());
    let previous = context(epoch);
    let mut host = MemoryHost::new(policy(previous, 7, 11));
    let prepared = host.authorize(request(previous, 7, 11, 100)).unwrap();
    host.replace_policy(policy(context(epoch + advance), 7, replacement_resource))
        .unwrap();
    assert_eq!(
        host.execute(prepared, 75),
        Err(HostError::Denied(Denied::Epoch))
    );
    assert_eq!(host.reads(), 0);
}
