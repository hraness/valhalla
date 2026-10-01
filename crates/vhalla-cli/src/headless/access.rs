//! Process-retained room grants with one-use durable authorization and guarded output.

use super::{
    backend::Room,
    catalog::{commitment, Catalog, Hash, Hex, Id, Locator},
    local::{OutputPermit, Reply},
};
use hraness_control_kit::{ErrorBody, ErrorCode};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use vhalla_private_native::agent::{
    AgentAccess, Budget, LocalGrant, Permissions, RevocationHandle,
};

const MAX_GRANTS: usize = 128;
const MAX_SENDS: u64 = 4096;
const MAX_PAGE: usize = 16;
const TEXT_BYTES: usize = 4096;
type Result<T> = std::result::Result<T, ErrorBody>;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct GrantPermissions {
    pub status: bool,
    pub messages: bool,
    pub send: bool,
    pub outbox_status: bool,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct GrantBudget {
    pub calls: u64,
    pub send_attempts: u64,
    pub body_bytes: u64,
    pub read_records: u64,
    pub read_bytes: u64,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum Scope {
    Public {
        pin: Hash,
        author: Hash,
        policy: Hash,
        revision: u64,
    },
    Private {
        room: Hash,
        anchor: Hash,
        account: Hash,
        device: Hash,
        epoch: u64,
        roster: Hash,
    },
}
impl Scope {
    fn locator(self) -> Locator {
        match self {
            Self::Public { pin, .. } => Locator::Public { pin },
            Self::Private {
                room,
                anchor,
                account,
                device,
                ..
            } => Locator::Private {
                room,
                anchor,
                account,
                device,
            },
        }
    }
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct GrantSpec {
    pub scope: Scope,
    pub permissions: GrantPermissions,
    pub budget: GrantBudget,
    pub not_before: u64,
    pub expires_at: u64,
}

/// Only token-bound inert operations. No caller can choose a different room,
/// account, policy, author, destination, file, key or generic signing operation.
#[derive(Deserialize)]
#[serde(tag = "method", deny_unknown_fields)]
pub(super) enum Request {
    #[serde(rename = "agent.status")]
    Status { generation: Hash, token: Hash },
    #[serde(rename = "agent.messages")]
    Messages {
        generation: Hash,
        token: Hash,
        after: u64,
        limit: usize,
    },
    #[serde(rename = "agent.send")]
    Send {
        generation: Hash,
        token: Hash,
        operation: Id,
        text: String,
    },
    #[serde(rename = "agent.outbox_status")]
    OutboxStatus {
        generation: Hash,
        token: Hash,
        after: u64,
        limit: usize,
    },
}
impl Request {
    fn credential(&self) -> (Hash, Hash) {
        match self {
            Self::Status { generation, token }
            | Self::Messages {
                generation, token, ..
            }
            | Self::Send {
                generation, token, ..
            }
            | Self::OutboxStatus {
                generation, token, ..
            } => (*generation, *token),
        }
    }
    fn validate(&self) -> Result<()> {
        let (generation, token) = self.credential();
        if generation.0 == [0; 32] || token.0 == [0; 32] {
            return Err(usage());
        }
        match self {
            Self::Messages { limit, .. } | Self::OutboxStatus { limit, .. }
                if *limit == 0 || *limit > MAX_PAGE =>
            {
                return Err(usage())
            }
            Self::Send {
                operation, text, ..
            } => {
                if operation.0 == [0; 16] {
                    return Err(usage());
                }
                vhalla_direct_room::Text::new(text).map_err(|_| usage())?;
            }
            _ => {}
        }
        Ok(())
    }
}
pub(super) fn parse(value: Value) -> Result<Request> {
    let request: Request = serde_json::from_value(value).map_err(|_| usage())?;
    request.validate()?;
    Ok(request)
}
fn usage() -> ErrorBody {
    ErrorBody::new(ErrorCode::Usage, "Invalid scoped agent request or grant.")
}
fn closed() -> ErrorBody {
    ErrorBody::new(
        ErrorCode::PermissionDenied,
        "This scoped grant is closed or no longer authorized.",
    )
}
fn denied() -> ErrorBody {
    ErrorBody::new(
        ErrorCode::PermissionDenied,
        "This grant's permission or remaining budget does not allow the call.",
    )
}
fn conflict() -> ErrorBody {
    ErrorBody::new(
        ErrorCode::Conflict,
        "The operation was already bound to a different intent.",
    )
}
fn unavailable() -> ErrorBody {
    ErrorBody::new(
        ErrorCode::OwnerUnavailable,
        "The scoped operation requires trusted local reconciliation.",
    )
}
fn wall() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|v| v.as_secs())
        .map_err(|_| closed())
}

struct Clock {
    deadline: Instant,
    expires: u64,
    last_tick: Instant,
    last_wall: u64,
}
struct Live {
    generation: Hash,
    active: AtomicBool,
    clock: Mutex<Clock>,
}
impl Live {
    fn new(generation: Hash, now: u64, expires: u64) -> Result<Self> {
        let tick = Instant::now();
        Ok(Self {
            generation,
            active: AtomicBool::new(true),
            clock: Mutex::new(Clock {
                deadline: tick
                    .checked_add(Duration::from_secs(
                        expires.checked_sub(now).ok_or_else(usage)?,
                    ))
                    .ok_or_else(usage)?,
                expires,
                last_tick: tick,
                last_wall: now,
            }),
        })
    }
    fn close(&self) {
        self.active.store(false, Ordering::Release);
    }
    fn check(&self, generation: Hash) -> bool {
        if generation != self.generation || !self.active.load(Ordering::Acquire) {
            return false;
        }
        let valid = (|| {
            let mut clock = self.clock.lock().ok()?;
            let now = wall().ok()?;
            let tick = Instant::now();
            if tick < clock.last_tick
                || tick >= clock.deadline
                || now < clock.last_wall
                || now >= clock.expires
            {
                return None;
            }
            clock.last_tick = tick;
            clock.last_wall = now;
            Some(())
        })()
        .is_some();
        if !valid {
            self.close();
        }
        valid && self.active.load(Ordering::Acquire)
    }
}
struct CallGuard {
    live: Arc<Live>,
    completed: bool,
}
impl Drop for CallGuard {
    fn drop(&mut self) {
        if !self.completed {
            self.live.close();
        }
    }
}
enum Access {
    Public,
    Private {
        access: Box<AgentAccess>,
        authority: RevocationHandle,
    },
}
struct Grant {
    room: Id,
    operation: Id,
    intent: Hash,
    spec: GrantSpec,
    remaining: GrantBudget,
    live: Arc<Live>,
    access: Access,
    operations: BTreeMap<Id, Hash>,
}
impl Drop for Grant {
    fn drop(&mut self) {
        self.live.close();
        if let Access::Private { authority, .. } = &self.access {
            authority.revoke();
        }
    }
}
impl Grant {
    fn guarded(&self, value: Value) -> Reply {
        let live = self.live.clone();
        let generation = live.generation;
        Reply::guarded(value, OutputPermit::new(move || live.check(generation)))
    }
    fn token_reply(&self, token: Hash) -> Reply {
        self.guarded(json!({"generation":self.live.generation,"token":token,"room":self.room,
            "expires_at":self.spec.expires_at,"scope":self.spec.scope,"permissions":self.spec.permissions,
            "allowance":"retained for this process; reconnect does not renew it"}))
    }
    fn check(&mut self, room: &mut Room) -> Result<()> {
        if !self.live.check(self.live.generation) {
            return Err(closed());
        }
        check_scope(self.spec.scope, room)?;
        match (&mut self.access, room) {
            (Access::Public, Room::Public(_)) => {}
            (Access::Private { access, .. }, Room::Private(room)) => {
                room.scoped_agent(access).map_err(|_| closed())?;
            }
            _ => return Err(closed()),
        }
        Ok(())
    }
    async fn handle(&mut self, room: &mut Room, request: Request) -> Result<Reply> {
        self.check(room)?;
        if self.remaining.calls == 0 {
            return Err(denied());
        }
        self.remaining.calls -= 1;
        let permitted = match &request {
            Request::Status { .. } => self.spec.permissions.status,
            Request::Messages { .. } => self.spec.permissions.messages,
            Request::Send { .. } => self.spec.permissions.send,
            Request::OutboxStatus { .. } => self.spec.permissions.outbox_status,
        };
        if !permitted {
            return Err(denied());
        }
        if let Request::Send {
            operation, text, ..
        } = &request
        {
            let hash = commitment(b"agent-send-body", text.as_bytes());
            if self
                .operations
                .get(operation)
                .is_some_and(|old| *old != hash)
            {
                return Err(conflict());
            }
            if !self.operations.contains_key(operation)
                && self.operations.len() >= MAX_SENDS as usize
            {
                return Err(denied());
            }
        }
        match (&mut self.access, &mut *room) {
            (Access::Public, Room::Public(room)) => {
                preflight_public(&mut self.remaining, room, &request)?
            }
            (Access::Private { access, .. }, Room::Private(room)) => {
                preflight_private(room, access, &request)?
            }
            _ => return Err(closed()),
        }
        if let Request::Send {
            operation, text, ..
        } = &request
        {
            self.operations
                .insert(*operation, commitment(b"agent-send-body", text.as_bytes()));
        }
        let mut guard = CallGuard {
            live: self.live.clone(),
            completed: false,
        };
        let result = match (&mut self.access, &mut *room) {
            (Access::Public, Room::Public(room)) => {
                public_call(room, &request, self.room, self.spec.scope, self.remaining)
            }
            (Access::Private { access, .. }, Room::Private(room)) => {
                private_call(room, access, &request, self.room, self.remaining.calls).await
            }
            _ => return Err(closed()),
        };
        // A known intent conflict consumed this attempt but did not publish or
        // make custody uncertain. Keep only a still-valid native grant alive;
        // an image conflict or cancellation must never clear a native latch.
        let value = match result {
            Ok(value) => value,
            Err(error) => {
                if error.code == ErrorCode::Conflict {
                    self.check(room)?;
                    guard.completed = true;
                }
                return Err(error);
            }
        };
        self.check(room)?;
        guard.completed = true;
        Ok(self.guarded(value))
    }
}

pub(super) struct Registry {
    generation: Hash,
    grants: BTreeMap<Hash, Grant>,
}
impl Registry {
    pub(super) fn new(generation: Hash) -> Result<Self> {
        if generation.0 == [0; 32] {
            return Err(usage());
        }
        Ok(Self {
            generation,
            grants: BTreeMap::new(),
        })
    }
    pub(super) fn issue(
        &mut self,
        catalog: &mut Catalog,
        operation: Id,
        room_id: Id,
        room: &mut Room,
        spec: GrantSpec,
    ) -> Result<Reply> {
        catalog.check().map_err(|_| unavailable())?;
        let now = wall()?;
        validate_spec(&spec, now)?;
        if operation.0 == [0; 16] || room_id.0 == [0; 16] {
            return Err(usage());
        }
        if !catalog
            .slot(room_id)
            .is_some_and(|slot| slot.ready && slot.locator == Some(spec.scope.locator()))
        {
            return Err(closed());
        }
        let intent = commitment(
            b"agent-grant",
            &serde_json::to_vec(&(room_id, &spec)).map_err(|_| usage())?,
        );
        if let Some(token) = self
            .grants
            .iter()
            .find_map(|(token, grant)| (grant.operation == operation).then_some(*token))
        {
            let grant = self.grants.get_mut(&token).expect("existing grant");
            if grant.intent != intent || grant.room != room_id {
                return Err(conflict());
            }
            if grant.check(room).is_err() {
                self.revoke(token);
                return Err(closed());
            }
            return Ok(grant.token_reply(token));
        }
        self.grants
            .retain(|_, grant| grant.live.check(self.generation));
        if self.grants.len() >= MAX_GRANTS {
            return Err(denied());
        }
        check_scope(spec.scope, room)?;
        let access = match room {
            Room::Public(_) => Access::Public,
            Room::Private(room) => {
                let status = room.status().map_err(|_| closed())?;
                let (grant, authority) = LocalGrant::for_status(
                    status,
                    Duration::from_secs(spec.expires_at - now),
                    Permissions {
                        inbox: spec.permissions.messages,
                        queue: spec.permissions.send,
                        outbox_status: spec.permissions.outbox_status,
                    },
                    Budget {
                        preparations: spec.budget.send_attempts,
                        messages: spec.budget.send_attempts,
                        body_bytes: spec.budget.body_bytes,
                        read_records: spec.budget.read_records,
                        read_bytes: spec.budget.read_bytes,
                    },
                )
                .map_err(|_| closed())?;
                Access::Private {
                    access: Box::new(room.agent_access(grant).map_err(|_| closed())?),
                    authority,
                }
            }
        };
        let live = Arc::new(Live::new(self.generation, now, spec.expires_at)?);
        let token = self.fresh_token(operation, intent)?;
        let grant = Grant {
            room: room_id,
            operation,
            intent,
            remaining: spec.budget,
            spec,
            live,
            access,
            operations: BTreeMap::new(),
        };
        // No live token leaves this method before the complete authorization is
        // durably consumed. An existing receipt never reconstructs allowances.
        if !catalog.claim_grant(operation, intent).map_err(|error| {
            if error == vhalla_direct_store::Error::Conflict {
                conflict()
            } else {
                unavailable()
            }
        })? {
            return Err(closed());
        }
        let reply = grant.token_reply(token);
        self.grants.insert(token, grant);
        reply.check_release()?;
        Ok(reply)
    }
    fn fresh_token(&self, operation: Id, intent: Hash) -> Result<Hash> {
        for _ in 0..4 {
            let mut random = [0; 32];
            getrandom::fill(&mut random).map_err(|_| unavailable())?;
            if random == [0; 32] {
                continue;
            }
            let mut hash = Sha256::new();
            hash.update(b"valhalla/headless/agent-token/v1\0");
            hash.update(self.generation.0);
            hash.update(operation.0);
            hash.update(intent.0);
            hash.update(random);
            let token = Hex(hash.finalize().into());
            if token.0 != [0; 32] && !self.grants.contains_key(&token) {
                return Ok(token);
            }
        }
        Err(unavailable())
    }
    pub(super) fn room_for(&self, request: &Request) -> Result<Id> {
        request.validate()?;
        let (generation, token) = request.credential();
        if generation != self.generation {
            return Err(closed());
        }
        let grant = self.grants.get(&token).ok_or_else(closed)?;
        if !grant.live.check(generation) {
            return Err(closed());
        }
        Ok(grant.room)
    }
    pub(super) async fn handle(&mut self, room: &mut Room, request: Request) -> Result<Reply> {
        let id = self.room_for(&request)?;
        let (_, token) = request.credential();
        self.audit_room(id, room);
        let result = self
            .grants
            .get_mut(&token)
            .ok_or_else(closed)?
            .handle(room, request)
            .await;
        self.audit_room(id, room);
        result
    }
    pub(super) fn audit_room(&mut self, room_id: Id, room: &mut Room) {
        self.grants
            .retain(|_, grant| grant.room != room_id || grant.check(room).is_ok());
    }
    pub(super) fn revoke(&mut self, token: Hash) {
        self.grants.remove(&token);
    }
    pub(super) fn close_room(&mut self, room_id: Id) {
        self.grants.retain(|_, grant| grant.room != room_id);
    }
    pub(super) fn close_all(&mut self) {
        self.grants.clear();
    }
}
impl Drop for Registry {
    fn drop(&mut self) {
        self.close_all();
    }
}

fn validate_spec(spec: &GrantSpec, now: u64) -> Result<()> {
    if now < spec.not_before
        || now >= spec.expires_at
        || spec
            .expires_at
            .checked_sub(spec.not_before)
            .is_none_or(|v| v == 0 || v > 86_400)
        || spec.budget.calls == 0
        || spec.budget.calls > 8192
        || spec.budget.send_attempts > MAX_SENDS
        || spec.budget.body_bytes > 16 * 1024 * 1024
        || spec.budget.read_records > 4096
        || spec.budget.read_bytes > 128 * 1024 * 1024
    {
        return Err(usage());
    }
    Ok(())
}
fn check_scope(scope: Scope, room: &mut Room) -> Result<()> {
    match (scope, room) {
        (
            Scope::Public {
                pin,
                author,
                policy,
                revision,
            },
            Room::Public(room),
        ) => {
            let status = room.status().map_err(|_| closed())?;
            if *status.room.as_bytes() != pin.0
                || status.author != author.0
                || *status.policy.id.as_bytes() != policy.0
                || status.policy.revision != revision
                || status.pending_policy.is_some()
                || status.owner_forked
                || status.capacity_fenced
                || status.author_custody_lost
                || status.owner_custody_lost
            {
                return Err(closed());
            }
        }
        (
            Scope::Private {
                room: id,
                anchor,
                account,
                device,
                epoch,
                roster,
            },
            Room::Private(room),
        ) => {
            let status = room.status().map_err(|_| closed())?;
            if *status.context.scope.room.as_bytes() != id.0
                || *status.context.scope.anchor.as_bytes() != anchor.0
                || *status.context.account.as_bytes() != account.0
                || *status.context.device.as_bytes() != device.0
                || status.epoch != epoch
                || status.roster != roster.0
                || status.quarantined
                || matches!(
                    status.phase,
                    vhalla_private_kernel::Phase::AwaitingWelcome
                        | vhalla_private_kernel::Phase::Removed
                )
            {
                return Err(closed());
            }
        }
        _ => return Err(closed()),
    }
    Ok(())
}
fn preflight_public(
    budget: &mut GrantBudget,
    room: &mut vhalla_direct_native::RoomSession,
    request: &Request,
) -> Result<()> {
    match request {
        Request::Send { text, .. } => {
            if budget.send_attempts == 0 || budget.body_bytes < text.len() as u64 {
                return Err(denied());
            }
            budget.send_attempts -= 1;
            budget.body_bytes -= text.len() as u64;
        }
        Request::Messages { after, limit, .. } | Request::OutboxStatus { after, limit, .. } => {
            if *after > room.status().map_err(|_| closed())?.storage.tip {
                return Err(usage());
            }
            let text = matches!(request, Request::Messages { .. });
            let bytes = *limit as u64 * if text { TEXT_BYTES as u64 } else { 256 };
            if budget.read_bytes < bytes || (text && budget.read_records < *limit as u64) {
                return Err(denied());
            }
            budget.read_bytes -= bytes;
            if text {
                budget.read_records -= *limit as u64;
            }
        }
        Request::Status { .. } => {}
    }
    Ok(())
}
fn preflight_private(
    room: &mut vhalla_private_native::client::RoomSession,
    access: &mut AgentAccess,
    request: &Request,
) -> Result<()> {
    let status = room
        .scoped_agent(access)
        .map_err(|_| closed())?
        .status()
        .map_err(|_| closed())?;
    let budget = status.remaining;
    match request {
        Request::Send { text, .. }
            if budget.preparations == 0
                || budget.messages == 0
                || budget.body_bytes < text.len() as u64 =>
        {
            return Err(denied())
        }
        Request::Messages { after, limit, .. } => {
            if *after > status.accepted.inbox_head {
                return Err(usage());
            }
            if budget.read_records < *limit as u64
                || budget.read_bytes < (*limit * TEXT_BYTES) as u64
            {
                return Err(denied());
            }
        }
        Request::OutboxStatus { after, limit, .. } => {
            if *after > status.accepted.outbox_head {
                return Err(usage());
            }
            if budget.read_bytes < *limit as u64 * 256 {
                return Err(denied());
            }
        }
        _ => {}
    }
    Ok(())
}
fn public_call(
    room: &mut vhalla_direct_native::RoomSession,
    request: &Request,
    id: Id,
    scope: Scope,
    remaining: GrantBudget,
) -> Result<Value> {
    Ok(match request {
        Request::Status { .. } => {
            let status = room.status().map_err(|_| unavailable())?;
            json!({"room":id,"kind":"public","policy":Hex(*status.policy.id.as_bytes()),"revision":status.policy.revision,
                "author":Hex(status.author),"can_send":status.can_send,"pending_event_operation":status.pending_event_operation.map(Hex),
                "pending_policy_operation":status.pending_policy_operation.map(Hex),"remaining":remaining,"freshness":"local authenticated state"})
        }
        Request::Messages { after, limit, .. } => {
            let page = room.messages(*after, *limit).map_err(|_| unavailable())?;
            json!({"room":id,"kind":"public","head":page.tip,"next":page.next,"records":page.messages.iter().map(|row| {
                let event = row.event.claims();
                json!({"cursor":row.cursor,"event":Hex(*row.event.id().as_bytes()),"author":Hex(event.author),"sequence":event.sequence,
                    "policy":Hex(*event.policy.as_bytes()),"text":event.text.as_str(),"visibility":format!("{:?}",row.visibility),"trust":"inert untrusted room content"})
            }).collect::<Vec<_>>()})
        }
        Request::Send {
            operation, text, ..
        } => {
            let Scope::Public {
                author,
                policy,
                revision,
                ..
            } = scope
            else {
                return Err(closed());
            };
            let expected = vhalla_direct_room::PolicyPosition {
                revision,
                id: vhalla_direct_room::PolicyId::from_bytes(policy.0),
            };
            let outcome = room
                .send_scoped(expected, author.0, operation.0, text, wall()?)
                .map_err(|error| {
                    if error == vhalla_direct_native::Error::OperationConflict {
                        conflict()
                    } else {
                        unavailable()
                    }
                })?;
            json!({"room":id,"operation":operation,"frame_hash":Hex(<[u8;32]>::from(Sha256::digest(&outcome.bytes))),
                "state":format!("{:?}",outcome.state),"exact_retry":outcome.exact_retry,"delivery":"not asserted"})
        }
        Request::OutboxStatus { after, limit, .. } => public_operations(room, id, *after, *limit)?,
    })
}
async fn private_call(
    room: &mut vhalla_private_native::client::RoomSession,
    access: &mut AgentAccess,
    request: &Request,
    id: Id,
    calls: u64,
) -> Result<Value> {
    Ok(match request {
        Request::Status { .. } => {
            let mut session = room.scoped_agent(access).map_err(|_| closed())?;
            let status = session.status().map_err(|_| unavailable())?;
            let remaining = GrantBudget {
                calls,
                send_attempts: status.remaining.preparations.min(status.remaining.messages),
                body_bytes: status.remaining.body_bytes,
                read_records: status.remaining.read_records,
                read_bytes: status.remaining.read_bytes,
            };
            json!({"room":id,"kind":"private","epoch":status.accepted.epoch,"roster":Hex(status.accepted.roster),
                "inbox_head":status.accepted.inbox_head,"outbox_head":status.accepted.outbox_head,"remaining":remaining,"freshness":"local authenticated state"})
        }
        Request::Messages { after, limit, .. } => {
            let mut session = room.scoped_agent(access).map_err(|_| closed())?;
            let page = session
                .inbox(*after, *limit)
                .await
                .map_err(|_| unavailable())?;
            json!({"room":id,"kind":"private","head":page.head,"next":page.next,"records":page.records.iter()
                .filter(|row| !vhalla_private_kernel::MemberAcceptance::is_receipt(row.body())).map(|row|json!({"cursor":row.sequence(),
                    "sender":Hex(*row.sender().as_bytes()),"text":std::str::from_utf8(row.body()).ok(),"body_hex":plain_hex(row.body()),
                    "trust":"inert untrusted room content"})).collect::<Vec<_>>()})
        }
        Request::Send {
            operation, text, ..
        } => {
            let mut session = room.scoped_agent(access).map_err(|_| closed())?;
            let draft = session
                .prepare(text.as_bytes())
                .map_err(|_| unavailable())?;
            let queued = session
                .queue(
                    vhalla_private_kernel::OperationId::from_bytes(operation.0)
                        .map_err(|_| usage())?,
                    draft,
                )
                .await;
            let queued = queued.map_err(|error| {
                if matches!(
                    error,
                    vhalla_private_native::client::Error::Agent(
                        vhalla_private_native::agent::Error::Kernel(
                            vhalla_private_kernel::Error::Conflict
                        )
                    )
                ) && !session.latched()
                {
                    conflict()
                } else {
                    unavailable()
                }
            })?;
            json!({"room":id,"operation":operation,"sequence":queued.sequence,"state":"locally_queued","delivery":"not asserted"})
        }
        Request::OutboxStatus { after, limit, .. } => {
            // The scoped page checks and charges its outbox permission before
            // trusted receipt inspection. Only a bounded count is disclosed;
            // raw receipts and ciphertext never cross the agent boundary.
            let page = {
                let mut session = room.scoped_agent(access).map_err(|_| closed())?;
                session
                    .outbox_status(*after, *limit)
                    .await
                    .map_err(|_| unavailable())?
            };
            let mut records = Vec::with_capacity(page.records.len());
            for row in &page.records {
                let count = if row.kind == vhalla_private_kernel::OutboxKind::Application {
                    room.acceptances(row.sequence)
                        .await
                        .map_err(|_| unavailable())?
                        .len()
                } else {
                    0
                };
                records.push(
                    json!({"cursor":row.sequence,"operation":Hex(*row.operation.as_bytes()),
                    "kind":format!("{:?}",row.kind),"artifact_bytes":row.artifact_bytes,
                    "member_acceptance_count":count}),
                );
            }
            json!({"room":id,"kind":"private","head":page.head,"next":page.next,"records":records,"delivery":"not asserted",
                "acceptance_scope":"Authenticated device processing claims from current roster members; human reading is unknown."})
        }
    })
}
fn plain_hex(bytes: &[u8]) -> String {
    const HEX: &[u8] = b"0123456789abcdef";
    let mut result = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        result.push(HEX[(byte >> 4) as usize] as char);
        result.push(HEX[(byte & 15) as usize] as char);
    }
    result
}
fn public_operations(
    room: &mut vhalla_direct_native::RoomSession,
    id: Id,
    after: u64,
    limit: usize,
) -> Result<Value> {
    let page = room.operations(after, limit).map_err(|_| unavailable())?;
    Ok(
        json!({"room":id,"kind":"public","head":page.tip,"next":page.next,"operations":page.operations.iter().map(|row|json!({
        "cursor":row.cursor,"operation":Hex(row.operation),"kind":format!("{:?}",row.kind),"frame_hash":Hex(row.frame_hash)
    })).collect::<Vec<_>>(),"delivery":"not asserted"}),
    )
}

#[cfg(test)]
#[path = "access_tests.rs"]
mod tests;
