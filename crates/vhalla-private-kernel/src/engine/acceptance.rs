//! Recipient claims of durable processing, carried inside ordinary MLS messages.
use super::{
    messages::{bounded_wire, wire},
    *,
};
use crate::model::app_aad;
use ed25519_dalek::{Signature, VerifyingKey};
use openmls_traits::signatures::Signer;

const MAGIC: &[u8; 8] = b"VHACK\0\0\x01";
const SIGNED_BYTES: usize = 8 + 32 * 5 + 8;
const ENCODED_BYTES: usize = SIGNED_BYTES + 64;
const DOMAIN: &[u8] = b"vhalla/private-member-acceptance/v1\0";

/// A device-signed claim for one exact ciphertext after its durable reception.
///
/// The signature authenticates the recipient's claim, not their disk, human
/// reading, current membership, global freshness or independent replication.
/// Only [`Self::verify`] constructs this value, using a message already accepted
/// through the current room's authenticated MLS receive path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MemberAcceptance {
    context: Context,
    recipient: protocol::Key,
    ciphertext: [u8; 32],
    received_sequence: u64,
}
impl MemberAcceptance {
    /// The recipient device authenticated by both MLS and the inner signature.
    pub const fn recipient(&self) -> protocol::Key {
        self.recipient
    }
    /// Domain-separated commitment to the original exact MLS ciphertext.
    pub const fn ciphertext(&self) -> [u8; 32] {
        self.ciphertext
    }
    /// Recipient-local inbox position claimed by the signer, not a global clock.
    pub const fn received_sequence(&self) -> u64 {
        self.received_sequence
    }
    /// Whether inert content uses the reserved receipt prefix. This is only
    /// framing, never evidence of a valid claim; call [`Self::verify`] to trust it.
    pub fn is_receipt(body: &[u8]) -> bool {
        body.starts_with(MAGIC)
    }
    /// Read an **untrusted lookup hint** from exact version 1 framing only.
    /// This performs no signature, room, sender or reception verification. It
    /// may select the original retained output for [`Self::verify`], and must
    /// never create an acceptance status or authorize effects by itself.
    pub fn claimed_ciphertext(body: &[u8]) -> Option<[u8; 32]> {
        if !Self::is_receipt(body) || body.len() != ENCODED_BYTES {
            return None;
        }
        body[136..168].try_into().ok()
    }
    /// Domain-separated lookup commitment to exact ciphertext bytes. This hash
    /// alone says nothing about membership, receipt validity or durable storage.
    pub fn ciphertext_commitment(ciphertext: &[u8]) -> [u8; 32] {
        wire_hash(ciphertext)
    }
    /// Check that this already-verified claim belongs to the exact original
    /// sender custody and retained application output. This does not reverify
    /// disk state or establish that the recipient remains a current member.
    pub fn matches_original(&self, context: Context, original: &CommittedOutbox) -> bool {
        self.context == context
            && original.kind() == OutboxKind::Application
            && self.ciphertext == wire_hash(original.bytes())
    }
    /// Verify against an original committed output from this exact sender's
    /// custody and an authenticated received message from this same room.
    /// Ordinary messages return `None`; malformed/forged receipt bodies refuse.
    pub fn verify(
        context: Context,
        original: &CommittedOutbox,
        received: &ReceivedMessage,
    ) -> Result<Option<Self>> {
        let body = received.body();
        if !Self::is_receipt(body) {
            return Ok(None);
        }
        if body.len() != ENCODED_BYTES || original.kind() != OutboxKind::Application {
            return Err(Error::Encoding);
        }
        let field = |offset: usize| -> &[u8] { &body[offset..offset + 32] };
        if field(8) != context.scope.room.as_bytes()
            || field(40) != context.scope.anchor.as_bytes()
            || field(72) != context.device.as_bytes()
            || field(104) != received.sender().as_bytes()
            || field(136) != wire_hash(original.bytes())
            || received.sender() == context.device
        {
            return Err(Error::Scope);
        }
        let sequence = u64::from_be_bytes(body[168..176].try_into().map_err(|_| Error::Encoding)?);
        if sequence == 0 {
            return Err(Error::Encoding);
        }
        let signature =
            Signature::from_slice(&body[SIGNED_BYTES..]).map_err(|_| Error::Encoding)?;
        let verifier = VerifyingKey::from_bytes(received.sender().as_bytes())
            .map_err(|_| Error::Authentication)?;
        verifier
            .verify_strict(&signing_bytes(&body[..SIGNED_BYTES]), &signature)
            .map_err(|_| Error::Authentication)?;
        Ok(Some(Self {
            context,
            recipient: received.sender(),
            ciphertext: wire_hash(original.bytes()),
            received_sequence: sequence,
        }))
    }
}

fn signing_bytes(claims: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(DOMAIN.len() + claims.len());
    bytes.extend_from_slice(DOMAIN);
    bytes.extend_from_slice(claims);
    bytes
}

impl<S: Store> Kernel<S> {
    /// Issue a signed receipt only for ciphertext already committed in this
    /// device's inbox. Reception and receipt issuance are separate recoverable
    /// transactions, each retaining its original exact bytes. This never
    /// acknowledges another receipt and never grants a generic signing API.
    ///
    /// The caller retains one operation ID for this receipt. Exact retries,
    /// including after a lost publication result or membership update, return
    /// the original ciphertext without advancing another sender ratchet.
    pub async fn issue_acceptance(
        &mut self,
        operation: OperationId,
        original: &[u8],
        now: u64,
    ) -> Result<CommittedOutbox> {
        bounded_wire(original)?;
        let digest = wire_hash(original);
        let request = packets::request(self.context, OutboxKind::Application, &[DOMAIN, &digest])?;
        let mut work = self.begin_live().await?;
        if let Some(retained) = self
            .retained(
                operation,
                request,
                OutboxKind::Application,
                work.state.outbox,
            )
            .await?
        {
            self.needs_reopen = false;
            return Ok(retained);
        }
        if !matches!(work.state.phase, Phase::OwnerJoined | Phase::MemberJoined) {
            return Err(Error::Policy);
        }
        work.state.check_time(now)?;
        let received = self
            .received(original, work.state.inbox)
            .await?
            .ok_or(Error::Missing)?;
        if MemberAcceptance::is_receipt(received.body()) {
            return Err(Error::Policy);
        }
        let mut body = Vec::with_capacity(ENCODED_BYTES);
        body.extend_from_slice(MAGIC);
        for field in [
            self.context.scope.room.as_bytes(),
            self.context.scope.anchor.as_bytes(),
            received.sender().as_bytes(),
            self.context.device.as_bytes(),
            &digest,
        ] {
            body.extend_from_slice(field);
        }
        body.extend_from_slice(&received.sequence().to_be_bytes());
        let signature = work
            .signer()?
            .sign(&signing_bytes(&body))
            .map_err(|_| Error::Mls)?;
        if signature.len() != 64 {
            return Err(Error::Mls);
        }
        body.extend_from_slice(&signature);
        let mut group = work.group()?;
        group.set_aad(app_aad(self.context));
        let message = group
            .create_message(&work.provider, &work.signer()?, &body)
            .map_err(|_| Error::Mls)?;
        work.state.clock = now;
        self.publish_sent(
            work,
            operation,
            request,
            OutboxKind::Application,
            wire(&message)?,
        )
        .await
    }
}
