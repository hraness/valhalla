//! Closed local UI/worker vocabulary. None of these reports is network authority.
use vhalla_private_kernel::{
    protocol::{ControlFloor, Key, SignedDeviceEnrollment, SignedRoomAnchor, Validity},
    Context, OperationId, OutboxKind, Status,
};
use zeroize::Zeroizing;

/// Fixed application profile; never selected by a room, peer, or imported file.
pub const PROFILE: [u8; 32] = *b"vhalla-browser-local-profile-v01";
/// Separate fixed profile for read-only archive destinations. Keeping archives
/// outside PROFILE means a live room prefix can never alias an archive view.
pub const ARCHIVE: [u8; 32] = *b"vhalla-browser-local-archive-v01";
/// Exact upper bound of a complete signed confidential contact offer.
pub const MAX_OFFER: usize = 713;
/// Maximum encoded encrypted artifact accepted by the local worker interface.
pub const MAX_ARTIFACT: usize = vhalla_private_kernel::MAX_STORED_RECORD_BYTES;
/// Bounded local message size, including page payload and framing overhead.
pub const MAX_FRAME: usize = vhalla_private_kernel::MAX_PAGE_BYTES + 16 * 1024;
/// Owned sensitive bytes cleared on drop; browser-managed copies remain outside this guarantee.
pub type Bytes = Zeroizing<Vec<u8>>;

/// Move-only disclosure preview. No Debug/Clone, implicit room move or re-sign.
pub struct Consent {
    /// Nonzero identifier for the worker's retained draft in this session.
    pub id: u64,
    /// Complete room, anchor, account, and device to which the draft belongs.
    pub context: Context,
    /// MLS epoch under which the draft was prepared.
    pub epoch: u64,
    /// Exact current roster commitment shown when preparing the draft.
    pub roster: [u8; 32],
    /// Exact inert message bytes; edits require a new preparation.
    pub body: Bytes,
}
impl Consent {
    /// Compare every scope, lifecycle, identifier, and content byte without rebinding a draft.
    pub fn same(&self, other: &Self) -> bool {
        self.id == other.id
            && self.context == other.context
            && self.epoch == other.epoch
            && self.roster == other.roster
            && self.body == other.body
    }
}

/// Caller-selected operations only. No URL, generic signature or storage key.
pub enum Request {
    /// Irreversibly select private mode and revalidate the saved account pair.
    Enter {
        /// Exact encrypted envelope already authenticated by this worker.
        vault: Bytes,
        /// Expected presence of matching durable local-creation metadata.
        local_birth: bool,
    },
    /// Prepare a fresh owner device with an explicitly selected validity interval.
    PrepareOwner(Validity),
    /// Prepare a recipient device from a confidential offer and independent owner pin.
    PrepareContact {
        /// Complete signed confidential contact offer; never a public directory record.
        offer: Bytes,
        /// Independently selected owner account, not trusted from the offer alone.
        owner: Key,
        /// Caller-selected recipient enrollment validity interval.
        validity: Validity,
    },
    /// Exact preview locator, retained by the trusted UI before consumption.
    CommitCreation(Context),
    /// Open only an existing exact context; missing state never means creation.
    Open(Context),
    /// Authenticate and return the selected room's retained membership snapshot.
    Membership,
    /// Retain one exact body and prepare its current epoch/roster disclosure preview.
    PrepareMessage(Bytes),
    /// Publish the exact retained draft locally after full consent comparison.
    Send {
        /// Stable nonzero operation identifier, reused only for an exact retry.
        operation: OperationId,
        /// Unchanged preview of the worker's still-retained draft.
        consent: Box<Consent>,
    },
    /// Issue a one-time confidential offer for an independently selected recipient account.
    Offer {
        /// Stable operation identifier for exact secret-issuance retries.
        operation: OperationId,
        /// Account permitted to answer the offer.
        recipient: Key,
        /// Explicit finite offer validity; the kernel enforces its tighter cap.
        validity: Validity,
    },
    /// Answer an exact confidential offer using this recipient's retained device state.
    ContactRequest {
        /// Stable operation identifier for the encrypted request.
        operation: OperationId,
        /// Complete independently selected signed offer.
        offer: Bytes,
    },
    /// Consume an authenticated encrypted request and admit its selected device.
    Accept {
        /// Stable operation identifier for admission and its encrypted response.
        operation: OperationId,
        /// Exact encrypted contact request bound to the owner's retained offer.
        request: Bytes,
        /// Explicit invitation validity interval, bounded by kernel policy.
        validity: Validity,
    },
    /// Join from the exact encrypted contact response for this pending request.
    Join(Bytes),
    /// Authenticate, commit, and only then expose one encrypted application message.
    Receive(Bytes),
    /// Remove one full admitted device key through an owner-authorized MLS transition.
    Remove {
        /// Stable identifier for the removal transition.
        operation: OperationId,
        /// Complete target device key, never a display label or leaf index alone.
        device: Key,
    },
    /// Renew the same owner device through a typed account grant and MLS update.
    Renew {
        /// Stable identifier for the renewal transition.
        operation: OperationId,
        /// Explicit monotonically extended enrollment validity interval.
        validity: Validity,
    },
    /// Authenticate and apply one encrypted owner control at the current floor.
    ApplyControl(Bytes),
    /// Read one bounded page of immutable encrypted owner controls.
    Controls {
        /// Exact retained control floor preceding the requested page.
        after: ControlFloor,
        /// Maximum page count; must be between one and the kernel's fixed page cap.
        limit: usize,
    },
    /// Read one bounded page of plaintext signed owner-control proofs. These
    /// are inspection records, not the encrypted envelopes members apply.
    ControlProofs {
        /// Exact retained control floor preceding the requested page.
        after: ControlFloor,
        /// Maximum page count; must be between one and the kernel's fixed page cap.
        limit: usize,
    },
    /// Compare one signed owner control against retained history only. A
    /// conflicting valid claim at a known floor writes durable quarantine in
    /// the kernel before the worker reports its terminal failure.
    ObserveControl(Bytes),
    /// Read the first locally proven owner-fork proof, if one is retained.
    /// Missing evidence means no locally retained proof only; it never clears
    /// quarantine or grants owner succession.
    ForkEvidence,
    /// Local qualification only: have the owner device sign a divergent control
    /// at an already retained floor, fabricating exactly the equivocation an
    /// observer quarantines on. Never a network artifact, state change or
    /// authority grant.
    #[cfg(feature = "local-qualification")]
    Divergent {
        /// Retained control-floor sequence to diverge.
        sequence: u64,
    },
    /// Read a bounded local outbox page; confidential offers return metadata only.
    Outbox {
        /// Exclusive local outbox sequence cursor, with zero before the first entry.
        after: u64,
        /// Maximum page count within the fixed kernel limit.
        limit: usize,
    },
    /// Read one bounded page of already committed inert inbox messages.
    Inbox {
        /// Exclusive local inbox sequence cursor, with zero before the first entry.
        after: u64,
        /// Maximum page count within the fixed kernel limit.
        limit: usize,
    },
    /// Begin a bounded encrypted archive export of the currently open room.
    /// The stream is read-only evidence; exporting never mutates the room.
    ArchiveExport,
    /// Emit the next encrypted archive page. The final page is followed by one
    /// `None` report; an interrupted stream is abandoned, never spliced.
    ArchiveExportNext,
    /// Begin or exactly resume archive reception for an independently selected
    /// context and archive identity. The account must match this session's.
    ArchiveImportBegin {
        /// Complete room, anchor, account and device the archive claims.
        context: Context,
        /// Random archive correlation ID from the file header, checked by the
        /// kernel against every authenticated page.
        archive_id: [u8; 32],
    },
    /// Feed one exact encrypted archive page in file order. The worker consumes
    /// source-image pages first, then appends record pages; the reply reports
    /// the durable receiving cursor so an interrupted import can resume.
    ArchiveImportFeed(Bytes),
    /// Finish reception with the exact authenticated final page. A completed
    /// archive becomes a read-only view; it never activates a live device.
    ArchiveImportFinish(Bytes),
    /// Open an already completed archive read-only from its exact retained
    /// final page. Missing or foreign destination state is refused.
    ArchiveOpen {
        /// Complete room, anchor, account and device the archive claims.
        context: Context,
        /// Archive correlation ID, independently retained with the context.
        archive_id: [u8; 32],
        /// Exact final encrypted page; authenticates the destination image.
        final_page: Bytes,
    },
    /// Re-read the open archive's last-observed membership snapshot.
    ArchiveInspect,
    /// Read one bounded page of committed archive inbox messages.
    ArchiveInbox {
        /// Exclusive archived inbox sequence cursor, with zero before the first entry.
        after: u64,
        /// Maximum page count within the fixed kernel limit.
        limit: usize,
    },
    /// Read one bounded page of retained archive outbox entries.
    ArchiveOutbox {
        /// Exclusive archived outbox sequence cursor, with zero before the first entry.
        after: u64,
        /// Maximum page count within the fixed kernel limit.
        limit: usize,
    },
    /// Drop any retained archive handle. Read-only state is never a custody
    /// requirement; the durable destination is unchanged.
    ArchiveClose,
}

/// Nonsecret creation locator and signed metadata, returned before any room commit.
pub struct Preview {
    /// Exact context the trusted UI must retain before authorizing creation.
    pub context: Context,
    /// Signed owner anchor; signature verification alone does not admit a member.
    pub anchor: SignedRoomAnchor,
    /// Account-signed enrollment of the fresh local device.
    pub enrollment: SignedDeviceEnrollment,
}
/// Authenticated local membership report; it does not prove global freshness.
pub struct Membership {
    /// Retained local epoch, floor, roster and lifecycle state.
    pub status: Status,
    /// Immutable signed room authority anchor.
    pub anchor: SignedRoomAnchor,
    /// Retained current owner device enrollment.
    pub owner: SignedDeviceEnrollment,
    /// Enrollment of the device held by this worker.
    pub local: SignedDeviceEnrollment,
    /// Bounded current admitted roster, including the owner.
    pub members: Vec<SignedDeviceEnrollment>,
}
/// Local outbox report, not evidence that any peer received the artifact.
pub struct Artifact {
    /// Nonzero immutable local outbox sequence.
    pub sequence: u64,
    /// Original operation identifier for exact retry correlation.
    pub operation: OperationId,
    /// Closed artifact kind; secret issuance is distinguished from transport bytes.
    pub kind: OutboxKind,
    /// None only for secret issuance. Never an empty ciphertext substitute.
    pub bytes: Option<Bytes>,
}
/// Already committed application message; its body remains inert untrusted content.
pub struct Inbound {
    /// Nonzero immutable local inbox sequence.
    pub sequence: u64,
    /// Full authenticated MLS sender device key.
    pub sender: Key,
    /// Committed plaintext for this private view only; never automatic public export.
    pub body: Bytes,
}
/// Immutable owner control with its exact full control floor. `Controls`
/// records carry the encrypted wire envelope; `ControlProofs` records carry
/// the plaintext signed proof for inspection only.
pub struct Control {
    /// Sequence and control identifier committed by this record.
    pub floor: ControlFloor,
    /// Exact retained control record bytes, not a plaintext membership export.
    pub bytes: Bytes,
}
/// Closed verdict from comparing one signed owner control with retained
/// history; a proven conflict never reaches this report because the kernel
/// writes durable quarantine first and the worker fails terminally.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObserveVerdict {
    /// The exact signed control is already accepted retained history.
    Retained,
    /// Valid owner signature at an unknown or future floor; members apply
    /// encrypted controls in order rather than adopting observed proofs.
    UnknownHistory,
    /// Valid owner signature below this device's retained history base; a
    /// late joiner cannot confirm or apply predecessor floors it never held.
    BeforeBase,
}
/// First locally proven conflict under the fixed owner's valid signature.
/// This is evidence for inspection; it never clears quarantine, chooses a
/// winner, or grants owner succession.
pub struct ForkProof {
    /// Previously accepted exact floor, backed by retained control/checkpoint.
    pub accepted: ControlFloor,
    /// Different valid owner-signed control at that same accepted sequence.
    pub conflicting: Bytes,
    /// Exact accepted signed control, or the bounded joining checkpoint.
    pub accepted_proof: Bytes,
    /// Whether `accepted_proof` is the joining checkpoint encoding.
    pub accepted_from_checkpoint: bool,
}
/// Closed local worker reports; decoding is not independent network admission.
pub enum Response {
    /// Private entry completed for this authenticated account key.
    Entered(Key),
    /// Fresh preparation awaiting exact locator retention and explicit commit.
    Prepared(Box<Preview>),
    /// Reauthenticated membership and local lifecycle metadata.
    Membership(Box<Membership>),
    /// Exact preview of one worker-retained message draft.
    Draft(Box<Consent>),
    /// Locally committed artifact; no network delivery is implied.
    Artifact {
        /// Complete context of the selected local room/device.
        context: Context,
        /// Exact committed output and operation metadata.
        artifact: Artifact,
    },
    /// Explicitly confidential transfer only; excluded from ordinary outbox.
    Offer {
        /// Complete context in which the offer was issued.
        context: Context,
        /// Exact secret-issuance operation identifier.
        operation: OperationId,
        /// Explicit confidential output; must never enter ordinary outbox sharing.
        secret: Bytes,
    },
    /// One authenticated message exposed only after local inbox publication.
    Received {
        /// Complete context that authenticated and committed the message.
        context: Context,
        /// Committed sender and inert plaintext content.
        message: Inbound,
    },
    /// Bounded encrypted-control page from one retained snapshot.
    Controls {
        /// Complete context of the selected local room/device.
        context: Context,
        /// Earliest independently retained control floor for this local history.
        base: ControlFloor,
        /// Observed complete retained control head.
        head: ControlFloor,
        /// Exclusive continuation floor when another retained page remains.
        next: Option<ControlFloor>,
        /// Ordered bounded immutable encrypted control records.
        records: Vec<Control>,
    },
    /// Bounded signed-control-proof page from one retained snapshot.
    ControlProofs {
        /// Complete context of the selected local room/device.
        context: Context,
        /// Earliest independently retained control floor for this local history.
        base: ControlFloor,
        /// Observed complete retained control head.
        head: ControlFloor,
        /// Exclusive continuation floor when another retained page remains.
        next: Option<ControlFloor>,
        /// Ordered bounded immutable signed-proof records.
        records: Vec<Control>,
    },
    /// Signed-control observation verdict against retained history only.
    Observed {
        /// Complete context of the selected local room/device.
        context: Context,
        /// Closed local comparison result; never a freshness claim.
        verdict: ObserveVerdict,
    },
    /// Retained owner-fork proof, when the kernel has durably recorded one.
    ForkEvidence {
        /// Complete context of the selected local room/device.
        context: Context,
        /// First locally proven conflict; none on a clean or unknown store.
        proof: Option<ForkProof>,
    },
    /// Bounded outbox page; secret issuance remains metadata-only.
    Outbox {
        /// Complete context of the selected local room/device.
        context: Context,
        /// Observed local outbox head, not a delivery cursor.
        head: u64,
        /// Exclusive continuation sequence when another page remains.
        next: Option<u64>,
        /// Ordered immutable local outputs; confidential offers have no artifact bytes.
        records: Vec<Artifact>,
    },
    /// Bounded page of already committed private inbox messages.
    Inbox {
        /// Complete context of the selected local room/device.
        context: Context,
        /// Observed complete local inbox head.
        head: u64,
        /// Exclusive continuation sequence when another page remains.
        next: Option<u64>,
        /// Ordered committed messages with bounded inert bodies.
        records: Vec<Inbound>,
    },
    /// Archive stream or destination identity. The random archive_id binds one
    /// exact exported stream; it is never a device, room or membership proof.
    ArchiveBegin {
        /// Complete context the export or import is bound to.
        context: Context,
        /// Archive correlation ID from the authenticated stream.
        archive_id: [u8; 32],
    },
    /// One bounded encrypted archive page; `None` marks a complete stream.
    ArchivePage {
        /// Complete context of the exporting room.
        context: Context,
        /// Exact encrypted page bytes; absent only after the final page.
        page: Option<Bytes>,
    },
    /// Durable archive-receiving cursor. Progress is not a completeness or
    /// liveness claim; it permits only exact same-archive resumption.
    ArchiveProgress {
        /// Complete context of the archive destination.
        context: Context,
        /// Whether the authenticated source image is complete and the durable
        /// destination now accepts record pages.
        source_ready: bool,
        /// Next expected file page index; earlier pages were already committed.
        next_page: u64,
        /// Immutable records durably copied so far.
        records: u64,
        /// Encrypted immutable payload bytes durably copied so far.
        bytes: u64,
    },
    /// Read-only archive view opened or re-read. The retained snapshot is the
    /// source's last local state; it grants no live-device or send authority.
    ArchiveInspect {
        /// Complete context of the imported archive.
        context: Context,
        /// Archive correlation ID of the exact completed stream.
        archive_id: [u8; 32],
        /// Exact source local revision at export time; not proof of newest state.
        source_revision: u64,
        /// Last-observed membership snapshot; never current authorization.
        status: Status,
    },
    /// Archive handle dropped. Only carried context is reported.
    ArchiveClosed {
        /// Complete context whose archive handle was released.
        context: Context,
    },
    /// Divergent signed owner control produced only by a local-qualification
    /// build; fork evidence material, never a committed outbox artifact.
    #[cfg(feature = "local-qualification")]
    Divergent {
        /// Complete context of the selected local room/device.
        context: Context,
        /// Divergent signed control at the requested retained floor.
        control: Bytes,
    },
}
impl Response {
    /// Return the complete selected context, absent only for account-only entry.
    pub fn context(&self) -> Option<Context> {
        match self {
            Self::Entered(_) => None,
            Self::Prepared(p) => Some(p.context),
            Self::Membership(m) => Some(m.status.context),
            Self::Draft(d) => Some(d.context),
            Self::Artifact { context, .. }
            | Self::Offer { context, .. }
            | Self::Received { context, .. }
            | Self::Controls { context, .. }
            | Self::ControlProofs { context, .. }
            | Self::Observed { context, .. }
            | Self::ForkEvidence { context, .. }
            | Self::Outbox { context, .. }
            | Self::Inbox { context, .. }
            | Self::ArchiveBegin { context, .. }
            | Self::ArchivePage { context, .. }
            | Self::ArchiveProgress { context, .. }
            | Self::ArchiveInspect { context, .. }
            | Self::ArchiveClosed { context } => Some(*context),
            #[cfg(feature = "local-qualification")]
            Self::Divergent { context, .. } => Some(*context),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
/// Response correlation tag; never an authority or permission token.
pub enum ReplyKind {
    /// Account-only private entry.
    Entered,
    /// Uncommitted creation preparation.
    Prepared,
    /// Authenticated local membership.
    Membership,
    /// Retained disclosure preview.
    Draft,
    /// Committed ordinary outbox artifact.
    Artifact,
    /// Explicit confidential offer output.
    Offer,
    /// Committed inbox message.
    Received,
    /// Immutable encrypted-control page.
    Controls,
    /// Immutable signed-control-proof page.
    ControlProofs,
    /// Signed-control observation verdict.
    Observed,
    /// Retained owner-fork proof report.
    ForkEvidence,
    /// Bounded ordinary outbox page.
    Outbox,
    /// Bounded committed inbox page.
    Inbox,
    /// Archive stream or destination identity.
    ArchiveBegin,
    /// One bounded encrypted archive page or stream end.
    ArchivePage,
    /// Durable archive receiving progress.
    ArchiveProgress,
    /// Read-only archive view summary.
    ArchiveInspect,
    /// Archive handle released.
    ArchiveClosed,
    /// Local-qualification divergent owner control.
    #[cfg(feature = "local-qualification")]
    Divergent,
}
impl Request {
    /// Expected closed response kind used by the generation-checked UI broker.
    pub fn reply_kind(&self) -> ReplyKind {
        match self {
            Self::Enter { .. } => ReplyKind::Entered,
            Self::PrepareOwner(_) | Self::PrepareContact { .. } => ReplyKind::Prepared,
            Self::CommitCreation(_)
            | Self::Open(_)
            | Self::Membership
            | Self::Join(_)
            | Self::ApplyControl(_) => ReplyKind::Membership,
            Self::PrepareMessage(_) => ReplyKind::Draft,
            Self::Send { .. }
            | Self::ContactRequest { .. }
            | Self::Accept { .. }
            | Self::Remove { .. }
            | Self::Renew { .. } => ReplyKind::Artifact,
            Self::Offer { .. } => ReplyKind::Offer,
            Self::Receive(_) => ReplyKind::Received,
            Self::Controls { .. } => ReplyKind::Controls,
            Self::ControlProofs { .. } => ReplyKind::ControlProofs,
            Self::ObserveControl(_) => ReplyKind::Observed,
            Self::ForkEvidence => ReplyKind::ForkEvidence,
            Self::Outbox { .. } | Self::ArchiveOutbox { .. } => ReplyKind::Outbox,
            Self::Inbox { .. } | Self::ArchiveInbox { .. } => ReplyKind::Inbox,
            Self::ArchiveExport | Self::ArchiveImportBegin { .. } => ReplyKind::ArchiveBegin,
            Self::ArchiveExportNext => ReplyKind::ArchivePage,
            Self::ArchiveImportFeed(_) => ReplyKind::ArchiveProgress,
            Self::ArchiveOpen { .. } | Self::ArchiveImportFinish(_) | Self::ArchiveInspect => {
                ReplyKind::ArchiveInspect
            }
            Self::ArchiveClose => ReplyKind::ArchiveClosed,
            #[cfg(feature = "local-qualification")]
            Self::Divergent { .. } => ReplyKind::Divergent,
        }
    }
}
impl Response {
    /// Closed report kind for exact request/response correlation.
    pub fn kind(&self) -> ReplyKind {
        match self {
            Self::Entered(_) => ReplyKind::Entered,
            Self::Prepared(_) => ReplyKind::Prepared,
            Self::Membership(_) => ReplyKind::Membership,
            Self::Draft(_) => ReplyKind::Draft,
            Self::Artifact { .. } => ReplyKind::Artifact,
            Self::Offer { .. } => ReplyKind::Offer,
            Self::Received { .. } => ReplyKind::Received,
            Self::Controls { .. } => ReplyKind::Controls,
            Self::ControlProofs { .. } => ReplyKind::ControlProofs,
            Self::Observed { .. } => ReplyKind::Observed,
            Self::ForkEvidence { .. } => ReplyKind::ForkEvidence,
            Self::Outbox { .. } => ReplyKind::Outbox,
            Self::Inbox { .. } => ReplyKind::Inbox,
            Self::ArchiveBegin { .. } => ReplyKind::ArchiveBegin,
            Self::ArchivePage { .. } => ReplyKind::ArchivePage,
            Self::ArchiveProgress { .. } => ReplyKind::ArchiveProgress,
            Self::ArchiveInspect { .. } => ReplyKind::ArchiveInspect,
            Self::ArchiveClosed { .. } => ReplyKind::ArchiveClosed,
            #[cfg(feature = "local-qualification")]
            Self::Divergent { .. } => ReplyKind::Divergent,
        }
    }
}
