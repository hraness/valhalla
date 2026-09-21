//! Explicit local recovery of one exact held draft, never fresh peer admission.
use super::*;
use vhalla_room_activity::{
    continuity::HistoricalUnsigned, AdmissionContext, EventId, VerifiedEvent,
};

pub(super) const HELP: &str = "vhalla public activity recover-history BOOTSTRAP PIN64 JOURNAL KEY_DIR OUTBOX ROOM64 EXPECTED_SEQUENCE EXPECTED_EVENT64 [--replay-profile PROFILE]\nRecover only this exact already-durable unsigned request against its admitted historical enabled policy. All unsigned content, timestamp, policy ID, author and chain fields stay unchanged. This signs and retains local continuity material, not a currently permitted post or delivery receipt. A later ordinary current-policy terminal is required for new peer admission. Missing state never initializes an author; preserve every path after uncertainty.";

#[derive(Clone, Copy)]
struct Selection {
    sequence: u64,
    event: EventId,
}
impl Selection {
    fn parse(sequence: &str, event: &str) -> Result<Self, String> {
        let n: u64 = sequence.parse().map_err(|_| "invalid selected sequence")?;
        if n == 0 || n.to_string() != sequence {
            return Err("selected sequence must be nonzero canonical unsigned decimal".into());
        }
        let id = EventId::from_bytes(crate::public_network::hex32(event)?);
        if id == EventId::ZERO {
            return Err("selected event ID cannot be zero".into());
        }
        Ok(Self {
            sequence: n,
            event: id,
        })
    }
}

enum Target {
    Retained(Box<VerifiedEvent>),
    Pending(Box<ReservedDraft>),
}
fn target(store: &NativeOutbox, selected: Selection) -> Result<Target, String> {
    let head = store.head().map_err(preserved)?;
    if selected.sequence <= head.sequence() {
        let event = store
            .read_page(selected.sequence - 1, 1)
            .map_err(preserved)?
            .events
            .into_iter()
            .next()
            .ok_or("selected retained frame is missing")?;
        if event.id() != selected.event || event.claims().sequence != selected.sequence {
            return Err(
                "selected sequence contains different retained content; nothing replaced".into(),
            );
        }
        return Ok(Target::Retained(Box::new(event)));
    }
    let pending = store
        .load_pending()
        .map_err(preserved)?
        .ok_or("no exact held draft; nothing signed or created")?;
    if pending.base() != head
        || head.sequence().checked_add(1) != Some(selected.sequence)
        || pending.request().claims().sequence != selected.sequence
        || pending.request().id() != selected.event
    {
        return Err("selected sequence/ID does not match the actual pending draft and author base; nothing signed".into());
    }
    Ok(Target::Pending(Box::new(pending)))
}

// Private seam only. Production accepts the unchanged certified Context, not a
// remote registry or caller-supplied authorization callback. Tests count signer
// calls and inject a final-HEAD refusal around real native CAS/publication.
trait View {
    fn head(&self) -> HistoryHead;
    fn historical(&self, request: UnsignedEvent) -> Result<HistoricalUnsigned, String>;
    fn check_current(&self) -> Result<(), String>;
}
impl View for Context {
    fn head(&self) -> HistoryHead {
        self.head
    }
    fn historical(&self, request: UnsignedEvent) -> Result<HistoricalUnsigned, String> {
        if request.claims().scope != self.room {
            return Err("held draft has a different complete room scope".into());
        }
        AdmissionContext::new(self.room.network, self.client.registry())
            .and_then(|context| context.check_historical_unsigned(request))
            .map_err(|e| format!("unsigned historical policy check: {e:?}; no signing grant or past-admission claim"))
    }
    fn check_current(&self) -> Result<(), String> {
        Context::check_current(self)
    }
}

struct Recovered {
    event: VerifiedEvent,
    basis: Option<HistoryHead>,
}
fn recover(
    view: &impl View,
    store: &mut NativeOutbox,
    selected: Selection,
    sign: impl FnOnce(UnsignedEvent) -> Result<VerifiedEvent, String>,
) -> Result<Recovered, String> {
    let original = match target(store, selected)? {
        Target::Retained(event) => {
            return Ok(Recovered {
                event: *event,
                basis: None,
            })
        }
        Target::Pending(draft) => draft,
    };
    // The shared historical algorithm runs on unsigned bytes before any signer.
    let checked = view.historical(original.request().clone())?;
    let basis = view.head();
    let draft = original
        .rebase_historical(basis, &checked)
        .map_err(preserved)?;
    view.check_current()?;
    let prior = store.history_head().map_err(preserved)?;
    if prior != basis {
        store.advance_history(prior, basis).map_err(preserved)?;
    }
    if draft.as_bytes() != original.as_bytes() {
        store
            .rebase_reservation(&original, &draft)
            .map_err(preserved)?;
    }
    // Both exact retries and newly rebased drafts pass actual durable storage
    // checks. A token alone never replaces the persisted reservation.
    store.reserve(&draft).map_err(preserved)?;
    if view.head() != basis
        || store.head().map_err(preserved)? != draft.base()
        || store.history_head().map_err(preserved)? != basis
        || store.load_pending().map_err(preserved)?.as_ref() != Some(&draft)
    {
        return Err("recovery basis or exact pending state changed before signing".into());
    }
    view.check_current()?;
    let event = sign(checked.request().clone())?;
    // A produced signature is retained even if current policy changes later.
    // Failure preserves the same pending request/intent; never reset or rebase
    // its content as a way to repair an uncertain signature/publication.
    store.finalize(&draft, &event).map_err(preserved)?;
    Ok(Recovered {
        event,
        basis: Some(basis),
    })
}

pub(super) fn run(args: &[OsString], profile: Option<&Path>) -> Result<(), String> {
    if args.len() != 11 {
        return Err(HELP.into());
    }
    let selected = Selection::parse(
        args[9].to_str().ok_or("invalid sequence")?,
        args[10].to_str().ok_or("invalid event ID")?,
    )?;
    let mut context = Context::load(args, profile)?;
    let identity = Identity::open(Path::new(&args[6]))
        .map_err(|e| format!("open retained author identity: {e:?}"))?;
    let author = AuthorScope::new(context.room, identity.public_key());
    let mut store =
        NativeOutbox::open(Path::new(&args[7]), author, context.head.scope()).map_err(preserved)?;
    // Wrong selection refuses before profile catch-up. Already-signed recovery
    // is an indexed read and never touches a newer pending draft or needs a new
    // current policy grant. It makes no fresh historical-evaluation claim.
    if matches!(target(&store, selected)?, Target::Pending(_)) {
        context.replay(Some(store.history_head().map_err(preserved)?))?;
    }
    let result = recover(&context, &mut store, selected, |request| {
        identity
            .sign_activity(request)
            .and_then(|e| e.verify())
            .map_err(|e| {
                format!("typed historical draft signing: {e:?}; exact reservation retained")
            })
    })?;
    println!("author-sequence {}", result.event.claims().sequence);
    println!(
        "event-id {}",
        crate::public_network::hex(result.event.id().as_bytes())
    );
    if let Some(basis) = result.basis {
        println!("status signed-and-retained-for-continuity");
        println!("evaluation-height {}", basis.frontier().height);
        println!(
            "evaluation-registry {}",
            crate::public_network::hex(&basis.frontier().registry)
        );
    } else {
        println!("status already-signed-retained-locally");
    }
    println!("current-posting-permission not-established");
    println!("past-admission not-established");
    println!("delivery not-established");
    Ok(())
}

#[cfg(test)]
#[path = "recovery/tests.rs"]
mod tests;
