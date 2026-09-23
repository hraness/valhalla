//! Explicit operator re-arm of stopped host delivery jobs. Offline only: the
//! queue's exclusive custody refuses while an agent driver owns it, so a live
//! session never observes a job leaving `Stopped`.
use super::{agent_delivery, hex, now, unhex, Args};
use serde_json::json;
use vhalla_private_kernel::Context;
use vhalla_private_native::relay::delivery::JobState;

const REFUSED: &str = "delivery resume refused; preserve the exact queue, scan and applied evidence; stop any live agent-serve driver and retry with the same profile";

pub(super) fn execute(args: &Args, context: Context) -> Result<(), String> {
    let only = match args.flags.get("job") {
        Some(raw) => Some(unhex::<32>(raw.to_str().ok_or(REFUSED)?)?),
        None => None,
    };
    let (stream, mut queue) = agent_delivery::open_queue(args, context)?;
    let resumed = queue.resume(only, now()?).map_err(|_| REFUSED)?;
    let mut jobs = Vec::with_capacity(resumed.len());
    for status in &resumed {
        let evidence = queue.evidence(status.id).map_err(|_| REFUSED)?;
        jobs.push(json!({
            "digest": hex(&status.id),
            "sequence": status.sequence.to_string(),
            "state": match status.state {
                JobState::Pending => "pending",
                JobState::Uncertain => "uncertain",
                JobState::Retained => "retained",
                JobState::Stopped => "stopped",
            },
            "uncertain": status.uncertain,
            "attempts": status.attempts,
            "outages": evidence.outages,
            "resumes": evidence.resumes,
            "spent_attempts": evidence.spent_attempts,
            "last_error": status.last_error.map(|e| e.to_string()),
        }));
    }
    println!(
        "{}",
        json!({"status":"resumed","stream":stream,"resumed":resumed.len(),"jobs":jobs,"note":"exact bytes retry from a fresh budget; spent attempts remain evidence"})
    );
    Ok(())
}
