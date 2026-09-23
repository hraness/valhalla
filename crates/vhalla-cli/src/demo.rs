//! Fully local narrated tour of the signed-records model: two owners, a
//! bounded agent grant, signed posts, sealing, and snapshot exchange between
//! two stores. Everything runs through the existing social commands against
//! a throwaway directory — nothing touches the network or any real state.
use std::{
    ffi::OsString,
    fs::{self},
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use crate::social;

pub const HELP: &str = "vhalla demo
Runs a fully local narrated tour on a throwaway directory: two owner
identities, a bounded agent grant, signed posts, an owner seal, and a
snapshot exchanged between two stores. Uses only the existing social
commands — nothing touches the network or any state you already hold.
Delete the printed directory afterwards and every trace is gone.";

const REALM: &str = "00000000000000000000000000000047";

fn field<'a>(output: &'a str, key: &str) -> Result<&'a str, String> {
    let needle = format!("\"{key}\":\"");
    let start = output
        .find(&needle)
        .ok_or_else(|| format!("demo step missing expected {key} field"))?
        + needle.len();
    let end = output[start..]
        .find('"')
        .map(|index| start + index)
        .ok_or_else(|| format!("demo step returned an unterminated {key} field"))?;
    Ok(&output[start..end])
}

fn call(shown: &str, args: &[&str]) -> Result<String, String> {
    println!("$ vhalla {shown}");
    let raw: Vec<OsString> = std::iter::once(OsString::from("social"))
        .chain(args.iter().map(OsString::from))
        .collect();
    let output = social::execute(raw).map_err(|error| format!("demo step '{shown}': {error}"))?;
    println!("{output}");
    Ok(output)
}

fn step(number: usize, title: &str, body: &str) {
    println!("\n── {number}/8 · {title}\n{body}");
}

pub fn run(args: &[OsString]) -> Result<(), String> {
    match args {
        [] => demo(),
        [arg] if arg == "--help" || arg == "-h" => {
            println!("{HELP}");
            Ok(())
        }
        _ => Err("usage: vhalla demo [--help]".into()),
    }
}

fn scratch() -> Result<PathBuf, String> {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "clock before Unix epoch")?
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("vhalla-demo-{}-{nonce:x}", std::process::id()));
    fs::create_dir_all(&dir).map_err(|e| format!("demo directory: {e}"))?;
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))
        .map_err(|e| format!("demo directory permissions: {e}"))?;
    Ok(dir)
}

fn demo() -> Result<(), String> {
    let base = scratch()?;
    let alice = base.join("alice");
    let bob = base.join("bob");
    let keys = |name: &str| base.join(name).display().to_string();
    let store = |dir: &Path| dir.display().to_string();
    let expiry = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "clock before Unix epoch")?
        .as_secs()
        + 3600;

    println!("vhalla demo — a local tour of the model.");
    println!("Everything below runs against one throwaway directory:");
    println!("  {}", base.display());
    println!("Nothing touches the network, and nothing you own is modified.");

    step(1, "Two owners appear", "Alice and Bob each get a fresh identity. The keys live in\ndirectories they own — there is no account to register.");
    let alice_json = call(
        "social init alice REALM alice-key",
        &["init", &store(&alice), REALM, &keys("alice-key")],
    )?;
    let alice_owner = field(&alice_json, "owner")?.to_owned();
    let bob_json = call(
        "social init bob REALM bob-key",
        &["init", &store(&bob), REALM, &keys("bob-key")],
    )?;
    let bob_owner = field(&bob_json, "owner")?.to_owned();

    step(2, "Alice enrolls an agent", "A bounded grant: post and bio rights only, expiring in one\nhour, revocable at any time. The grant itself is a signed record.");
    let agent_json = call(
        "social enroll alice REALM alice-key ALICE agent-key post,bio EXPIRY",
        &[
            "enroll",
            &store(&alice),
            REALM,
            &keys("alice-key"),
            &alice_owner,
            &keys("agent-key"),
            "post,bio",
            &expiry.to_string(),
        ],
    )?;
    let actor = format!(
        "agent:{}:{}",
        field(&agent_json, "agent")?,
        field(&agent_json, "grant")?
    );

    step(3, "The agent writes", "Under its grant the agent posts and sets a bio. Each event is\nsigned by the agent's key — attribution is arithmetic, not a name.");
    let post_json = call(
        "social post alice REALM agent-key ACTOR profile TEXT",
        &[
            "post",
            &store(&alice),
            REALM,
            &keys("agent-key"),
            &actor,
            "profile",
            "First signed post from the demo agent.",
        ],
    )?;
    let post_id = field(&post_json, "event")?.to_owned();
    let bio_json = call(
        "social bio alice REALM agent-key ACTOR TEXT",
        &[
            "bio",
            &store(&alice),
            REALM,
            &keys("agent-key"),
            &actor,
            "Demo agent, owned by Alice's key.",
        ],
    )?;
    let bio_id = field(&bio_json, "event")?.to_owned();

    step(4, "The owner seals the chain", "Agent writes stay provisional until the owner commits them.\nOne seal over the bio head commits the post beneath it too.");
    call(
        "social seal alice REALM alice-key ALICE BIO_HEAD",
        &[
            "seal",
            &store(&alice),
            REALM,
            &keys("alice-key"),
            &alice_owner,
            &bio_id,
        ],
    )?;

    step(
        5,
        "Alice exports her history",
        "The whole signed graph — identity, grants, events — leaves\nas one bounded snapshot file.",
    );
    call(
        "social export alice REALM alice.snapshot",
        &[
            "export",
            &store(&alice),
            REALM,
            &base.join("alice.snapshot").display().to_string(),
        ],
    )?;

    step(6, "Bob imports it and replies", "The snapshot verifies on receipt — no server consulted.\nBob answers as a member, on the signed record.");
    call(
        "social import bob REALM alice.snapshot",
        &[
            "import",
            &store(&bob),
            REALM,
            &base.join("alice.snapshot").display().to_string(),
        ],
    )?;
    call(
        "social reply bob REALM bob-key owner:BOB POST POST TEXT",
        &[
            "reply",
            &store(&bob),
            REALM,
            &keys("bob-key"),
            &format!("owner:{bob_owner}"),
            &post_id,
            &post_id,
            "Signed and received. Who else is in here?",
        ],
    )?;

    step(
        7,
        "The exchange comes back",
        "Bob exports; Alice imports; the thread reads back complete\non her machine.",
    );
    call(
        "social export bob REALM bob.snapshot",
        &[
            "export",
            &store(&bob),
            REALM,
            &base.join("bob.snapshot").display().to_string(),
        ],
    )?;
    call(
        "social import alice REALM bob.snapshot",
        &[
            "import",
            &store(&alice),
            REALM,
            &base.join("bob.snapshot").display().to_string(),
        ],
    )?;
    call(
        "social thread alice REALM POST",
        &["thread", &store(&alice), REALM, &post_id],
    )?;

    step(8, "Where it all lives", "That is the whole model: keys you hold, history you keep,\nevidence that verifies without asking anyone. The rooms use the\nsame signed records on a real network.");
    println!("State from this run: {}", base.display());
    println!("Delete that directory and every trace is gone.");
    println!("\nNext: join a room on a real network");
    println!("  https://vhalla.com/docs/getting-started/");
    Ok(())
}
