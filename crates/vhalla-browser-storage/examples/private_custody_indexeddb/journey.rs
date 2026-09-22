//! Fixture-only composition of maintained custody, MLS and IndexedDB APIs.
//! Password re-encryption reseals a publicly known synthetic seed. It is not a
//! production password-change API and never extracts a seed from an identity.
use vhalla_browser_storage::{
    browser::{
        private_rooms::{IndexedPrivateStore, Limits},
        IndexedStorage,
    },
    identity::IdentitySnapshot,
    Image as VaultImage, Namespace, Slot,
};
use vhalla_browser_vault::{seal, unlock, Envelope, UnlockedIdentity, ENVELOPE_BYTES};
use vhalla_private_kernel::{
    protocol::{Key, Validity},
    storage::{Image, RecordKey, Store, StoredRecord},
    Context, Error, Kernel, MessageDraft, OperationId, OwnerDraft, Status,
};
use wasm_bindgen::JsValue;

const OLD_PASSWORD: &[u8] = b"Valhalla public fixture password v1";
const NEW_PASSWORD: &[u8] = b"Valhalla synthetic replacement password v1";
const WRONG_PASSWORD: &[u8] = b"Valhalla synthetic wrong account password v1";
const BODY: &[u8] = b"synthetic private custody retained message";

fn fail(error: impl std::fmt::Debug) -> JsValue {
    JsValue::from_str(&format!(
        "private account custody IndexedDB qualification: {error:?}"
    ))
}
fn ensure(value: bool, message: &str) -> Result<(), JsValue> {
    if value {
        Ok(())
    } else {
        Err(fail(message))
    }
}
fn hook(function: &js_sys::Function, mode: &str) -> Result<(), JsValue> {
    function.call1(&JsValue::NULL, &mode.into()).map(|_| ())
}
fn operation() -> OperationId {
    OperationId::from_bytes([17; 16]).expect("nonzero synthetic operation")
}
fn limits() -> Limits {
    Limits {
        max_records: 16,
        max_record_bytes: 1024 * 1024,
    }
}
fn fixture_envelope() -> Result<Envelope, JsValue> {
    let raw = include_str!("../../../vhalla-browser-vault/vectors/v1-envelope.hex").trim();
    ensure(raw.len() == 2 * ENVELOPE_BYTES, "fixture envelope size")?;
    let bytes = raw
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let text = std::str::from_utf8(pair).map_err(fail)?;
            u8::from_str_radix(text, 16).map_err(fail)
        })
        .collect::<Result<Vec<u8>, JsValue>>()?;
    Envelope::from_bytes(&bytes).map_err(fail)
}
fn vault_image(envelope: &Envelope) -> Result<VaultImage, JsValue> {
    VaultImage::new(Slot::Vault, &[envelope.as_bytes()]).map_err(fail)
}
fn raw_vault(snapshot: &IdentitySnapshot) -> Result<&[u8], JsValue> {
    snapshot
        .vault()
        .and_then(|image| image.records().next())
        .ok_or_else(|| fail("saved vault absent"))
}
async fn authenticated(namespace: Namespace, password: &[u8]) -> Result<UnlockedIdentity, JsValue> {
    let mut profile = IndexedStorage::open(namespace).await.map_err(fail)?;
    let saved = profile.load_identity().await.map_err(fail)?;
    let identity = unlock(raw_vault(&saved)?, password).map_err(fail)?;
    ensure(
        profile.revalidate_identity(&saved).await.map_err(fail)? == saved,
        "saved vault changed during authentication",
    )?;
    // A known fixture is imported; it must never manufacture local birth or
    // public-author initialization authority, even after a password change.
    ensure(
        matches!(
            saved.local_creation(identity.public_key()),
            Err(vhalla_browser_storage::Error::RecoveryRequired)
        ),
        "fixture import manufactured local creation provenance",
    )?;
    Ok(identity)
}

/// Fixture-only joint lifetime. No field or handle is returned to JavaScript.
/// Kernel/key/connection drop before account custody, as a future worker must do.
struct Custody {
    kernel: Kernel<IndexedPrivateStore>,
    identity: UnlockedIdentity,
}
impl Custody {
    async fn open(
        namespace: Namespace,
        context: Context,
        identity: UnlockedIdentity,
    ) -> Result<Self, Error> {
        // Wrong account is refused before attempting any private-store access.
        let key = identity.private_storage_key(context)?;
        let store = IndexedPrivateStore::open(namespace, context)
            .await
            .map_err(|_| Error::NeedsReopen)?;
        let kernel = Kernel::open(store, &key, context).await?;
        drop(key);
        Ok(Self { kernel, identity })
    }
}

struct Evidence {
    context: Context,
    status: Status,
    image: Image,
    records: [StoredRecord; 2],
    wire: Vec<u8>,
    draft: MessageDraft,
    now: u64,
}
async fn image(namespace: Namespace, context: Context) -> Result<Image, JsValue> {
    let mut store = IndexedPrivateStore::open(namespace, context)
        .await
        .map_err(fail)?;
    store
        .load(context)
        .await
        .map_err(fail)?
        .ok_or_else(|| fail("private image absent"))
}
async fn retained(namespace: Namespace, evidence: &Evidence) -> Result<(), JsValue> {
    let mut store = IndexedPrivateStore::open(namespace, evidence.context)
        .await
        .map_err(fail)?;
    ensure(
        store.load(evidence.context).await.map_err(fail)?.as_ref() == Some(&evidence.image),
        "exact current image changed",
    )?;
    for expected in &evidence.records {
        ensure(
            store
                .read(evidence.context, expected.key())
                .await
                .map_err(fail)?
                .as_ref()
                == Some(expected),
            "exact immutable private record changed",
        )?;
    }
    Ok(())
}

async fn create(namespace: Namespace) -> Result<Evidence, JsValue> {
    let envelope = fixture_envelope()?;
    let mut profile = IndexedStorage::open(namespace).await.map_err(fail)?;
    let empty = profile.load_identity().await.map_err(fail)?;
    ensure(
        empty == IdentitySnapshot::empty(),
        "fixture profile not empty",
    )?;
    profile
        .replace_identity(&empty, &vault_image(&envelope)?)
        .await
        .map_err(fail)?;
    drop(profile);
    let identity = authenticated(namespace, OLD_PASSWORD).await?;
    let now = (js_sys::Date::now() / 1000.0) as u64;
    let validity = Validity::new(
        now.checked_sub(30).ok_or_else(|| fail("clock"))?,
        now + 7200,
    )
    .map_err(fail)?;
    let draft = OwnerDraft::new(
        Key::from_bytes(identity.public_key()).map_err(fail)?,
        validity,
    )
    .map_err(fail)?;
    let anchor = identity
        .sign_private_anchor(draft.anchor_request())
        .map_err(fail)?;
    let enrollment = identity
        .sign_private_enrollment(draft.enrollment_request())
        .map_err(fail)?;
    let context = draft.context(&anchor).map_err(fail)?;
    let key = identity.private_storage_key(context).map_err(fail)?;
    let store = IndexedPrivateStore::create_new(namespace, context, limits())
        .await
        .map_err(fail)?;
    let kernel = Box::pin(draft.create(store, &key, enrollment, anchor, now))
        .await
        .map_err(fail)?;
    drop(key);
    let mut custody = Custody { kernel, identity };
    let draft = custody.kernel.prepare_message(BODY).map_err(fail)?;
    let wire = custody
        .kernel
        .send(operation(), &draft, now)
        .await
        .map_err(fail)?
        .bytes()
        .to_vec();
    let status = custody.kernel.status();
    // End both secret owners. Only synthetic plaintext and encrypted evidence
    // survive in the fixture; no key can be reused for the following reopen.
    drop(custody);
    let mut store = IndexedPrivateStore::open(namespace, context)
        .await
        .map_err(fail)?;
    let image = store
        .load(context)
        .await
        .map_err(fail)?
        .ok_or_else(|| fail("image"))?;
    let outbox = store
        .read(context, RecordKey::Outbox(1))
        .await
        .map_err(fail)?
        .ok_or_else(|| fail("outbox"))?;
    let index = store
        .read(context, RecordKey::Operation(operation()))
        .await
        .map_err(fail)?
        .ok_or_else(|| fail("operation"))?;
    Ok(Evidence {
        context,
        status,
        image,
        records: [outbox, index],
        wire,
        draft,
        now,
    })
}

async fn reopened(
    namespace: Namespace,
    evidence: &Evidence,
    password: &[u8],
) -> Result<Custody, JsValue> {
    let identity = authenticated(namespace, password).await?;
    let mut custody = Box::pin(Custody::open(namespace, evidence.context, identity))
        .await
        .map_err(fail)?;
    ensure(
        custody.kernel.status() == evidence.status,
        "reopen changed accepted state",
    )?;
    let retry = custody
        .kernel
        .send(operation(), &evidence.draft, evidence.now)
        .await
        .map_err(fail)?;
    ensure(
        retry.bytes() == evidence.wire,
        "exact retry changed ciphertext",
    )?;
    retained(namespace, evidence).await?;
    Ok(custody)
}

async fn password_change(namespace: Namespace, evidence: &Evidence) -> Result<(), JsValue> {
    // Known public test seed only. Production has no seed getter, and this
    // fixture does not implement a user-facing password-change/backup workflow.
    let seed: [u8; 32] = core::array::from_fn(|i| i as u8);
    let replacement = seal(seed.into(), NEW_PASSWORD, [141; 16], [142; 24]).map_err(fail)?;
    let mut profile = IndexedStorage::open(namespace).await.map_err(fail)?;
    let previous = profile.load_identity().await.map_err(fail)?;
    ensure(
        raw_vault(&previous)? != replacement.as_bytes(),
        "replacement did not change bytes",
    )?;
    ensure(
        replacement.claimed_public_key() == *evidence.context.account.as_bytes(),
        "replacement changed account",
    )?;
    let next = profile
        .replace_identity(&previous, &vault_image(&replacement)?)
        .await
        .map_err(fail)?;
    ensure(next != previous, "vault replacement was a no-op")?;
    ensure(
        matches!(
            unlock(raw_vault(&next)?, OLD_PASSWORD),
            Err(vhalla_browser_vault::Error::Authentication)
        ),
        "old password unlocked replacement",
    )?;
    drop(profile);
    retained(namespace, evidence).await
}

async fn refusal(
    namespace: Namespace,
    custody: &Custody,
    evidence: &Evidence,
    control: &js_sys::Function,
) -> Result<(), JsValue> {
    // Independently known synthetic negative account, not a production seed path.
    let wrong_envelope =
        seal([143; 32].into(), WRONG_PASSWORD, [144; 16], [145; 24]).map_err(fail)?;
    let wrong = unlock(wrong_envelope.as_bytes(), WRONG_PASSWORD).map_err(fail)?;
    hook(control, "deny-writes")?;
    ensure(
        matches!(
            Custody::open(namespace, evidence.context, wrong).await,
            Err(Error::Scope)
        ),
        "foreign account reached private custody",
    )?;
    ensure(
        image(namespace, evidence.context).await? == evidence.image,
        "wrong account changed image",
    )?;
    retained(namespace, evidence).await?;
    hook(control, "assert-no-write")?;

    // A different synthetic namespace, same exact account/device context, holds
    // only an explicitly initialized empty store. It is never real lost data.
    let mut missing_id = *namespace.identifier();
    missing_id[0] ^= 0x80;
    let missing = Namespace::new(missing_id);
    hook(control, "require-strict")?;
    drop(
        IndexedPrivateStore::create_new(missing, evidence.context, limits())
            .await
            .map_err(fail)?,
    );
    let key = custody
        .identity
        .private_storage_key(evidence.context)
        .map_err(fail)?;
    hook(control, "deny-writes")?;
    let empty = IndexedPrivateStore::open(missing, evidence.context)
        .await
        .map_err(fail)?;
    ensure(
        matches!(
            Kernel::open(empty, &key, evidence.context).await,
            Err(Error::Missing)
        ),
        "account-only custody recreated missing image",
    )?;
    drop(key);
    let mut empty = IndexedPrivateStore::open(missing, evidence.context)
        .await
        .map_err(fail)?;
    ensure(
        empty.load(evidence.context).await.map_err(fail)?.is_none(),
        "missing image initialized",
    )?;
    ensure(
        empty
            .read(evidence.context, RecordKey::Outbox(1))
            .await
            .map_err(fail)?
            .is_none(),
        "missing history initialized",
    )?;
    retained(namespace, evidence).await?;
    hook(control, "assert-no-write")?;
    Ok(())
}

/// Run only against fresh harness-owned random namespaces. The imported account
/// is public synthetic fixture data; actual MLS device entropy is still secure.
pub async fn run(namespace: Namespace, control: js_sys::Function) -> Result<String, JsValue> {
    hook(&control, "require-strict")?;
    let evidence = Box::pin(create(namespace)).await?;
    let old = Box::pin(reopened(namespace, &evidence, OLD_PASSWORD)).await?;
    drop(old);
    Box::pin(password_change(namespace, &evidence)).await?;
    let current = Box::pin(reopened(namespace, &evidence, NEW_PASSWORD)).await?;
    Box::pin(refusal(namespace, &current, &evidence, &control)).await?;
    drop(current);
    hook(&control, "finish")?;
    Ok("real account-derived MLS/IndexedDB: saved-vault authentication, joint custody drop, exact reopen and ciphertext retry, password re-encryption parity, wrong-account image preservation, and missing-image refusal passed".into())
}
