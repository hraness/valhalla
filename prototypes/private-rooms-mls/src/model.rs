use chacha20poly1305::{
    KeyInit, XChaCha20Poly1305, XNonce,
    aead::{Aead, Payload},
};
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::OpenMlsProvider;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tls_codec::Deserialize as _;
use zeroize::Zeroizing;

const SUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
const MAX_IMAGE: usize = 4 * 1024 * 1024;
const MAX_WIRE: usize = 128 * 1024;
const MAX_BODY: usize = 4096;
const MAX_RECORDS: usize = 256;
const MAX_MESSAGES: usize = 64;
const DOMAIN: &[u8] = b"valhalla-mls-qualification-v1";

#[derive(Debug, PartialEq, Eq)]
pub(super) enum Error {
    Entropy,
    Bounds,
    Authentication,
    Codec,
    Mls,
    Scope,
    Conflict,
    #[cfg(test)]
    CommitRefused,
    NeedsReopen,
    Missing,
}

impl Error {
    pub(super) fn label(&self) -> &'static str {
        match self {
            Self::Entropy => "secure randomness unavailable",
            Self::Bounds => "qualification budget exceeded",
            Self::Authentication => "encrypted state authentication failed",
            Self::Codec => "invalid bounded encoding",
            Self::Mls => "MLS operation rejected",
            Self::Scope => "wrong qualification scope",
            Self::Conflict => "stale state or operation collision",
            #[cfg(test)]
            Self::CommitRefused => "synthetic commit refusal",
            Self::NeedsReopen => "uncertain outcome requires reopen",
            Self::Missing => "required committed record missing",
        }
    }
}

type Result<T> = std::result::Result<T, Error>;

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
enum Kind {
    KeyPackage,
    Welcome,
    Commit,
    Application,
}

#[derive(Clone, Serialize, Deserialize)]
struct Wire {
    kind: Kind,
    bytes: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
struct Sent {
    operation: [u8; 16],
    request: [u8; 32],
    outputs: Vec<Wire>,
}

#[derive(Serialize, Deserialize)]
struct Received {
    wire_hash: [u8; 32],
    kind: Kind,
    // Plaintext is quarantined in this private candidate, then encrypted at rest.
    // No accessor exists until it is reloaded from a successfully committed image.
    body: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
struct State {
    format: u16,
    room: [u8; 32],
    signer_public: Vec<u8>,
    label: Vec<u8>,
    group: bool,
    // Sorted opaque provider records. Values use upstream's JSON representation.
    records: Vec<(Vec<u8>, Vec<u8>)>,
    outbox: Vec<Sent>,
    inbox: Vec<Received>,
}

impl State {
    fn validate(&self, room: &[u8; 32]) -> Result<()> {
        if self.format != 1 || &self.room != room || self.signer_public.len() != 32 {
            return Err(Error::Scope);
        }
        if self.label.is_empty()
            || self.label.len() > 64
            || self.records.len() > MAX_RECORDS
            || self.outbox.len() > MAX_MESSAGES
            || self.inbox.len() > MAX_MESSAGES
        {
            return Err(Error::Bounds);
        }
        let mut previous: Option<&[u8]> = None;
        let mut bytes = 0usize;
        for (key, value) in &self.records {
            if key.len() > 4096 || value.len() > MAX_IMAGE / 2 {
                return Err(Error::Bounds);
            }
            if previous.is_some_and(|old| old >= key.as_slice()) {
                return Err(Error::Codec);
            }
            previous = Some(key);
            bytes = bytes
                .checked_add(key.len())
                .and_then(|n| n.checked_add(value.len()))
                .ok_or(Error::Bounds)?;
            if bytes > MAX_IMAGE {
                return Err(Error::Bounds);
            }
        }
        for item in &self.outbox {
            if item.outputs.is_empty() || item.outputs.len() > 2 {
                return Err(Error::Bounds);
            }
            for output in &item.outputs {
                bounded_wire(&output.bytes)?;
            }
        }
        if self.inbox.iter().any(|item| item.body.len() > MAX_BODY) {
            return Err(Error::Bounds);
        }
        Ok(())
    }
}

#[derive(Clone, PartialEq, Eq)]
struct Image {
    revision: u64,
    nonce: [u8; 24],
    ciphertext: Vec<u8>,
}

// Not exported: a candidate has no ciphertext/plaintext accessors. Only the
// trusted transaction model may publish it. There is no network callback here.
struct Prepared {
    base: Image,
    next: Image,
}

#[derive(Clone, Copy, Default)]
enum Fault {
    #[default]
    None,
    #[cfg(test)]
    BeforeCommit,
    #[cfg(test)]
    AfterCommit,
}

// This model's one assignment stands for a real atomic durable transaction. It
// tests protocol coupling, not filesystem fsync/IndexedDB/browser power loss.
struct Device {
    room: [u8; 32],
    key: Zeroizing<[u8; 32]>,
    image: Image,
    needs_reopen: bool,
}

struct Working {
    state: State,
    provider: OpenMlsRustCrypto,
}

impl Working {
    fn signer(&self) -> Result<SignatureKeyPair> {
        SignatureKeyPair::read(
            self.provider.storage(),
            &self.state.signer_public,
            SUITE.signature_algorithm(),
        )
        .ok_or(Error::Missing)
    }

    fn credential(&self) -> CredentialWithKey {
        CredentialWithKey {
            credential: BasicCredential::new(self.state.label.clone()).into(),
            signature_key: self.state.signer_public.clone().into(),
        }
    }

    fn group(&self) -> Result<MlsGroup> {
        if !self.state.group {
            return Err(Error::Missing);
        }
        MlsGroup::load(
            self.provider.storage(),
            &GroupId::from_slice(&self.state.room),
        )
        .map_err(|_| Error::Mls)?
        .ok_or(Error::Missing)
    }

    fn capture(mut self) -> Result<State> {
        let map = self
            .provider
            .storage()
            .values
            .read()
            .map_err(|_| Error::Mls)?;
        let bytes = map
            .iter()
            .try_fold(0usize, |total, (key, value)| {
                total
                    .checked_add(key.len())
                    .and_then(|n| n.checked_add(value.len()))
            })
            .ok_or(Error::Bounds)?;
        if map.len() > MAX_RECORDS || bytes > MAX_IMAGE {
            return Err(Error::Bounds);
        }
        self.state.records = map.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
        self.state.records.sort_by(|a, b| a.0.cmp(&b.0));
        self.state.validate(&self.state.room)?;
        Ok(self.state)
    }
}

impl Device {
    fn fresh(room: [u8; 32], label: &[u8]) -> Result<Self> {
        let provider = OpenMlsRustCrypto::default();
        let signer = SignatureKeyPair::new(SUITE.signature_algorithm()).map_err(|_| Error::Mls)?;
        signer.store(provider.storage()).map_err(|_| Error::Mls)?;
        let state = State {
            format: 1,
            room,
            signer_public: signer.to_public_vec(),
            label: label.to_vec(),
            group: false,
            records: Vec::new(),
            outbox: Vec::new(),
            inbox: Vec::new(),
        };
        let key = Zeroizing::new(random()?);
        let state = Working { state, provider }.capture()?;
        let image = seal(&key, &room, 0, &state)?;
        Ok(Self {
            room,
            key,
            image,
            needs_reopen: false,
        })
    }

    fn load(&self) -> Result<Working> {
        if self.needs_reopen {
            return Err(Error::NeedsReopen);
        }
        let mut state = unseal(&self.key, &self.room, &self.image)?;
        let provider = OpenMlsRustCrypto::default();
        provider
            .storage()
            .values
            .write()
            .map_err(|_| Error::Mls)?
            .extend(std::mem::take(&mut state.records));
        Ok(Working { state, provider })
    }

    fn prepare(&self, work: Working) -> Result<Prepared> {
        if self.needs_reopen {
            return Err(Error::NeedsReopen);
        }
        let revision = self.image.revision.checked_add(1).ok_or(Error::Bounds)?;
        let next = seal(&self.key, &self.room, revision, &work.capture()?)?;
        Ok(Prepared {
            base: self.image.clone(),
            next,
        })
    }

    fn commit(&mut self, prepared: Prepared, _fault: Fault) -> Result<()> {
        if self.needs_reopen {
            return Err(Error::NeedsReopen);
        }
        if prepared.base != self.image {
            return Err(Error::Conflict);
        }
        #[cfg(test)]
        if matches!(_fault, Fault::BeforeCommit) {
            return Err(Error::CommitRefused);
        }
        self.image = prepared.next;
        #[cfg(test)]
        if matches!(_fault, Fault::AfterCommit) {
            self.needs_reopen = true;
            return Err(Error::NeedsReopen);
        }
        Ok(())
    }

    fn reopen(&mut self) -> Result<()> {
        unseal(&self.key, &self.room, &self.image)?;
        self.needs_reopen = false;
        Ok(())
    }

    fn create_group(&mut self) -> Result<()> {
        let mut work = self.load()?;
        if work.state.group {
            return Err(Error::Conflict);
        }
        let config = MlsGroupCreateConfig::builder()
            .ciphersuite(SUITE)
            .wire_format_policy(PURE_CIPHERTEXT_WIRE_FORMAT_POLICY)
            .use_ratchet_tree_extension(true)
            .sender_ratchet_configuration(SenderRatchetConfiguration::new(4, 32))
            .build();
        MlsGroup::new_with_group_id(
            &work.provider,
            &work.signer()?,
            &config,
            GroupId::from_slice(&self.room),
            work.credential(),
        )
        .map_err(|_| Error::Mls)?;
        work.state.group = true;
        self.commit(self.prepare(work)?, Fault::None)
    }

    fn retained(&self, operation: [u8; 16], request: [u8; 32]) -> Result<Option<Vec<Wire>>> {
        let work = self.load()?;
        let found = work
            .state
            .outbox
            .iter()
            .find(|item| item.operation == operation);
        match found {
            Some(item) if item.request == request => Ok(Some(item.outputs.clone())),
            Some(_) => Err(Error::Conflict),
            None => Ok(None),
        }
    }

    fn key_package(&mut self, operation: [u8; 16], fault: Fault) -> Result<Vec<Wire>> {
        let request = digest(Kind::KeyPackage, &[]);
        if let Some(retained) = self.retained(operation, request)? {
            return Ok(retained);
        }
        let mut work = self.load()?;
        let package = KeyPackage::builder()
            .build(SUITE, &work.provider, &work.signer()?, work.credential())
            .map_err(|_| Error::Mls)?;
        work.state.outbox.push(Sent {
            operation,
            request,
            outputs: vec![wire(Kind::KeyPackage, package.key_package())?],
        });
        self.commit(self.prepare(work)?, fault)?;
        self.retained(operation, request)?.ok_or(Error::Missing)
    }

    fn add(&mut self, operation: [u8; 16], package: &[u8]) -> Result<Vec<Wire>> {
        bounded_wire(package)?;
        let request = digest(Kind::Welcome, package);
        if let Some(retained) = self.retained(operation, request)? {
            return Ok(retained);
        }
        let mut work = self.load()?;
        let package = KeyPackageIn::tls_deserialize_exact(package)
            .map_err(|_| Error::Codec)?
            .validate(work.provider.crypto(), ProtocolVersion::Mls10)
            .map_err(|_| Error::Mls)?;
        let mut group = work.group()?;
        group.set_aad(aad(&self.room));
        let (commit, welcome, _) = group
            .add_members(&work.provider, &work.signer()?, &[package])
            .map_err(|_| Error::Mls)?;
        // Qualification uses one owner and no concurrent membership commits.
        // Production must validate grants and establish Commit delivery ordering.
        group
            .merge_pending_commit(&work.provider)
            .map_err(|_| Error::Mls)?;
        work.state.outbox.push(Sent {
            operation,
            request,
            outputs: vec![wire(Kind::Commit, &commit)?, wire(Kind::Welcome, &welcome)?],
        });
        self.commit(self.prepare(work)?, Fault::None)?;
        self.retained(operation, request)?.ok_or(Error::Missing)
    }

    fn join(&mut self, welcome: &[u8], fault: Fault) -> Result<()> {
        bounded_wire(welcome)?;
        let mut work = self.load()?;
        if work.state.group {
            return Err(Error::Conflict);
        }
        let welcome = decode_welcome(welcome)?;
        let config = MlsGroupJoinConfig::builder()
            .wire_format_policy(PURE_CIPHERTEXT_WIRE_FORMAT_POLICY)
            .sender_ratchet_configuration(SenderRatchetConfiguration::new(4, 32))
            .build();
        let staged = StagedWelcome::new_from_welcome(&work.provider, &config, welcome, None)
            .map_err(|_| Error::Mls)?;
        if staged.group_context().group_id().as_slice() != self.room {
            return Err(Error::Scope);
        }
        if staged.members().count() != 2 {
            return Err(Error::Scope);
        }
        staged.into_group(&work.provider).map_err(|_| Error::Mls)?;
        work.state.group = true;
        self.commit(self.prepare(work)?, fault)
    }

    fn stage_send(&self, operation: [u8; 16], body: &[u8]) -> Result<Prepared> {
        if body.is_empty() || body.len() > MAX_BODY {
            return Err(Error::Bounds);
        }
        let mut work = self.load()?;
        if work
            .state
            .outbox
            .iter()
            .any(|item| item.operation == operation)
        {
            return Err(Error::Conflict);
        }
        let mut group = work.group()?;
        group.set_aad(aad(&self.room));
        let message = group
            .create_message(&work.provider, &work.signer()?, body)
            .map_err(|_| Error::Mls)?;
        work.state.outbox.push(Sent {
            operation,
            request: digest(Kind::Application, body),
            outputs: vec![wire(Kind::Application, &message)?],
        });
        self.prepare(work)
    }

    fn send(&mut self, operation: [u8; 16], body: &[u8], fault: Fault) -> Result<Vec<Wire>> {
        if body.is_empty() || body.len() > MAX_BODY {
            return Err(Error::Bounds);
        }
        let request = digest(Kind::Application, body);
        if let Some(retained) = self.retained(operation, request)? {
            return Ok(retained);
        }
        self.commit(self.stage_send(operation, body)?, fault)?;
        self.retained(operation, request)?.ok_or(Error::Missing)
    }

    fn inbox(&self, wire_hash: [u8; 32]) -> Result<Option<Vec<u8>>> {
        Ok(self
            .load()?
            .state
            .inbox
            .iter()
            .find(|item| item.wire_hash == wire_hash)
            .map(|item| item.body.clone()))
    }

    fn receive(&mut self, encoded: &[u8], fault: Fault) -> Result<Vec<u8>> {
        bounded_wire(encoded)?;
        let wire_hash = Sha256::digest(encoded).into();
        if let Some(body) = self.inbox(wire_hash)? {
            return Ok(body);
        }
        let mut work = self.load()?;
        let mut group = work.group()?;
        let message = MlsMessageIn::tls_deserialize_exact(encoded)
            .map_err(|_| Error::Codec)?
            .try_into_protocol_message()
            .map_err(|_| Error::Codec)?;
        if message.group_id().as_slice() != self.room {
            return Err(Error::Scope);
        }
        let processed = group
            .process_message(&work.provider, message)
            .map_err(|_| Error::Mls)?;
        if processed.aad() != aad(&self.room) {
            return Err(Error::Scope);
        }
        let (kind, body) = match processed.into_content() {
            ProcessedMessageContent::ApplicationMessage(message) => {
                (Kind::Application, message.into_bytes())
            }
            ProcessedMessageContent::StagedCommitMessage(commit) => {
                // Intentionally only a synthetic owner-removes-member exercise.
                // This is not production owner/invitation authorization.
                group
                    .merge_staged_commit(&work.provider, *commit)
                    .map_err(|_| Error::Mls)?;
                (Kind::Commit, Vec::new())
            }
            // In particular OwnPrivateMessage is NOT authenticated application content.
            _ => return Err(Error::Mls),
        };
        if body.len() > MAX_BODY {
            return Err(Error::Bounds);
        }
        work.state.inbox.push(Received {
            wire_hash,
            kind,
            body,
        });
        self.commit(self.prepare(work)?, fault)?;
        self.inbox(wire_hash)?.ok_or(Error::Missing)
    }

    fn remove(&mut self, operation: [u8; 16], target: &[u8]) -> Result<Vec<Wire>> {
        let request = digest(Kind::Commit, target);
        if let Some(retained) = self.retained(operation, request)? {
            return Ok(retained);
        }
        let mut work = self.load()?;
        let mut group = work.group()?;
        let member = group
            .members()
            .find(|member| member.signature_key == target)
            .ok_or(Error::Missing)?;
        group.set_aad(aad(&self.room));
        let (commit, _, _) = group
            .remove_members(&work.provider, &work.signer()?, &[member.index])
            .map_err(|_| Error::Mls)?;
        group
            .merge_pending_commit(&work.provider)
            .map_err(|_| Error::Mls)?;
        work.state.outbox.push(Sent {
            operation,
            request,
            outputs: vec![wire(Kind::Commit, &commit)?],
        });
        self.commit(self.prepare(work)?, Fault::None)?;
        self.retained(operation, request)?.ok_or(Error::Missing)
    }
}

fn random<const N: usize>() -> Result<[u8; N]> {
    let mut bytes = [0u8; N];
    getrandom::getrandom(&mut bytes).map_err(|_| Error::Entropy)?;
    Ok(bytes)
}

fn aad(room: &[u8; 32]) -> Vec<u8> {
    [DOMAIN, room].concat()
}

fn digest(kind: Kind, bytes: &[u8]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(DOMAIN);
    digest.update([kind as u8]);
    digest.update(bytes);
    digest.finalize().into()
}

fn bounded_wire(bytes: &[u8]) -> Result<()> {
    if bytes.is_empty() || bytes.len() > MAX_WIRE {
        Err(Error::Bounds)
    } else {
        Ok(())
    }
}

fn decode_welcome(bytes: &[u8]) -> Result<Welcome> {
    bounded_wire(bytes)?;
    match MlsMessageIn::tls_deserialize_exact(bytes)
        .map_err(|_| Error::Codec)?
        .extract()
    {
        MlsMessageBodyIn::Welcome(welcome) => Ok(welcome),
        _ => Err(Error::Codec),
    }
}

fn wire(kind: Kind, value: &impl tls_codec::Serialize) -> Result<Wire> {
    let bytes = value.tls_serialize_detached().map_err(|_| Error::Codec)?;
    bounded_wire(&bytes)?;
    Ok(Wire { kind, bytes })
}

fn seal(key: &[u8; 32], room: &[u8; 32], revision: u64, state: &State) -> Result<Image> {
    state.validate(room)?;
    let mut clear = Zeroizing::new(Vec::new());
    serde_json::to_writer(BoundedWriter(&mut clear), state).map_err(|_| Error::Bounds)?;
    let nonce = random()?;
    let mut authenticated = aad(room);
    authenticated.extend_from_slice(&revision.to_be_bytes());
    let ciphertext = XChaCha20Poly1305::new(key.into())
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: &clear,
                aad: &authenticated,
            },
        )
        .map_err(|_| Error::Authentication)?;
    Ok(Image {
        revision,
        nonce,
        ciphertext,
    })
}

struct BoundedWriter<'a>(&'a mut Vec<u8>);

impl std::io::Write for BoundedWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if self
            .0
            .len()
            .checked_add(bytes.len())
            .is_none_or(|size| size > MAX_IMAGE)
        {
            return Err(std::io::Error::other("qualification image exceeds bound"));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn unseal(key: &[u8; 32], room: &[u8; 32], image: &Image) -> Result<State> {
    if image.ciphertext.len() < 16 || image.ciphertext.len() > MAX_IMAGE + 16 {
        return Err(Error::Bounds);
    }
    let mut authenticated = aad(room);
    authenticated.extend_from_slice(&image.revision.to_be_bytes());
    let clear = Zeroizing::new(
        XChaCha20Poly1305::new(key.into())
            .decrypt(
                XNonce::from_slice(&image.nonce),
                Payload {
                    msg: &image.ciphertext,
                    aad: &authenticated,
                },
            )
            .map_err(|_| Error::Authentication)?,
    );
    let state: State = serde_json::from_slice(&clear).map_err(|_| Error::Codec)?;
    state.validate(room)?;
    Ok(state)
}

fn two_members() -> Result<(Device, Device, Vec<u8>)> {
    let room = random()?;
    let mut alice = Device::fresh(room, b"synthetic-alice")?;
    let mut bob = Device::fresh(room, b"synthetic-bob")?;
    alice.create_group()?;
    let package = bob.key_package([1; 16], Fault::None)?;
    let added = alice.add([2; 16], &package[0].bytes)?;
    let welcome = added
        .iter()
        .find(|wire| wire.kind == Kind::Welcome)
        .ok_or(Error::Missing)?
        .bytes
        .clone();
    bob.join(&welcome, Fault::None)?;
    Ok((alice, bob, welcome))
}

pub(super) fn roundtrip() -> Result<()> {
    let (mut alice, mut bob, _) = two_members()?;
    let message = b"synthetic private room message";
    let sent = alice.send([3; 16], message, Fault::None)?;
    if bob.receive(&sent[0].bytes, Fault::None)? != message {
        return Err(Error::Mls);
    }
    alice.reopen()?;
    let retry = alice.send([3; 16], message, Fault::None)?;
    if retry[0].bytes != sent[0].bytes {
        return Err(Error::Conflict);
    }
    let target = bob.load()?.state.signer_public;
    let removal = alice.remove([4; 16], &target)?;
    bob.receive(&removal[0].bytes, Fault::None)?;
    let later = alice.send([5; 16], b"after removal", Fault::None)?;
    if bob.receive(&later[0].bytes, Fault::None).is_ok() {
        return Err(Error::Mls);
    }
    Ok(())
}

#[cfg(test)]
mod tests;
