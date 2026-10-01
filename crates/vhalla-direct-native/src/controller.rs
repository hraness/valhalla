use crate::{codec::*, *};
use std::{fs, path::Path};
use vhalla_custody as custody;
use vhalla_direct_room::{
    EventClaims, GenesisClaims, PolicyClaims, SignedGenesis, Text, UnsignedEvent, UnsignedGenesis,
    UnsignedPolicy,
};
use vhalla_direct_store::{Context, Record};

impl RoomSession {
    /// Create a new pinned room and fresh room author in an absent private home.
    /// Partial creation is retained on error and is never silently reused.
    pub fn create(account: Arc<Identity>, path: impl AsRef<Path>, limits: Limits) -> Result<Self> {
        let mut creation_nonce = [0; 32];
        getrandom::fill(&mut creation_nonce).map_err(|_| Error::Entropy)?;
        Self::create_bound(account, path, creation_nonce, limits)
    }

    /// Create a room whose signed genesis binds a retained creation intent.
    /// The caller must generate and retain a fresh random nonzero nonce before
    /// the first attempt. An existing or partial home is never silently reused.
    /// A zero nonce is refused before any filesystem mutation.
    pub fn create_bound(
        account: Arc<Identity>,
        path: impl AsRef<Path>,
        creation_nonce: [u8; 32],
        limits: Limits,
    ) -> Result<Self> {
        if creation_nonce == [0; 32] {
            return Err(Error::Bounds);
        }
        Self::check_limits(limits)?;
        let (home, directory, lock) = Self::create_home(path.as_ref())?;
        let author = Identity::create_new(home.join("author")).map_err(|_| Error::Custody)?;
        let mut writers = vec![account.public_key(), author.public_key()];
        writers.sort_unstable();
        let unsigned = UnsignedGenesis::new(GenesisClaims {
            owner: account.public_key(),
            nonce: creation_nonce,
            writers,
        })?;
        let signed = account.sign_direct_genesis(unsigned)?;
        let genesis = signed.clone().verify_pin(signed.id())?;
        Self::initialize(
            account,
            author,
            home,
            directory,
            lock,
            genesis,
            true,
            creation_nonce,
            limits,
        )
    }

    /// Pin an existing genesis and generate a new room author. This grants neither
    /// posting rights nor owner capability, including for the owner's account key.
    pub fn join(
        account: Arc<Identity>,
        path: impl AsRef<Path>,
        signed_genesis: &[u8],
        expected_pin: RoomId,
        limits: Limits,
    ) -> Result<Self> {
        let mut creation_nonce = [0; 32];
        getrandom::fill(&mut creation_nonce).map_err(|_| Error::Entropy)?;
        Self::join_bound(
            account,
            path,
            signed_genesis,
            expected_pin,
            creation_nonce,
            limits,
        )
    }

    /// Join under a retained local creation intent, generating a fresh author.
    /// The random nonzero nonce is retained only in local controller state; it
    /// never changes the pinned genesis or grants owner rights. Existing homes
    /// are refused, and a zero nonce is rejected before filesystem mutation.
    pub fn join_bound(
        account: Arc<Identity>,
        path: impl AsRef<Path>,
        signed_genesis: &[u8],
        expected_pin: RoomId,
        creation_nonce: [u8; 32],
        limits: Limits,
    ) -> Result<Self> {
        if creation_nonce == [0; 32] {
            return Err(Error::Bounds);
        }
        Self::check_limits(limits)?;
        let genesis = SignedGenesis::decode(signed_genesis)?.verify_pin(expected_pin)?;
        let (home, directory, lock) = Self::create_home(path.as_ref())?;
        let author = Identity::create_new(home.join("author")).map_err(|_| Error::Custody)?;
        Self::initialize(
            account,
            author,
            home,
            directory,
            lock,
            genesis,
            false,
            creation_nonce,
            limits,
        )
    }

    /// Open intact local custody under the exact independent room pin. This never
    /// generates a key, imports an archive or initializes missing signing state.
    pub fn open(
        account: Arc<Identity>,
        path: impl AsRef<Path>,
        expected_pin: RoomId,
    ) -> Result<Self> {
        let home = custody::absolute(path.as_ref()).map_err(|_| Error::Custody)?;
        let (directory, owner) =
            custody::open_private_directory(&home).map_err(|_| Error::Custody)?;
        if owner != custody::Owner::current().map_err(|_| Error::Custody)? {
            return Err(Error::Custody);
        }
        let lock =
            custody::open_private_file(&home.join("lock"), owner, 0).map_err(|_| Error::Custody)?;
        custody::acquire_exclusive(&lock).map_err(|_| Error::Custody)?;
        Self::check_home_entries(&home)?;
        let author = Identity::open(home.join("author")).map_err(|_| Error::Custody)?;
        let context = Context::new(*expected_pin.as_bytes(), account.public_key())?;
        let mut store = Store::open(home.join("store"), context)?;
        let config = Config::decode(&store.read(config_key())?.ok_or(Error::Corrupt)?)?;
        if config.account != account.public_key() || config.author != author.public_key() {
            return Err(Error::Corrupt);
        }
        let raw = store
            .read(raw_key(GENESIS, *expected_pin.as_bytes()))?
            .ok_or(Error::Corrupt)?;
        let genesis = SignedGenesis::decode(&raw)?.verify_pin(expected_pin)?;
        if config.created
            && (genesis.claims().owner != account.public_key()
                || genesis.claims().nonce != config.creation_nonce)
        {
            return Err(Error::Corrupt);
        }
        let image_bytes = store.load()?.ok_or(Error::Corrupt)?;
        let image = Image::decode(&image_bytes)?;
        let mut session = Self {
            account,
            author,
            store,
            home,
            directory,
            lock,
            policy: PolicyState::new(genesis.clone()),
            genesis,
            created_here: config.created,
            creation_nonce: config.creation_nonce,
            image,
            image_bytes,
            poisoned: false,
            author_cache: BTreeMap::new(),
            policy_replay: None,
            author_rotation: 0,
            #[cfg(test)]
            full_replays: 0,
            #[cfg(test)]
            frame_reads: 0,
        };
        session.reload_model()?;
        Ok(session)
    }

    #[allow(clippy::too_many_arguments)]
    fn initialize(
        account: Arc<Identity>,
        author: Identity,
        home: PathBuf,
        directory: File,
        lock: File,
        genesis: PinnedGenesis,
        created_here: bool,
        creation_nonce: [u8; 32],
        limits: Limits,
    ) -> Result<Self> {
        let context = Context::new(*genesis.id().as_bytes(), account.public_key())?;
        let mut store = Store::create_new(home.join("store"), context, limits)?;
        let config = Config {
            account: account.public_key(),
            author: author.public_key(),
            created: created_here,
            creation_nonce,
        };
        let image = Image::default();
        let image_bytes = image.encode();
        store.publish(
            None,
            &image_bytes,
            &[
                record(config_key(), &config.encode())?,
                record(
                    raw_key(GENESIS, *genesis.id().as_bytes()),
                    &genesis.encode(),
                )?,
                record(
                    raw_key(POLICY_INDEX, *genesis.id().initial_policy().as_bytes()),
                    &0u64.to_be_bytes(),
                )?,
            ],
        )?;
        directory.sync_all().map_err(|_| Error::Uncertain)?;
        custody::sync_directory(home.parent().ok_or(Error::Custody)?)
            .map_err(|_| Error::Uncertain)?;
        let mut session = Self {
            account,
            author,
            store,
            home,
            directory,
            lock,
            policy: PolicyState::new(genesis.clone()),
            genesis,
            created_here,
            creation_nonce,
            image,
            image_bytes,
            poisoned: false,
            author_cache: BTreeMap::new(),
            policy_replay: None,
            author_rotation: 0,
            #[cfg(test)]
            full_replays: 0,
            #[cfg(test)]
            frame_reads: 0,
        };
        session.sync_author_cache(false)?;
        let mut budget = MAX_REPLAY_FRAMES;
        session.advance_authors(&mut budget)?;
        Ok(session)
    }
    fn check_limits(limits: Limits) -> Result<()> {
        if limits.max_records <= CONTROL_RESERVED_RECORDS + 8
            || limits.max_record_bytes <= CONTROL_RESERVED_BYTES + 32 * 1024
        {
            return Err(Error::Bounds);
        }
        Ok(())
    }
    fn create_home(path: &Path) -> Result<(PathBuf, File, File)> {
        let home = custody::absolute(path).map_err(|_| Error::Custody)?;
        let (directory, owner) =
            custody::create_private_directory(&home).map_err(|_| Error::Custody)?;
        if owner != custody::Owner::current().map_err(|_| Error::Custody)? {
            return Err(Error::Custody);
        }
        let lock = custody::create_private_file(&home.join("lock")).map_err(|_| Error::Custody)?;
        custody::acquire_exclusive(&lock).map_err(|_| Error::Custody)?;
        lock.sync_all().map_err(|_| Error::Uncertain)?;
        directory.sync_all().map_err(|_| Error::Uncertain)?;
        Ok((home, directory, lock))
    }
    fn check_home_entries(home: &Path) -> Result<()> {
        let mut count = 0;
        for entry in fs::read_dir(home).map_err(|_| Error::Custody)? {
            let entry = entry.map_err(|_| Error::Custody)?;
            if !["lock", "author", "store"]
                .iter()
                .any(|name| entry.file_name() == *name)
            {
                return Err(Error::Corrupt);
            }
            count += 1;
        }
        if count != 3 {
            return Err(Error::Corrupt);
        }
        Ok(())
    }
    pub(crate) fn ready(&self) -> Result<()> {
        if self.poisoned {
            return Err(Error::Uncertain);
        }
        if !custody::same_file(&self.home, &self.directory).map_err(|_| Error::Custody)?
            || !custody::same_file(&self.home.join("lock"), &self.lock)
                .map_err(|_| Error::Custody)?
        {
            return Err(Error::Custody);
        }
        Ok(())
    }
    pub(crate) fn writable(&self, owner: bool) -> Result<()> {
        self.ready()?;
        if self.image.blocked.is_some() {
            return Err(Error::Capacity);
        }
        if (!owner && self.image.author_lost) || (owner && self.image.owner_lost) {
            return Err(Error::ReadOnly);
        }
        if self.policy.is_forked() {
            return Err(vhalla_direct_room::Error::Fork.into());
        }
        if self.policy.observation_overflow() {
            return Err(Error::Capacity);
        }
        Ok(())
    }
    /// Full independently pinned room identity.
    pub fn room_id(&self) -> RoomId {
        self.genesis.id()
    }
    /// Fresh per-room author key; this is the key the owner must admit.
    pub fn author_key(&self) -> [u8; 32] {
        self.author.public_key()
    }
    /// Immutable local creation intent, independent of the public room pin.
    /// Hosts compare this with their retained reservation before opening a slot.
    /// It is neither a signing key nor proof against coherent whole-home rollback.
    pub const fn creation_nonce(&self) -> [u8; 32] {
        self.creation_nonce
    }
    /// Pinned signed public genesis, safe to share without local controller data.
    pub fn genesis(&self) -> &PinnedGenesis {
        &self.genesis
    }

    /// Reserve exact bytes before signing and retain a local public message.
    /// Repeating the operation preserves its original timestamp and policy.
    pub fn send(
        &mut self,
        operation: [u8; 16],
        text: &str,
        created_at: u64,
    ) -> Result<OperationOutcome> {
        self.ready()?;
        Self::operation_nonzero(operation)?;
        let text = Text::new(text)?;
        if let Some(reserved) = self.reservation(operation)? {
            if reserved.kind != EVENT
                || UnsignedEvent::decode(&reserved.unsigned)?.claims().text != text
            {
                return Err(Error::OperationConflict);
            }
            return self.finish_operation(reserved, true);
        }
        self.writable(false)?;
        if self.image.pending_event.is_some() {
            return Err(Error::OperationPending);
        }
        let chain = self.author_chain(self.author_key(), &self.policy.clone())?;
        let head = chain.authoring_head(&self.policy)?;
        let unsigned = UnsignedEvent::new(EventClaims {
            room: self.room_id(),
            policy: self.policy.head().id,
            author: self.author_key(),
            sequence: head.sequence.checked_add(1).ok_or(Error::Bounds)?,
            previous: head.event,
            created_at,
            text,
        })?;
        // Reserve room for the complete operation, not just its intent. The five
        // new records are intent, signed frame, author index, completion and local
        // operation binding. No signature is produced for a predictable refusal.
        let complete_bytes = 2 * unsigned.encode().len() as u64 + 218;
        if !self.has_capacity(5, complete_bytes, false)? {
            return Err(Error::Capacity);
        }
        let reserved = Reservation {
            operation,
            kind: EVENT,
            unsigned: unsigned.encode(),
        };
        let mut image = self.image.clone();
        image.pending_event = Some(operation);
        self.publish(
            image,
            &[record(
                operation_key(RESERVATION, operation),
                &reserved.encode(),
            )?],
            false,
        )?;
        self.finish_operation(reserved, false)
    }

    /// Replace the complete writer list, closing the current policy using the
    /// contiguous current-policy author heads retained locally. Include the owner.
    pub fn set_writers(
        &mut self,
        operation: [u8; 16],
        mut writers: Vec<[u8; 32]>,
    ) -> Result<OperationOutcome> {
        self.ready()?;
        Self::operation_nonzero(operation)?;
        writers.sort_unstable();
        if !self.created_here {
            return Err(Error::NotOwner);
        }
        if let Some(reserved) = self.reservation(operation)? {
            if reserved.kind != POLICY
                || UnsignedPolicy::decode(&reserved.unsigned)?.claims().writers != writers
            {
                return Err(Error::OperationConflict);
            }
            return self.finish_operation(reserved, true);
        }
        self.writable(true)?;
        if self.image.pending_policy.is_some() {
            return Err(Error::OperationPending);
        }
        if self.policy.pending().is_some() {
            return Err(vhalla_direct_room::Error::PolicyPending.into());
        }
        let sealed_heads = self.current_seals()?;
        let unsigned = UnsignedPolicy::new(PolicyClaims {
            room: self.room_id(),
            owner: self.account.public_key(),
            revision: self
                .policy
                .head()
                .revision
                .checked_add(1)
                .ok_or(Error::Bounds)?,
            previous: self.policy.head().id,
            writers,
            sealed_heads,
        })?;
        // Intent, signed frame, observed index, completion, local binding and the
        // two committed-policy indices must all fit before owner signing begins.
        if !self.has_capacity(7, 2 * unsigned.encode().len() as u64 + 234, true)? {
            return Err(Error::Capacity);
        }
        let reserved = Reservation {
            operation,
            kind: POLICY,
            unsigned: unsigned.encode(),
        };
        let mut image = self.image.clone();
        image.pending_policy = Some(operation);
        self.publish(
            image,
            &[record(
                operation_key(RESERVATION, operation),
                &reserved.encode(),
            )?],
            true,
        )?;
        self.finish_operation(reserved, false)
    }
    fn operation_nonzero(operation: [u8; 16]) -> Result<()> {
        if operation == [0; 16] {
            Err(Error::Bounds)
        } else {
            Ok(())
        }
    }

    pub(crate) fn has_capacity(&mut self, records: u64, bytes: u64, control: bool) -> Result<bool> {
        let accounting = self.store.accounting()?;
        let reserve_records = if control { 0 } else { CONTROL_RESERVED_RECORDS };
        let reserve_bytes = if control { 0 } else { CONTROL_RESERVED_BYTES };
        Ok(accounting
            .records
            .saturating_add(records)
            .saturating_add(reserve_records)
            <= accounting.limits.max_records
            && accounting
                .bytes
                .saturating_add(bytes)
                .saturating_add(reserve_bytes)
                <= accounting.limits.max_record_bytes)
    }

    pub(crate) fn publish(&mut self, next: Image, records: &[Record], control: bool) -> Result<()> {
        self.ready()?;
        let accounting = self.store.accounting()?;
        let mut count = 0u64;
        let mut bytes = 0u64;
        for item in records {
            match self.store.read(item.key())? {
                Some(old) if old == item.as_bytes() => {}
                Some(_) => return Err(Error::Corrupt),
                None => {
                    count += 1;
                    bytes += item.as_bytes().len() as u64;
                }
            }
        }
        let reserve_records = if control { 0 } else { CONTROL_RESERVED_RECORDS };
        let reserve_bytes = if control { 0 } else { CONTROL_RESERVED_BYTES };
        if accounting
            .records
            .saturating_add(count)
            .saturating_add(reserve_records)
            > accounting.limits.max_records
            || accounting
                .bytes
                .saturating_add(bytes)
                .saturating_add(reserve_bytes)
                > accounting.limits.max_record_bytes
        {
            return Err(Error::Capacity);
        }
        let encoded = next.encode();
        match self
            .store
            .publish(Some(&self.image_bytes), &encoded, records)
        {
            Ok(()) => {
                self.image = next;
                self.image_bytes = encoded;
                Ok(())
            }
            Err(error) => {
                if matches!(
                    error,
                    vhalla_direct_store::Error::Uncertain | vhalla_direct_store::Error::Corrupt
                ) {
                    self.poisoned = true;
                }
                Err(error.into())
            }
        }
    }
    pub(crate) fn capacity_fence<T>(&mut self, blocked: Record) -> Result<T> {
        if self.image.blocked.is_none() {
            let mut next = self.image.clone();
            next.blocked = Some(blocked.clone());
            self.publish(next, &[], true)?;
            if blocked.key()[0] == POLICY {
                self.observe_cached(self.policy_raw(blocked.as_bytes())?)?;
            }
        }
        Err(Error::Capacity)
    }
}
