//! Deliberately ephemeral U0 adapter. Production persistence belongs to U1.
use crate::fixture;
use std::{cell::RefCell, future::Future, pin::Pin};
use vhalla_attention::{Attention, ReaderScope};
use vhalla_dioxus_services_spike::{Engine, Error, Intent, Projection, Screen};
use vhalla_discovery::{Change, DiscoveryState, Subscription};
use vhalla_social::view::{Eligibility, View};

/// Bounded presentation actions only: no arbitrary signing, paths, URLs or commands.
pub trait UiServices {
    fn project(&self, screen: Screen) -> Result<Projection, Error>;
    fn apply(&self, intent: Intent) -> Result<Projection, Error>;
    fn can_qualify_browser(&self) -> bool {
        false
    }
    fn qualify_browser(&self) -> Pin<Box<dyn Future<Output = Result<String, Error>>>> {
        Box::pin(async { Err(Error::Storage) })
    }
}

/// Static signed demonstration corpus and one private in-memory reader namespace.
pub struct FixtureServices(RefCell<Engine>);
impl FixtureServices {
    pub fn new(reader_index: usize) -> Result<Self, Error> {
        let fixture = fixture::signed();
        let agent = *fixture.readers.get(reader_index).ok_or(Error::Bounds)?;
        let scope = ReaderScope::new(
            &fixture.archive,
            fixture::NOW,
            fixture.owner,
            Some(agent),
            [0; 32],
            [0; 32],
        )?;
        let mut discovery = DiscoveryState::new(scope.digest());
        discovery.apply(Change::Subscribe(
            Subscription::Channel(fixture::ROOM),
            true,
        ))?;
        discovery.observe(&View::new(
            &fixture.archive,
            fixture::NOW,
            &Eligibility::default(),
        ))?;
        Ok(Self(RefCell::new(Engine::new(
            fixture.archive,
            scope,
            Attention::new(scope),
            discovery,
        )?)))
    }
}
impl UiServices for FixtureServices {
    fn project(&self, screen: Screen) -> Result<Projection, Error> {
        self.0
            .try_borrow_mut()
            .map_err(|_| Error::Storage)?
            .project(screen, fixture::NOW)
    }
    fn apply(&self, intent: Intent) -> Result<Projection, Error> {
        self.0
            .try_borrow_mut()
            .map_err(|_| Error::Storage)?
            .apply_ephemeral(intent, fixture::NOW)
    }
    fn can_qualify_browser(&self) -> bool {
        cfg!(target_arch = "wasm32")
    }
    fn qualify_browser(&self) -> Pin<Box<dyn Future<Output = Result<String, Error>>>> {
        #[cfg(target_arch = "wasm32")]
        {
            Box::pin(qualify_browser_fixture())
        }
        #[cfg(not(target_arch = "wasm32"))]
        {
            Box::pin(async { Err(Error::Storage) })
        }
    }
}

#[cfg(target_arch = "wasm32")]
async fn qualify_browser_fixture() -> Result<String, Error> {
    let fixture = fixture::signed();
    let mut namespace = [0; 32];
    getrandom::fill(&mut namespace).map_err(|_| Error::Storage)?;
    let scope = ReaderScope::new(
        &fixture.archive,
        fixture::NOW,
        fixture.owner,
        Some(fixture.readers[0]),
        namespace,
        [0; 32],
    )?;
    let engine = Engine::new(
        fixture.archive,
        scope,
        Attention::new(scope),
        DiscoveryState::new(scope.digest()),
    )?;
    vhalla_dioxus_services_spike::browser::qualify(engine.image(), fixture::NOW).await
}
