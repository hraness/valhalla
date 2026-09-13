//! Native launcher adapter. Components receive only the Service trait object.
use super::*;
use vhalla_discovery_store::{PrivateState, Store as PrivateStore};
use vhalla_social_store::Store as SocialStore;

pub struct NativeService<C> {
    source: SocialStore,
    private: PrivateStore,
    engine: Engine,
    clock: C,
    ready: bool,
}
impl<C: Clock> NativeService<C> {
    /// Host supplies already opened, locked, configured stores. No path is accepted.
    pub fn new(source: SocialStore, private: PrivateStore, clock: C) -> Result<Self, Error> {
        if source.recovery_required().map_err(|_| Error::Storage)?
            || private.recovery_required().map_err(|_| Error::Storage)?
        {
            return Err(Error::Storage);
        }
        let state = private.state();
        let image = Image {
            scope: state.scope(),
            archive: source.archive().clone(),
            attention: state.attention().clone(),
            discovery: state.discovery().clone(),
        };
        let engine = Engine::from_image(image, Persistence::Native)?;
        Ok(Self {
            source,
            private,
            engine,
            clock,
            ready: true,
        })
    }
}
impl<C: Clock> Service for NativeService<C> {
    fn project(&mut self, screen: Screen) -> Result<Projection, Error> {
        if !self.ready {
            return Err(Error::Storage);
        }
        self.engine.project(screen, self.clock.now()?)
    }
    fn submit(
        &mut self,
        intent: Intent,
    ) -> Pin<Box<dyn Future<Output = Result<Projection, Error>> + '_>> {
        Box::pin(async move {
            if !self.ready {
                return Err(Error::Storage);
            }
            let now = self.clock.now()?;
            let pending = self.engine.prepare(intent, now)?;
            let candidate = PrivateState::new(pending.image.scope)
                .with_attention(pending.image.attention.clone())
                .map_err(|_| Error::Storage)?
                .with_discovery(pending.image.discovery.clone())
                .map_err(|_| Error::Storage)?;
            self.ready = false;
            self.private
                .commit(candidate, self.private.pin(), &self.source)
                .map_err(|_| Error::Storage)?;
            let result = self.engine.confirm(pending, Persistence::Native, now);
            self.ready = result.is_ok();
            result
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        os::unix::fs::DirBuilderExt,
        task::{Context, Poll, Waker},
    };
    use vhalla_social::archive::Limits;
    struct Fixed;
    impl Clock for Fixed {
        fn now(&self) -> Result<u64, Error> {
            Ok(10)
        }
    }
    #[test]
    fn native_adapter_restarts_exact_private_ack_without_changing_public_export() {
        let fixture = crate::tests::fixture(1);
        let image = fixture.image();
        let mut random = [0; 16];
        getrandom::fill(&mut random).unwrap();
        let path = std::env::temp_dir().join(format!(
            "vhalla-u1-native-{:032x}",
            u128::from_be_bytes(random)
        ));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        let source_path = path.join("source");
        let private_path = path.join("private");
        let mut source =
            SocialStore::create(&source_path, image.scope.realm(), Limits::default()).unwrap();
        source.commit(image.archive.clone(), source.pin()).unwrap();
        let public = source.archive().snapshot();
        let private = PrivateStore::create(&private_path, image.scope, &source).unwrap();
        let mut service = NativeService::new(source, private, Fixed).unwrap();
        let page = service.project(Screen::Inbox).unwrap();
        let id = page.notifications[0].id;
        let mut future = service.submit(Intent::acknowledge(page.receipt, vec![id]).unwrap());
        let mut context = Context::from_waker(Waker::noop());
        let result = match future.as_mut().poll(&mut context) {
            Poll::Ready(result) => result.unwrap(),
            Poll::Pending => panic!("native fixture does not await external work"),
        };
        assert_eq!(result.persistence, Persistence::Native);
        drop(future);
        drop(service);
        let source =
            SocialStore::open(&source_path, image.scope.realm(), Limits::default(), None).unwrap();
        assert_eq!(source.archive().snapshot(), public);
        let private = PrivateStore::open(&private_path, image.scope, None).unwrap();
        let mut service = NativeService::new(source, private, Fixed).unwrap();
        let page = service.project(Screen::Inbox).unwrap();
        assert_eq!(
            page.notifications
                .iter()
                .filter(|n| n.id == id && n.read == ReadState::Read)
                .count(),
            1
        );
        drop(service);
        fs::remove_dir_all(path).unwrap();
    }
}
