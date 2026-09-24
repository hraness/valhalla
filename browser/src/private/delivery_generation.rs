//! Explicit same-origin generation selection; no relay-selected route or reset.
use super::*;
use crate::private_wire::{Bytes, GenerationConsent, GenerationReport};
use model::{generation::Receipt, Successor};
use vhalla_browser_storage::private_rooms::DeliveryGeneration;
use vhalla_private_kernel::protocol::Validity;

pub(in super::super) struct ReviewedSuccessor {
    pub consent: GenerationConsent,
    profile: Bytes,
    next: Successor,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Fence {
    version: u8,
    transition: String,
    predecessor: String,
    successor: String,
    head: String,
    items_commitment: String,
    fence_commitment: String,
    predecessor_address: String,
    successor_address: String,
    tls_name: String,
    ca_sha256: String,
    receipt_commitments: Vec<String>,
}
fn endpoint(origin: &str) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"vhalla/browser-private-delivery-origin/v1\0");
    hash.update(origin.as_bytes());
    hash.finalize().into()
}
impl Delivery {
    fn generation_report(&self, context: Context) -> Result<GenerationReport> {
        let line = &self.engine.state().lineage;
        Ok(GenerationReport {
            context,
            generation: line.generation,
            attempts: self.engine.state().attempts,
            wire_bytes: self.engine.state().wire_bytes,
            attempt_ceiling: line.attempt_ceiling,
            byte_ceiling: line.byte_ceiling,
            scanned: line.audit.as_ref().map_or_else(
                || line.pause.as_ref().map_or(0, |p| p.head),
                |a| a.digests.len() as u64,
            ),
            head: line
                .audit
                .as_ref()
                .map_or_else(|| line.pause.as_ref().map_or(0, |p| p.head), |a| a.head),
            receipt: Zeroizing::new(
                line.pause
                    .as_ref()
                    .map(|p| p.encode())
                    .transpose()
                    .map_err(|_| Failure::Storage)?
                    .unwrap_or_default(),
            ),
        })
    }
    pub(in super::super) async fn drain(
        &mut self,
        session: &mut Session,
        context: Context,
        transition: [u8; 32],
        head: u64,
        restart: bool,
    ) -> Result<GenerationReport> {
        if let Some(pause) = &self.engine.state().lineage.pause {
            if pause.transition != transition || pause.head != head || restart {
                return Err(Failure::State);
            }
            if self
                .store
                .pause_receipt()
                .await
                .map_err(|_| Failure::Storage)?
                .as_deref()
                != Some(pause.encode().map_err(|_| Failure::Storage)?.as_slice())
            {
                return Err(Failure::Storage);
            }
            return self.generation_report(context);
        }
        let origin = endpoint(&self.origin);
        let plan = {
            let (engine, mut host) = self.host(session);
            if !engine
                .drain_step(&mut host, transition, head, restart)
                .await?
            {
                return self.generation_report(context);
            }
            engine.pause_plan(&mut host, origin).await?
        };
        let selected = DeliveryGeneration {
            generation: plan.receipt.generation,
            binding: plan.receipt.binding,
            namespace: plan.receipt.namespace,
            paused: true,
            transition: plan.receipt.transition,
        };
        self.store
            .pause(
                &plan.expected,
                &plan.next,
                &plan.image,
                selected,
                &plan.receipt.encode().map_err(|_| Failure::Storage)?,
            )
            .await
            .map_err(|_| Failure::Storage)?;
        session.kernel_generation = Some(selected);
        self.engine = Engine::selected(plan.next, self.namespace)?;
        self.generation_report(context)
    }
    pub(in super::super) async fn review_successor(
        &mut self,
        session: &mut Session,
        profile: Bytes,
        fence: Bytes,
        attempt_ceiling: u64,
    ) -> Result<ReviewedSuccessor> {
        if profile.len() > 4096 || fence.len() > 16384 {
            return Err(Failure::Invalid);
        }
        let pause = self
            .engine
            .state()
            .lineage
            .pause
            .as_ref()
            .ok_or(Failure::State)?
            .clone();
        if self
            .store
            .load()
            .await
            .map_err(|_| Failure::Storage)?
            .as_deref()
            != Some(self.engine.raw())
            || self
                .store
                .pause_receipt()
                .await
                .map_err(|_| Failure::Storage)?
                .as_deref()
                != Some(pause.encode().map_err(|_| Failure::Storage)?.as_slice())
        {
            return Err(Failure::Storage);
        }
        let mut p: Profile = serde_json::from_slice(&profile).map_err(|_| Failure::Invalid)?;
        let capability = Zeroizing::new(std::mem::take(&mut p.capability));
        // Both transports remain on the exact browser origin retaining custody.
        if p.format != 1
            || p.origin != self.origin
            || p.initial_cursor != "0"
            || transport::origin().map_err(|_| Failure::Invalid)? != self.origin
        {
            return Err(Failure::Invalid);
        }
        hex(&capability)?;
        let namespace =
            RelayNamespace::from_bytes(hex(&p.namespace)?).map_err(|_| Failure::Invalid)?;
        let f: Fence = serde_json::from_slice(&fence).map_err(|_| Failure::Invalid)?;
        let head = f.head.parse::<u64>().map_err(|_| Failure::Invalid)?;
        if f.version != 1
            || head.to_string() != f.head
            || head != pause.head
            || hex(&f.transition)? != pause.transition
            || hex(&f.predecessor)? != pause.namespace
            || hex(&f.successor)? != *namespace.as_bytes()
            || namespace == self.namespace
            || hex(&f.items_commitment)? != pause.items
            || f.receipt_commitments.is_empty()
            || f.receipt_commitments.len() > 32
            || f.receipt_commitments.windows(2).any(|p| p[0] >= p[1])
            || f.predecessor_address.len() > 128
            || f.successor_address.len() > 128
            || f.tls_name.is_empty()
            || f.tls_name.len() > 253
            || f.predecessor_address
                .parse::<std::net::SocketAddr>()
                .is_err()
            || f.successor_address.parse::<std::net::SocketAddr>().is_err()
            || !(pause.accounting.attempt_ceiling..=model::generation::MAX_ATTEMPTS)
                .contains(&attempt_ceiling)
            || pause.generation + 1 >= model::generation::MAX_GENERATIONS
        {
            return Err(Failure::Invalid);
        }
        hex(&f.ca_sha256)?;
        let own = pause.commitment().map_err(|_| Failure::Storage)?;
        let listed: Vec<[u8; 32]> = f
            .receipt_commitments
            .iter()
            .map(|value| hex(value))
            .collect::<Result<_>>()?;
        if !listed.contains(&own) {
            return Err(Failure::Invalid);
        }
        let mut hash = Sha256::new();
        hash.update(b"vhalla/private/relay-generation-fence/v1\0");
        hash.update(pause.transition);
        hash.update(pause.namespace);
        hash.update(namespace.as_bytes());
        hash.update(head.to_be_bytes());
        hash.update(pause.items);
        let fence: [u8; 32] = hash.finalize().into();
        if fence != hex(&f.fence_commitment)? {
            return Err(Failure::Invalid);
        }
        let next = Successor {
            namespace: *namespace.as_bytes(),
            binding: binding(pause.context, &p, namespace, 0),
            fence,
            byte_ceiling: pause.accounting.byte_ceiling,
            attempt_ceiling,
        };
        if self
            .engine
            .state()
            .lineage
            .intent
            .is_some_and(|old| old != next)
        {
            return Err(Failure::State);
        }
        session.revalidate().await?;
        let image = session.kernel()?.authenticated_image().await?;
        if pause.image != <[u8; 32]>::from(Sha256::digest(image.as_bytes()))
            || pause.endpoint != endpoint(&self.origin)
        {
            return Err(Failure::State);
        }
        let time = now()?;
        let validity = Validity::new(time, time.checked_add(300).ok_or(Failure::State)?)?;
        Ok(ReviewedSuccessor {
            consent: GenerationConsent {
                context: pause.context,
                transition: pause.transition,
                generation: pause.generation + 1,
                namespace: next.namespace,
                binding: next.binding,
                fence,
                receipt: own,
                byte_ceiling: next.byte_ceiling,
                attempt_ceiling,
                validity,
            },
            profile,
            next,
        })
    }
    pub(in super::super) async fn confirm_successor(
        &mut self,
        session: &mut Session,
        reviewed: ReviewedSuccessor,
    ) -> Result<DeliveryReport> {
        reviewed.consent.validity.check_at(now()?)?;
        let pause: Receipt = self
            .engine
            .state()
            .lineage
            .pause
            .as_ref()
            .ok_or(Failure::State)?
            .clone();
        if pause.commitment().map_err(|_| Failure::Storage)? != reviewed.consent.receipt {
            return Err(Failure::State);
        }
        let mut intent = self.engine.state().clone();
        intent.lineage.intent = Some(reviewed.next);
        let intent_raw = intent.encode().map_err(|_| Failure::State)?;
        if intent_raw != self.engine.raw() {
            self.store
                .publish_paused(self.engine.raw(), &intent_raw)
                .await
                .map_err(|_| Failure::Storage)?;
            self.engine = Engine::selected(intent_raw.clone(), self.namespace)?;
        }
        session.revalidate().await?;
        reviewed.consent.validity.check_at(now()?)?;
        let next = intent.successor().map_err(|_| Failure::State)?;
        let raw = next.encode().map_err(|_| Failure::State)?;
        let selected = DeliveryGeneration {
            generation: next.lineage.generation,
            binding: next.binding,
            namespace: reviewed.next.namespace,
            paused: false,
            transition: pause.transition,
        };
        self.store
            .select_successor(&intent_raw, &raw, selected)
            .await
            .map_err(|_| Failure::Storage)?;
        let mut p: Profile =
            serde_json::from_slice(&reviewed.profile).map_err(|_| Failure::Invalid)?;
        self.capability = Zeroizing::new(std::mem::take(&mut p.capability));
        self.namespace =
            RelayNamespace::from_bytes(reviewed.next.namespace).map_err(|_| Failure::Invalid)?;
        self.engine = Engine::selected(raw, self.namespace)?;
        session.reopen_after_generation(pause.context).await?;
        Ok(self.status(pause.context))
    }
}
