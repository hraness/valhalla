//! Reference validation for replaceable discovery hints and route selection.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Route {
    Direct,
    Relay,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Descriptor {
    pub realm: u64,
    pub protocol: u16,
    pub expires_at: u64,
    pub route: Route,
    pub signature_valid: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TrustPolicy {
    pub realm: u64,
    pub minimum_protocol: u16,
    pub now: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Reject {
    WrongRealm,
    Downgrade,
    Expired,
    InvalidSignature,
}

pub fn accept(policy: TrustPolicy, descriptor: Descriptor) -> Result<Descriptor, Reject> {
    if descriptor.realm != policy.realm {
        return Err(Reject::WrongRealm);
    }
    if descriptor.protocol < policy.minimum_protocol {
        return Err(Reject::Downgrade);
    }
    if descriptor.expires_at < policy.now {
        return Err(Reject::Expired);
    }
    if !descriptor.signature_valid {
        return Err(Reject::InvalidSignature);
    }
    Ok(descriptor)
}

pub fn choose_route(
    direct: Option<Descriptor>,
    relay: Option<Descriptor>,
    policy: TrustPolicy,
) -> Result<Descriptor, Reject> {
    if let Some(candidate) = direct.and_then(|d| accept(policy, d).ok()) {
        return Ok(candidate);
    }
    relay.map_or(Err(Reject::InvalidSignature), |candidate| {
        accept(policy, candidate)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn policy() -> TrustPolicy {
        TrustPolicy {
            realm: 7,
            minimum_protocol: 1,
            now: 100,
        }
    }
    fn descriptor(route: Route) -> Descriptor {
        Descriptor {
            realm: 7,
            protocol: 1,
            expires_at: 200,
            route,
            signature_valid: true,
        }
    }

    #[test]
    fn direct_is_preferred_and_relay_is_fallback() {
        assert_eq!(
            choose_route(
                Some(descriptor(Route::Direct)),
                Some(descriptor(Route::Relay)),
                policy()
            )
            .unwrap()
            .route,
            Route::Direct
        );
        let bad_direct = Descriptor {
            signature_valid: false,
            ..descriptor(Route::Direct)
        };
        assert_eq!(
            choose_route(Some(bad_direct), Some(descriptor(Route::Relay)), policy())
                .unwrap()
                .route,
            Route::Relay
        );
    }

    #[test]
    fn discovery_hints_cannot_change_trust_or_downgrade_protocol() {
        let mut bad = descriptor(Route::Direct);
        bad.realm = 8;
        assert_eq!(accept(policy(), bad), Err(Reject::WrongRealm));
        let mut old = descriptor(Route::Direct);
        old.protocol = 0;
        assert_eq!(accept(policy(), old), Err(Reject::Downgrade));
    }
}
