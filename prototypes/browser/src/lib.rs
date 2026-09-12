//! Reference policy for an origin-paired browser requester.

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Pairing {
    pub origin: String,
    pub key_fingerprint: u64,
    pub nonce: u64,
    pub allowed_scope: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Request {
    pub origin: String,
    pub key_fingerprint: u64,
    pub nonce: u64,
    pub scope: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Reject {
    UnknownOrigin,
    WrongKey,
    Replay,
    Scope,
}

pub fn authorize(pairing: &Pairing, request: &Request) -> Result<(), Reject> {
    if pairing.origin != request.origin {
        return Err(Reject::UnknownOrigin);
    }
    if pairing.key_fingerprint != request.key_fingerprint {
        return Err(Reject::WrongKey);
    }
    if pairing.nonce != request.nonce {
        return Err(Reject::Replay);
    }
    if request.scope != pairing.allowed_scope {
        return Err(Reject::Scope);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn pairing() -> Pairing {
        Pairing {
            origin: "https://owner.example".into(),
            key_fingerprint: 9,
            nonce: 4,
            allowed_scope: 2,
        }
    }
    fn request() -> Request {
        Request {
            origin: "https://owner.example".into(),
            key_fingerprint: 9,
            nonce: 4,
            scope: 2,
        }
    }

    #[test]
    fn exact_origin_key_nonce_and_scope_are_required() {
        let p = pairing();
        assert_eq!(authorize(&p, &request()), Ok(()));
        let mut bad = request();
        bad.origin = "https://evil.example".into();
        assert_eq!(authorize(&p, &bad), Err(Reject::UnknownOrigin));
        let mut bad = request();
        bad.key_fingerprint = 8;
        assert_eq!(authorize(&p, &bad), Err(Reject::WrongKey));
        let mut bad = request();
        bad.nonce = 5;
        assert_eq!(authorize(&p, &bad), Err(Reject::Replay));
        let mut bad = request();
        bad.scope = 3;
        assert_eq!(authorize(&p, &bad), Err(Reject::Scope));
    }
}
