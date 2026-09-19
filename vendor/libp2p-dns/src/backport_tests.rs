//! Deterministic coverage of the Hickory 0.26 adapter, without public DNS.

use futures::executor::block_on;
use hickory_resolver::proto::{
    op::Query,
    rr::{rdata::TXT, Name, Record, RecordType},
};

use super::*;

#[derive(Clone)]
struct Answers {
    lookup: Lookup,
    fail: bool,
}

impl Answers {
    fn new(records: Vec<RData>) -> Self {
        let name: Name = "example.test.".parse().unwrap();
        Self {
            lookup: Lookup::new_with_max_ttl(
                Query::query(name.clone(), RecordType::ANY),
                records
                    .into_iter()
                    .map(|data| Record::from_rdata(name.clone(), 60, data)),
            ),
            fail: false,
        }
    }

    fn result(&self) -> Result<Lookup, ResolveError> {
        if self.fail {
            Err(ResolveError::from("injected resolver failure"))
        } else {
            Ok(self.lookup.clone())
        }
    }
}

#[async_trait]
impl Resolver for Answers {
    async fn lookup_ip(&self, _: String) -> Result<LookupIp, ResolveError> {
        self.result().map(Into::into)
    }

    async fn ipv4_lookup(&self, _: String) -> Result<Lookup, ResolveError> {
        self.result()
    }

    async fn ipv6_lookup(&self, _: String) -> Result<Lookup, ResolveError> {
        self.result()
    }

    async fn txt_lookup(&self, _: String) -> Result<Lookup, ResolveError> {
        self.result()
    }
}

#[test]
fn backport_lookup_answers_are_filtered_by_family() {
    let v4 = Ipv4Addr::new(192, 0, 2, 1);
    let v6: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let resolver = Answers::new(vec![
        RData::A(v4.into()),
        RData::AAAA(v6.into()),
        RData::TXT(TXT::new(vec!["unrelated".into()])),
    ]);
    let result = block_on(resolve::<io::Error, _>(
        &Protocol::Dns4("example.test".into()),
        &resolver,
    ))
    .unwrap();
    assert!(matches!(result, Resolved::One(Protocol::Ip4(ip)) if ip == v4));
    let result = block_on(resolve::<io::Error, _>(
        &Protocol::Dns6("example.test".into()),
        &resolver,
    ))
    .unwrap();
    assert!(matches!(result, Resolved::One(Protocol::Ip6(ip)) if ip == v6));
    let result = block_on(resolve::<io::Error, _>(
        &Protocol::Dns("example.test".into()),
        &resolver,
    ))
    .unwrap();
    match result {
        Resolved::Many(ips) => assert_eq!(ips, vec![Protocol::Ip4(v4), Protocol::Ip6(v6)]),
        _ => panic!("expected both IP addresses"),
    }
}

#[test]
fn backport_multiple_addresses_preserve_fallback_order() {
    let resolver = Answers::new(vec![
        RData::A(Ipv4Addr::new(192, 0, 2, 1).into()),
        RData::A(Ipv4Addr::new(192, 0, 2, 2).into()),
    ]);
    let result = block_on(resolve::<io::Error, _>(
        &Protocol::Dns4("example.test".into()),
        &resolver,
    ))
    .unwrap();
    match result {
        Resolved::Many(ips) => assert_eq!(
            ips,
            vec![
                Protocol::Ip4(Ipv4Addr::new(192, 0, 2, 1)),
                Protocol::Ip4(Ipv4Addr::new(192, 0, 2, 2)),
            ]
        ),
        _ => panic!("expected ordered fallback addresses"),
    }
}

#[test]
fn backport_txt_records_decode_dnsaddr() {
    let resolver = Answers::new(vec![
        RData::A(Ipv4Addr::new(192, 0, 2, 1).into()),
        RData::TXT(TXT::new(vec!["unrelated".into()])),
        RData::TXT(TXT::new(vec!["dnsaddr=/ip4/192.0.2.2/tcp/42".into()])),
    ]);
    let result = block_on(resolve::<io::Error, _>(
        &Protocol::Dnsaddr("example.test".into()),
        &resolver,
    ))
    .unwrap();
    match result {
        Resolved::Addrs(addrs) => assert_eq!(
            addrs,
            vec!["/ip4/192.0.2.2/tcp/42".parse::<Multiaddr>().unwrap()]
        ),
        _ => panic!("expected the one valid DNS address"),
    }
}

#[test]
fn backport_lookup_failures_remain_transport_errors() {
    let mut resolver = Answers::new(vec![]);
    resolver.fail = true;
    for proto in [
        Protocol::Dns("example.test".into()),
        Protocol::Dns4("example.test".into()),
        Protocol::Dns6("example.test".into()),
        Protocol::Dnsaddr("example.test".into()),
    ] {
        assert!(matches!(
            block_on(resolve::<io::Error, _>(&proto, &resolver)),
            Err(Error::ResolveError(_))
        ));
    }
}

#[test]
fn backport_literal_addresses_do_not_query_dns() {
    let mut resolver = Answers::new(vec![]);
    resolver.fail = true;
    let ip = Ipv4Addr::new(192, 0, 2, 1);
    let result = block_on(resolve::<io::Error, _>(&Protocol::Ip4(ip), &resolver)).unwrap();
    assert!(matches!(result, Resolved::One(Protocol::Ip4(found)) if found == ip));
}

#[test]
fn backport_tokio_constructor_implements_libp2p_043_transport() {
    fn accepts_transport<T: libp2p_core::Transport>(_: T) {}
    let transport = tokio::Transport::custom(
        libp2p_core::transport::MemoryTransport::default(),
        ResolverConfig::default(),
        ResolverOpts::default(),
    );
    accepts_transport(transport);
}

#[test]
fn backport_successful_empty_ip_lookup_returns_error() {
    let resolver = Answers::new(vec![]);
    for protocol in [
        Protocol::Dns("example.test".into()),
        Protocol::Dns4("example.test".into()),
        Protocol::Dns6("example.test".into()),
    ] {
        assert!(matches!(
            block_on(resolve::<io::Error, _>(&protocol, &resolver)),
            Err(Error::ResolveError(_))
        ));
    }
}

#[test]
fn backport_wrong_family_lookup_returns_error() {
    let cases = [
        (
            Protocol::Dns4("example.test".into()),
            RData::AAAA(Ipv6Addr::LOCALHOST.into()),
        ),
        (
            Protocol::Dns6("example.test".into()),
            RData::A(Ipv4Addr::LOCALHOST.into()),
        ),
        (
            Protocol::Dns("example.test".into()),
            RData::TXT(TXT::new(vec!["not an IP".into()])),
        ),
    ];
    for (protocol, data) in cases {
        let resolver = Answers::new(vec![data]);
        assert!(matches!(
            block_on(resolve::<io::Error, _>(&protocol, &resolver)),
            Err(Error::ResolveError(_))
        ));
    }
}

#[test]
fn backport_additional_only_ip_lookup_returns_error() {
    // Hickory 0.26 can report success for a matching record in ADDITIONAL
    // while ANSWER remains empty. Never turn that remote response into a panic.
    for (protocol, record_type, data) in [
        (
            Protocol::Dns("example.test".into()),
            RecordType::A,
            RData::A(Ipv4Addr::LOCALHOST.into()),
        ),
        (
            Protocol::Dns4("example.test".into()),
            RecordType::A,
            RData::A(Ipv4Addr::LOCALHOST.into()),
        ),
        (
            Protocol::Dns6("example.test".into()),
            RecordType::AAAA,
            RData::AAAA(Ipv6Addr::LOCALHOST.into()),
        ),
    ] {
        let name: Name = "example.test.".parse().unwrap();
        let mut lookup = Lookup::new_with_max_ttl(Query::query(name.clone(), record_type), []);
        lookup.extend_additionals([Record::from_rdata(name, 60, data)]);
        let resolver = Answers {
            lookup,
            fail: false,
        };
        assert!(matches!(
            block_on(resolve::<io::Error, _>(&protocol, &resolver)),
            Err(Error::ResolveError(_))
        ));
    }
}
