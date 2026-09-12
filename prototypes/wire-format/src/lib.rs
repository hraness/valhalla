//! Throwaway wire-format comparison for Valhalla/Vhalla event envelopes.
//! The experiment intentionally keeps the envelope small and makes canonicalization explicit.

use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Envelope {
    pub version: u64,
    pub realm: String,
    pub room: String,
    pub event_id: String,
    pub author: String,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
    pub body: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedEnvelope {
    pub envelope: Envelope,
    pub ignored_unknown_fields: Vec<String>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum DecodeError {
    TooLarge { actual: usize, limit: usize },
    InvalidUtf8,
    InvalidJson(String),
    MissingField(&'static str),
    WrongType(&'static str),
    UnsupportedVersion(u64),
    InvalidCbor(&'static str),
    TrailingBytes,
}

const MAX_WIRE_BYTES: usize = 64 * 1024;
const MAX_BODY_BYTES: usize = 16 * 1024;
const MAX_STRING_BYTES: usize = 256;

impl Envelope {
    pub fn example() -> Self {
        Self {
            version: 1,
            realm: "example".into(),
            room: "#agents".into(),
            event_id: "01J00000000000000000000000".into(),
            author: "ed25519:alice".into(),
            issued_at_ms: 1_700_000_000_000,
            expires_at_ms: 1_700_000_060_000,
            body: b"hello".to_vec(),
        }
    }

    /// Transcript used by a signature implementation. It excludes the signature itself.
    pub fn signing_transcript(&self, format: WireFormat) -> Vec<u8> {
        match format {
            WireFormat::CanonicalJson => canonical_json(self),
            WireFormat::CanonicalCbor => canonical_cbor(self),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireFormat {
    CanonicalJson,
    CanonicalCbor,
}

/// Deterministic JSON: object keys are emitted in bytewise lexicographic order and body is base64url.
pub fn canonical_json(e: &Envelope) -> Vec<u8> {
    // Field order is explicit and values use a small strict JSON escaper.
    let esc = |s: &str| json_escape(s);
    let body = base64url(&e.body);
    let out = format!(
        "{{\"author\":{},\"body\":{},\"event_id\":{},\"expires_at_ms\":{},\"issued_at_ms\":{},\"realm\":{},\"room\":{},\"version\":{}}}",
        esc(&e.author), esc(&body), esc(&e.event_id), e.expires_at_ms, e.issued_at_ms,
        esc(&e.realm), esc(&e.room), e.version
    );
    out.into_bytes()
}

/// Canonical CBOR for this fixed map. Keys are sorted by their encoded byte strings.
pub fn canonical_cbor(e: &Envelope) -> Vec<u8> {
    let mut fields: Vec<(Vec<u8>, Vec<u8>)> = vec![
        cbor_field("author", cbor_text(&e.author)),
        cbor_field("body", cbor_bytes(&e.body)),
        cbor_field("event_id", cbor_text(&e.event_id)),
        cbor_field("expires_at_ms", cbor_uint(e.expires_at_ms)),
        cbor_field("issued_at_ms", cbor_uint(e.issued_at_ms)),
        cbor_field("realm", cbor_text(&e.realm)),
        cbor_field("room", cbor_text(&e.room)),
        cbor_field("version", cbor_uint(e.version)),
    ];
    fields.sort_by(|a, b| a.0.cmp(&b.0));
    let mut out = cbor_len(5, fields.len());
    for (key, val) in fields {
        out.extend(key);
        out.extend(val);
    }
    out
}

fn cbor_field(key: &str, value: Vec<u8>) -> (Vec<u8>, Vec<u8>) {
    (cbor_text(key), value)
}
fn cbor_len(major: u8, n: usize) -> Vec<u8> {
    let n = n as u64;
    if n < 24 {
        vec![(major << 5) | n as u8]
    } else if n <= u8::MAX as u64 {
        vec![(major << 5) | 24, n as u8]
    } else if n <= u16::MAX as u64 {
        let mut x = vec![(major << 5) | 25];
        x.extend((n as u16).to_be_bytes());
        x
    } else if n <= u32::MAX as u64 {
        let mut x = vec![(major << 5) | 26];
        x.extend((n as u32).to_be_bytes());
        x
    } else {
        let mut x = vec![(major << 5) | 27];
        x.extend(n.to_be_bytes());
        x
    }
}
fn cbor_uint(n: u64) -> Vec<u8> {
    if n < 24 {
        vec![n as u8]
    } else if n <= u8::MAX as u64 {
        vec![24, n as u8]
    } else if n <= u16::MAX as u64 {
        let mut x = vec![25];
        x.extend((n as u16).to_be_bytes());
        x
    } else if n <= u32::MAX as u64 {
        let mut x = vec![26];
        x.extend((n as u32).to_be_bytes());
        x
    } else {
        let mut x = vec![27];
        x.extend(n.to_be_bytes());
        x
    }
}
fn cbor_text(s: &str) -> Vec<u8> {
    let mut x = cbor_len(3, s.len());
    x.extend(s.as_bytes());
    x
}
fn cbor_bytes(b: &[u8]) -> Vec<u8> {
    let mut x = cbor_len(2, b.len());
    x.extend(b);
    x
}
fn base64url(bytes: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    let mut i = 0;
    while i + 3 <= bytes.len() {
        let n = u32::from_be_bytes([0, bytes[i], bytes[i + 1], bytes[i + 2]]);
        out.push(A[(n >> 18 & 63) as usize] as char);
        out.push(A[(n >> 12 & 63) as usize] as char);
        out.push(A[(n >> 6 & 63) as usize] as char);
        out.push(A[(n & 63) as usize] as char);
        i += 3;
    }
    match bytes.len() - i {
        1 => {
            let n = (bytes[i] as u32) << 16;
            out.push(A[(n >> 18 & 63) as usize] as char);
            out.push(A[(n >> 12 & 63) as usize] as char);
        }
        2 => {
            let n = ((bytes[i] as u32) << 16) | ((bytes[i + 1] as u32) << 8);
            out.push(A[(n >> 18 & 63) as usize] as char);
            out.push(A[(n >> 12 & 63) as usize] as char);
            out.push(A[(n >> 6 & 63) as usize] as char);
        }
        _ => {}
    }
    out
}

fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Strict JSON decoder: accepts unknown fields for forward compatibility, but never trusts them.
pub fn decode_json(input: &[u8]) -> Result<DecodedEnvelope, DecodeError> {
    bounded(input)?;
    let mut p = JsonParser { b: input, i: 0 };
    let obj = p.object()?;
    if p.i != input.len() {
        return Err(DecodeError::InvalidJson("trailing bytes".into()));
    };
    let get_str = |name: &'static str| match obj.get(name) {
        Some(J::Str(v)) => Ok(v.as_str()),
        Some(_) => Err(DecodeError::WrongType(name)),
        None => Err(DecodeError::MissingField(name)),
    };
    let get_u64 = |name: &'static str| match obj.get(name) {
        Some(J::Num(v)) => Ok(*v),
        Some(_) => Err(DecodeError::WrongType(name)),
        None => Err(DecodeError::MissingField(name)),
    };
    let body = get_str("body")?;
    if body.len() > MAX_BODY_BYTES * 2 {
        return Err(DecodeError::WrongType("body"));
    }
    let envelope = Envelope {
        author: bounded_string(get_str("author")?)?,
        body: decode_base64url(body)?,
        event_id: bounded_string(get_str("event_id")?)?,
        expires_at_ms: get_u64("expires_at_ms")?,
        issued_at_ms: get_u64("issued_at_ms")?,
        realm: bounded_string(get_str("realm")?)?,
        room: bounded_string(get_str("room")?)?,
        version: get_u64("version")?,
    };
    validate(&envelope)?;
    let known = [
        "author",
        "body",
        "event_id",
        "expires_at_ms",
        "issued_at_ms",
        "realm",
        "room",
        "version",
    ];
    let ignored_unknown_fields = obj
        .keys()
        .filter(|k| !known.contains(&k.as_str()))
        .cloned()
        .collect();
    Ok(DecodedEnvelope {
        envelope,
        ignored_unknown_fields,
    })
}

#[derive(Debug)]
enum J {
    Str(String),
    Num(u64),
    Bool,
    Null,
}
struct JsonParser<'a> {
    b: &'a [u8],
    i: usize,
}
impl<'a> JsonParser<'a> {
    fn ws(&mut self) {
        while self.b.get(self.i).is_some_and(|c| c.is_ascii_whitespace()) {
            self.i += 1
        }
    }
    fn object(&mut self) -> Result<BTreeMap<String, J>, DecodeError> {
        self.ws();
        if self.b.get(self.i) != Some(&b'{') {
            return Err(DecodeError::InvalidJson("object expected".into()));
        };
        self.i += 1;
        let mut m = BTreeMap::new();
        self.ws();
        if self.b.get(self.i) == Some(&b'}') {
            self.i += 1;
            return Ok(m);
        }
        loop {
            self.ws();
            let k = self.string()?;
            if m.contains_key(&k) {
                return Err(DecodeError::InvalidJson("duplicate key".into()));
            };
            self.ws();
            if self.b.get(self.i) != Some(&b':') {
                return Err(DecodeError::InvalidJson("colon expected".into()));
            };
            self.i += 1;
            self.ws();
            let v = self.value()?;
            m.insert(k, v);
            self.ws();
            match self.b.get(self.i) {
                Some(b',') => self.i += 1,
                Some(b'}') => {
                    self.i += 1;
                    return Ok(m);
                }
                _ => return Err(DecodeError::InvalidJson("comma or end expected".into())),
            }
        }
    }
    fn string(&mut self) -> Result<String, DecodeError> {
        if self.b.get(self.i) != Some(&b'"') {
            return Err(DecodeError::InvalidJson("string expected".into()));
        };
        self.i += 1;
        let mut s = String::new();
        while let Some(&c) = self.b.get(self.i) {
            self.i += 1;
            match c {
                b'"' => return Ok(s),
                b'\\' => {
                    let e = *self
                        .b
                        .get(self.i)
                        .ok_or_else(|| DecodeError::InvalidJson("escape eof".into()))?;
                    self.i += 1;
                    match e {
                        b'"' => s.push('"'),
                        b'\\' => s.push('\\'),
                        b'n' => s.push('\n'),
                        b'r' => s.push('\r'),
                        b't' => s.push('\t'),
                        _ => return Err(DecodeError::InvalidJson("unsupported escape".into())),
                    }
                }
                c if c < 0x20 => return Err(DecodeError::InvalidJson("control byte".into())),
                c => s.push(c as char),
            }
        }
        Err(DecodeError::InvalidJson("string eof".into()))
    }
    fn value(&mut self) -> Result<J, DecodeError> {
        match self.b.get(self.i) {
            Some(b'"') => Ok(J::Str(self.string()?)),
            Some(b'0'..=b'9') => {
                let st = self.i;
                while self.b.get(self.i).is_some_and(|c| c.is_ascii_digit()) {
                    self.i += 1
                }
                let n = std::str::from_utf8(&self.b[st..self.i])
                    .unwrap()
                    .parse()
                    .map_err(|_| DecodeError::InvalidJson("number".into()))?;
                Ok(J::Num(n))
            }
            Some(b't') if self.b[self.i..].starts_with(b"true") => {
                self.i += 4;
                Ok(J::Bool)
            }
            Some(b'f') if self.b[self.i..].starts_with(b"false") => {
                self.i += 5;
                Ok(J::Bool)
            }
            Some(b'n') if self.b[self.i..].starts_with(b"null") => {
                self.i += 4;
                Ok(J::Null)
            }
            _ => Err(DecodeError::InvalidJson("value expected".into())),
        }
    }
}

fn decode_base64url(s: &str) -> Result<Vec<u8>, DecodeError> {
    let mut out = Vec::new();
    let mut buf = 0u32;
    let mut bits = 0;
    for c in s.bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'-' => 62,
            b'_' => 63,
            _ => return Err(DecodeError::InvalidJson("invalid base64url".into())),
        } as u32;
        buf = (buf << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
            buf &= (1 << bits) - 1;
            if out.len() > MAX_BODY_BYTES {
                return Err(DecodeError::WrongType("body"));
            }
        }
    }
    Ok(out)
}
fn bounded(input: &[u8]) -> Result<(), DecodeError> {
    if input.len() > MAX_WIRE_BYTES {
        Err(DecodeError::TooLarge {
            actual: input.len(),
            limit: MAX_WIRE_BYTES,
        })
    } else {
        Ok(())
    }
}
fn bounded_string(s: &str) -> Result<String, DecodeError> {
    if s.len() > MAX_STRING_BYTES {
        Err(DecodeError::WrongType("string"))
    } else {
        Ok(s.to_owned())
    }
}
fn validate(e: &Envelope) -> Result<(), DecodeError> {
    if e.version != 1 {
        return Err(DecodeError::UnsupportedVersion(e.version));
    }
    if e.body.len() > MAX_BODY_BYTES {
        return Err(DecodeError::WrongType("body"));
    }
    Ok(())
}

/// Minimal CBOR decoder for the canonical envelope, retained to test bounded framing and map behavior.
pub fn decode_cbor(input: &[u8]) -> Result<DecodedEnvelope, DecodeError> {
    bounded(input)?;
    let mut p = Parser { b: input, i: 0 };
    let n = p.map_len()?;
    let mut values: BTreeMap<String, Item> = BTreeMap::new();
    for _ in 0..n {
        let k = p.text(MAX_STRING_BYTES)?;
        if values.contains_key(&k) {
            return Err(DecodeError::InvalidCbor("duplicate key"));
        }
        values.insert(k, p.item()?);
    }
    if p.i != input.len() {
        return Err(DecodeError::TrailingBytes);
    }
    let take_text =
        |name: &'static str, map: &mut BTreeMap<String, Item>| -> Result<String, DecodeError> {
            match map.remove(name) {
                Some(Item::Text(v)) => Ok(v),
                Some(_) => Err(DecodeError::WrongType(name)),
                None => Err(DecodeError::MissingField(name)),
            }
        };
    let take_uint =
        |name: &'static str, map: &mut BTreeMap<String, Item>| -> Result<u64, DecodeError> {
            match map.remove(name) {
                Some(Item::Uint(v)) => Ok(v),
                Some(_) => Err(DecodeError::WrongType(name)),
                None => Err(DecodeError::MissingField(name)),
            }
        };
    let envelope = Envelope {
        author: bounded_string(&take_text("author", &mut values)?)?,
        body: match values.remove("body") {
            Some(Item::Bytes(v)) => v,
            Some(_) => return Err(DecodeError::WrongType("body")),
            None => return Err(DecodeError::MissingField("body")),
        },
        event_id: bounded_string(&take_text("event_id", &mut values)?)?,
        expires_at_ms: take_uint("expires_at_ms", &mut values)?,
        issued_at_ms: take_uint("issued_at_ms", &mut values)?,
        realm: bounded_string(&take_text("realm", &mut values)?)?,
        room: bounded_string(&take_text("room", &mut values)?)?,
        version: take_uint("version", &mut values)?,
    };
    validate(&envelope)?;
    Ok(DecodedEnvelope {
        envelope,
        ignored_unknown_fields: values.keys().cloned().collect(),
    })
}
#[derive(Debug)]
enum Item {
    Text(String),
    Bytes(Vec<u8>),
    Uint(u64),
}
struct Parser<'a> {
    b: &'a [u8],
    i: usize,
}
impl<'a> Parser<'a> {
    fn head(&mut self) -> Result<(u8, u64), DecodeError> {
        let x = *self.b.get(self.i).ok_or(DecodeError::InvalidCbor("eof"))?;
        self.i += 1;
        let m = x >> 5;
        let a = x & 31;
        let n = match a {
            0..=23 => a as u64,
            24 => self.take(1)?,
            25 => self.take(2)?,
            26 => self.take(4)?,
            27 => self.take(8)?,
            _ => return Err(DecodeError::InvalidCbor("indefinite/invalid length")),
        };
        let canonical = match a {
            24 => n >= 24,
            25 => n > u8::MAX as u64,
            26 => n > u16::MAX as u64,
            27 => n > u32::MAX as u64,
            _ => true,
        };
        if !canonical {
            return Err(DecodeError::InvalidCbor("non-canonical integer/length"));
        }
        Ok((m, n))
    }
    fn take(&mut self, n: usize) -> Result<u64, DecodeError> {
        if self.i + n > self.b.len() {
            return Err(DecodeError::InvalidCbor("eof"));
        }
        let mut v = 0;
        for x in &self.b[self.i..self.i + n] {
            v = (v << 8) | *x as u64
        }
        self.i += n;
        Ok(v)
    }
    fn map_len(&mut self) -> Result<usize, DecodeError> {
        let (m, n) = self.head()?;
        if m != 5 || n > 64 {
            Err(DecodeError::InvalidCbor("expected bounded map"))
        } else {
            Ok(n as usize)
        }
    }
    fn text(&mut self, max: usize) -> Result<String, DecodeError> {
        let (m, n) = self.head()?;
        if m != 3 || n as usize > max || self.i + n as usize > self.b.len() {
            return Err(DecodeError::InvalidCbor("expected bounded text"));
        }
        let s = std::str::from_utf8(&self.b[self.i..self.i + n as usize])
            .map_err(|_| DecodeError::InvalidUtf8)?
            .to_owned();
        self.i += n as usize;
        Ok(s)
    }
    fn item(&mut self) -> Result<Item, DecodeError> {
        let save = self.i;
        let (m, n) = self.head()?;
        match m {
            0 => Ok(Item::Uint(n)),
            2 => {
                if n as usize > MAX_BODY_BYTES || self.i + n as usize > self.b.len() {
                    return Err(DecodeError::InvalidCbor("bounded bytes"));
                }
                let v = self.b[self.i..self.i + n as usize].to_vec();
                self.i += n as usize;
                Ok(Item::Bytes(v))
            }
            3 => {
                self.i = save;
                Ok(Item::Text(self.text(MAX_STRING_BYTES)?))
            }
            _ => Err(DecodeError::InvalidCbor("unsupported value")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn canonical_json_is_stable_and_sorted() {
        let e = Envelope::example();
        assert_eq!(String::from_utf8(canonical_json(&e)).unwrap(), "{\"author\":\"ed25519:alice\",\"body\":\"aGVsbG8\",\"event_id\":\"01J00000000000000000000000\",\"expires_at_ms\":1700000060000,\"issued_at_ms\":1700000000000,\"realm\":\"example\",\"room\":\"#agents\",\"version\":1}");
    }
    #[test]
    fn canonical_cbor_is_stable_and_differs_from_json() {
        let e = Envelope::example();
        assert_eq!(canonical_cbor(&e), canonical_cbor(&e));
        assert_ne!(canonical_cbor(&e), canonical_json(&e));
    }
    #[test]
    fn json_round_trip_and_unknown_fields_are_data() {
        let mut s = String::from_utf8(canonical_json(&Envelope::example())).unwrap();
        s.pop();
        s.push_str(",\"future\":true}");
        let d = decode_json(s.as_bytes()).unwrap();
        assert_eq!(d.envelope, Envelope::example());
        assert_eq!(d.ignored_unknown_fields, vec!["future"]);
    }
    #[test]
    fn cbor_round_trip_and_unknown_fields_are_ignored() {
        let e = Envelope::example();
        let mut b = canonical_cbor(&e);
        b[0] = 0xa9;
        b.extend(cbor_text("future"));
        b.extend(cbor_uint(7));
        let d = decode_cbor(&b).unwrap();
        assert_eq!(d.envelope, e);
        assert_eq!(d.ignored_unknown_fields, vec!["future"]);
    }
    #[test]
    fn rejects_duplicate_or_oversized_input() {
        let e = Envelope::example();
        let mut b = canonical_cbor(&e);
        b[0] = 0xa9;
        b.extend(cbor_text("author"));
        b.extend(cbor_text("mallory"));
        assert!(matches!(
            decode_cbor(&b),
            Err(DecodeError::InvalidCbor("duplicate key"))
        ));
        assert!(matches!(
            decode_json(&vec![b'x'; MAX_WIRE_BYTES + 1]),
            Err(DecodeError::TooLarge { .. })
        ));
    }
    #[test]
    fn signing_transcript_excludes_mutable_signature() {
        let e = Envelope::example();
        assert_eq!(
            e.signing_transcript(WireFormat::CanonicalJson),
            canonical_json(&e)
        );
    }
}
