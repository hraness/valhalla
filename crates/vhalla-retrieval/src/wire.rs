use super::*;
const MAGIC: &[u8; 8] = b"VHRTR\0\0\x01";
const CAPABILITY_ID: u8 = 1;
pub(super) fn request(request: &Request) -> Vec<u8> {
    let mut out = prefix(0, request.nonce, request.realm);
    text(&mut out, request.query.as_str());
    out.push(u8::from(request.tag.is_some()));
    if let Some(tag) = &request.tag {
        text(&mut out, tag.as_str());
    }
    count(&mut out, request.known.len());
    for id in &request.known {
        out.extend_from_slice(id.as_bytes());
    }
    assert!(out.len() <= MAX_FRAME);
    out
}
pub(super) fn response(response: &Response) -> Vec<u8> {
    let mut out = prefix(1, response.nonce, response.realm);
    out.push(response.sequence);
    count(&mut out, response.hints.len());
    for reference in &response.hints {
        out.extend_from_slice(reference.post.as_bytes());
        out.extend_from_slice(reference.revision.as_bytes());
    }
    count(&mut out, response.records.len());
    for record in &response.records {
        count(&mut out, record.len());
        out.extend_from_slice(record);
    }
    count(&mut out, response.provider_remaining);
    assert!(out.len() <= MAX_FRAME);
    out
}
fn prefix(kind: u8, nonce: [u8; 32], realm: RealmId) -> Vec<u8> {
    let mut out = MAGIC.to_vec();
    out.push(kind);
    out.push(CAPABILITY_ID);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&realm.0.to_be_bytes());
    out
}
fn text(out: &mut Vec<u8>, value: &str) {
    count(out, value.len());
    out.extend_from_slice(value.as_bytes());
}
fn count(out: &mut Vec<u8>, value: usize) {
    out.extend_from_slice(&u16::try_from(value).expect("bounded field").to_be_bytes());
}
pub(super) fn decode_request(raw: &[u8]) -> Result<Request, Error> {
    let (mut input, nonce, realm) = Input::header(raw, 0)?;
    let query = Query::parse(input.text(256)?).map_err(|_| Error::Encoding)?;
    let tag = match input.byte()? {
        0 => None,
        1 => {
            let raw = input.text(48)?;
            let tag = CanonicalTag::new(raw).map_err(|_| Error::Encoding)?;
            if tag.as_str() != raw {
                return Err(Error::Encoding);
            };
            Some(tag)
        }
        _ => return Err(Error::Encoding),
    };
    let count = input.count(MAX_KNOWN)?;
    let mut known = Vec::new();
    for _ in 0..count {
        known.push(RecordId::from_bytes(input.id()?));
    }
    input.finish()?;
    Request::new(nonce, realm, query, tag, known)
}
pub(super) fn decode_response(raw: &[u8]) -> Result<Response, Error> {
    let (mut input, nonce, realm) = Input::header(raw, 1)?;
    let sequence = input.byte()?;
    if usize::from(sequence) >= MAX_ATTEMPTS {
        return Err(Error::Bounds);
    };
    let count = input.count(MAX_HINTS)?;
    let mut hints = Vec::new();
    for _ in 0..count {
        hints.push(PostRef {
            post: RecordId::from_bytes(input.id()?),
            revision: RecordId::from_bytes(input.id()?),
        });
    }
    if hints.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(Error::Encoding);
    };
    let count = input.count(MAX_RECORDS_PER_FRAME)?;
    let mut records = Vec::new();
    for _ in 0..count {
        let count = input.count(MAX_RECORD_BYTES)?;
        if count == 0 {
            return Err(Error::Encoding);
        };
        records.push(input.take(count)?.to_vec());
    }
    let provider_remaining = input.count(vhalla_social::MAX_RECORDS)?;
    input.finish()?;
    Ok(Response {
        nonce,
        realm,
        sequence,
        hints,
        records,
        provider_remaining,
    })
}
struct Input<'a> {
    raw: &'a [u8],
    at: usize,
}
impl<'a> Input<'a> {
    fn header(raw: &'a [u8], kind: u8) -> Result<(Self, [u8; 32], RealmId), Error> {
        if raw.len() > MAX_FRAME {
            return Err(Error::Bounds);
        };
        let mut input = Self { raw, at: 0 };
        if input.take(8)? != MAGIC || input.byte() != Ok(kind) || input.byte() != Ok(CAPABILITY_ID)
        {
            return Err(Error::Encoding);
        };
        let nonce = input.id()?;
        let realm = RealmId(u128::from_be_bytes(
            input.take(16)?.try_into().map_err(|_| Error::Encoding)?,
        ));
        Ok((input, nonce, realm))
    }
    fn take(&mut self, count: usize) -> Result<&'a [u8], Error> {
        let end = self.at.checked_add(count).ok_or(Error::Bounds)?;
        let value = self.raw.get(self.at..end).ok_or(Error::Encoding)?;
        self.at = end;
        Ok(value)
    }
    fn id(&mut self) -> Result<[u8; 32], Error> {
        self.take(32)?.try_into().map_err(|_| Error::Encoding)
    }
    fn byte(&mut self) -> Result<u8, Error> {
        Ok(self.take(1)?[0])
    }
    fn count(&mut self, max: usize) -> Result<usize, Error> {
        let value = usize::from(u16::from_be_bytes(
            self.take(2)?.try_into().map_err(|_| Error::Encoding)?,
        ));
        if value > max {
            Err(Error::Bounds)
        } else {
            Ok(value)
        }
    }
    fn text(&mut self, max: usize) -> Result<&'a str, Error> {
        let count = self.count(max)?;
        core::str::from_utf8(self.take(count)?).map_err(|_| Error::Encoding)
    }
    fn finish(self) -> Result<(), Error> {
        if self.at == self.raw.len() {
            Ok(())
        } else {
            Err(Error::Encoding)
        }
    }
}
