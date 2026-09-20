//! One bounded, explicitly selected assembly from already authenticated activity.
use vhalla_room_activity::{
    puzzle_share::{Collector, Kind, Part},
    Content, RoomScope, Text, VerifiedEvent, MAX_TEXT_BYTES,
};

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct Context {
    pub room: RoomScope,
    pub bootstrap_pin: [u8; 32],
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct Selection {
    pub context: Context,
    pub author: [u8; 32],
    pub kind: Kind,
    pub digest: [u8; 32],
}

#[derive(Clone)]
pub struct PreparedPart {
    input: String,
    text: Text,
}
impl PreparedPart {
    pub fn new(input: &str) -> Result<Self, &'static str> {
        if input.len() > MAX_TEXT_BYTES {
            return Err(
                "A pasted puzzle part must fit within 4,096 UTF-8 bytes, including whitespace.",
            );
        }
        let part = Part::decode(input.trim())
            .map_err(|_| "Paste one canonical public puzzle part prepared by the CLI.")?;
        Ok(Self {
            input: input.into(),
            text: part.encode(),
        })
    }
    /// Called with the freshly loaded durable pending state, before creating
    /// a new reservation. This action can never select or resume that draft.
    pub fn queue_text(&self, input: &str, pending: bool) -> Result<Text, &'static str> {
        if input != self.input {
            return Err("The part changed. Validate and preview it again before signing.");
        }
        if pending {
            return Err("A draft is already reserved. Puzzle sharing cannot replace or resume it; use the existing explicit saved-draft controls.");
        }
        Ok(self.text.clone())
    }
    pub fn part(&self) -> Part {
        Part::decode(self.text.as_str()).expect("a prepared part remains canonical")
    }
}

#[derive(Default)]
pub struct Derived {
    pub context: Option<Context>,
    pub preview: Option<PreparedPart>,
    pub assembly: Option<Assembly>,
}
impl Derived {
    /// This type holds no persistent author state, reservation or key.
    pub fn set_context(&mut self, next: Option<Context>) -> bool {
        if self.context == next {
            return false;
        }
        self.context = next;
        self.preview = None;
        self.assembly = None;
        true
    }
}

pub struct Assembly {
    pub selection: Selection,
    collector: Collector,
    failed: bool,
}
impl Assembly {
    pub fn new(selection: Selection) -> Result<Self, &'static str> {
        let collector = Collector::new(
            selection.context.room,
            selection.author,
            selection.kind,
            selection.digest,
        )
        .map_err(|_| "Invalid full sharer key or artifact selection.")?;
        Ok(Self {
            selection,
            collector,
            failed: false,
        })
    }
    /// Ignore unrelated verified activity. Matching inconsistent evidence
    /// latches this derived assembly; an explicit new selection is required.
    pub fn observe(&mut self, event: &VerifiedEvent) -> Result<bool, &'static str> {
        if self.failed {
            return Err("This assembly failed validation. Start a new collection explicitly.");
        }
        let claims = event.claims();
        if claims.scope != self.selection.context.room || claims.author != self.selection.author {
            return Ok(false);
        }
        let Content::Text(text) = &claims.content;
        let Ok(part) = Part::decode(text.as_str()) else {
            return Ok(false);
        };
        if part.kind() != self.selection.kind || part.digest() != &self.selection.digest {
            return Ok(false);
        }
        if self.collector.push(event).is_err() {
            self.failed = true;
            return Err("Matching parts conflict or fail their complete artifact digest. Nothing can be downloaded from this assembly.");
        }
        Ok(true)
    }
    pub fn received(&self) -> usize {
        self.collector.received()
    }
    pub fn total(&self) -> Option<usize> {
        self.collector.total()
    }
    pub fn bytes(&self) -> Option<&[u8]> {
        (!self.failed).then(|| self.collector.bytes()).flatten()
    }
}

/// Strict complete lowercase hexadecimal selectors; never shortened keys.
pub fn hex32(text: &str) -> Option<[u8; 32]> {
    if text.len() != 64
        || !text
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return None;
    }
    let mut value = [0; 32];
    for (index, byte) in value.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[index * 2..index * 2 + 2], 16).ok()?;
    }
    Some(value)
}
