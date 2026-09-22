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

/// Publication approval binds a complete artifact to one network, room and key.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct ReleaseScope {
    pub context: Context,
    pub author: [u8; 32],
}

#[derive(Clone)]
pub struct PreparedArtifact {
    input: std::rc::Rc<str>,
    readable: String,
    parts: Vec<Text>,
    scope: ReleaseScope,
}
impl PreparedArtifact {
    pub fn new(input: &str, kind: Kind, scope: ReleaseScope) -> Result<Self, &'static str> {
        if input.is_empty() || input.len() > vhalla_room_activity::puzzle_share::MAX_ARTIFACT_BYTES
        {
            return Err("Paste the complete public JSON artifact, at most 256 KiB.");
        }
        // Reject duplicate fields even in nested objects: a preview must never
        // hide one of two competing values behind a last-member-wins parser.
        let UniqueJson(value) = serde_json::from_str(input)
            .map_err(|_| "The complete artifact must be bounded JSON without duplicate fields.")?;
        if !value.is_object() {
            return Err("The complete artifact must be a JSON object.");
        }
        let readable = serde_json::to_string(&value).map_err(|_| "Cannot preview artifact.")?;
        let parts = vhalla_room_activity::puzzle_share::pack(kind, input.as_bytes())
            .map_err(|_| "Cannot prepare this complete artifact.")?;
        Ok(Self {
            input: input.into(),
            readable,
            parts,
            scope,
        })
    }
    pub fn readable(&self) -> &str {
        &self.readable
    }
    pub fn part(&self) -> Part {
        Part::decode(self.parts[0].as_str()).expect("packed part remains canonical")
    }
    pub fn matches(&self, input: &str, scope: ReleaseScope) -> bool {
        self.input.as_ref() == input && self.scope == scope
    }
}

#[derive(Clone)]
pub struct PreparedPart {
    input: String,
    text: Text,
    artifact: std::rc::Rc<str>,
    scope: ReleaseScope,
}
impl PreparedPart {
    pub fn new(
        input: &str,
        artifact: &PreparedArtifact,
        scope: ReleaseScope,
    ) -> Result<Self, &'static str> {
        if input.len() > MAX_TEXT_BYTES || artifact.scope != scope {
            return Err("The part or destination changed. Review the complete artifact again.");
        }
        let part = Part::decode(input.trim())
            .map_err(|_| "Paste one canonical public puzzle part prepared by the CLI.")?;
        let text = part.encode();
        if artifact.parts.get(part.index()) != Some(&text) {
            return Err("This part does not exactly match the approved complete artifact.");
        }
        Ok(Self {
            input: input.into(),
            text,
            artifact: artifact.input.clone(),
            scope,
        })
    }
    /// Validate again at the actual reservation boundary; no caller-supplied
    /// digest or part label can replace the exact whole-artifact comparison.
    pub fn queue_text(
        &self,
        input: &str,
        artifact: &str,
        scope: ReleaseScope,
        pending: bool,
    ) -> Result<Text, &'static str> {
        if input != self.input || artifact != self.artifact.as_ref() || scope != self.scope {
            return Err(
                "The content, room or identity changed. Review the complete artifact again.",
            );
        }
        if pending {
            return Err("A draft is already reserved. Puzzle sharing cannot replace or resume it; use the existing saved-draft controls.");
        }
        Ok(self.text.clone())
    }
    pub fn part(&self) -> Part {
        Part::decode(self.text.as_str()).expect("a prepared part remains canonical")
    }
}

// This validates preview shape only. It grants no issuer, solve or tool authority.
struct UniqueJson(serde_json::Value);
impl<'de> serde::Deserialize<'de> for UniqueJson {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        use serde::de::{self, MapAccess, SeqAccess, Visitor};
        use serde_json::Value;
        struct Unique;
        impl<'de> Visitor<'de> for Unique {
            type Value = UniqueJson;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("JSON without duplicate fields")
            }
            fn visit_bool<E: de::Error>(self, v: bool) -> Result<Self::Value, E> {
                Ok(UniqueJson(v.into()))
            }
            fn visit_i64<E: de::Error>(self, v: i64) -> Result<Self::Value, E> {
                Ok(UniqueJson(v.into()))
            }
            fn visit_u64<E: de::Error>(self, v: u64) -> Result<Self::Value, E> {
                Ok(UniqueJson(v.into()))
            }
            fn visit_f64<E: de::Error>(self, v: f64) -> Result<Self::Value, E> {
                serde_json::Number::from_f64(v)
                    .map(|n| UniqueJson(Value::Number(n)))
                    .ok_or_else(|| E::custom("nonfinite number"))
            }
            fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
                Ok(UniqueJson(v.into()))
            }
            fn visit_string<E: de::Error>(self, v: String) -> Result<Self::Value, E> {
                Ok(UniqueJson(v.into()))
            }
            fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
                Ok(UniqueJson(Value::Null))
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                let mut values = Vec::new();
                while let Some(UniqueJson(value)) = seq.next_element()? {
                    values.push(value);
                }
                Ok(UniqueJson(Value::Array(values)))
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
                let mut values = serde_json::Map::new();
                while let Some((key, UniqueJson(value))) = map.next_entry::<String, UniqueJson>()? {
                    if values.insert(key, value).is_some() {
                        return Err(de::Error::custom("duplicate field"));
                    }
                }
                Ok(UniqueJson(Value::Object(values)))
            }
        }
        deserializer.deserialize_any(Unique)
    }
}

#[derive(Default)]
pub struct Derived {
    pub context: Option<Context>,
    pub preview: Option<PreparedPart>,
    pub artifact: Option<PreparedArtifact>,
    pub approved: bool,
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
        self.artifact = None;
        self.approved = false;
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
