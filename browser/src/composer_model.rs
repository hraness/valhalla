//! Volatile public text bound to its original full destination and author.
use vhalla_room_activity::{RoomScope, Text, MAX_TEXT_BYTES};
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct Context {
    pub room: RoomScope,
    pub bootstrap_pin: [u8; 32],
    pub author: [u8; 32],
}
#[derive(Default)]
pub struct Draft {
    context: Option<Context>,
    started: bool,
    text: Option<String>,
}
impl Draft {
    pub fn context(&self) -> Option<Context> {
        self.context
    }
    pub fn started(&self) -> bool {
        self.started
    }
    /// Editing preserves the original destination, including while too large
    /// to retain a bounded copy. Clearing is an explicit volatile discard only.
    pub fn edit(&mut self, text: &str, current: Option<Context>) -> Result<(), &'static str> {
        if text.is_empty() {
            *self = Self::default();
            return Ok(());
        }
        if !self.started {
            self.context = current;
            self.started = true;
        }
        if text.len() > MAX_TEXT_BYTES {
            self.text = None;
            return Err("Draft exceeds 4,096 UTF-8 bytes; its original destination is preserved.");
        }
        self.text = Some(text.into());
        Ok(())
    }
    /// Only this explicit destination action moves retained text to a new scope.
    pub fn use_here(&mut self, text: &str, current: Context) -> Result<(), &'static str> {
        Text::new(text).map_err(|_| "Write valid public text before selecting its destination.")?;
        self.context = Some(current);
        self.started = true;
        self.text = Some(text.into());
        Ok(())
    }
    pub fn queue_text(&self, text: &str, current: Context) -> Result<Text, &'static str> {
        if self.context != Some(current) || self.text.as_deref() != Some(text) {
            return Err("This text is not bound to the selected room and author. Review the destination, then choose Use text in selected room explicitly.");
        }
        Text::new(text).map_err(|_| "Write 1–4,096 UTF-8 bytes of valid public text.")
    }
    pub fn clear_saved(&mut self) {
        *self = Self::default();
    }
}
