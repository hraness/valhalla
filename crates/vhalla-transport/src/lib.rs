#![no_std]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

//! Transport owns delivery, not identity or authority.

extern crate alloc;

use alloc::collections::VecDeque;
use alloc::vec::Vec;

/// Maximum frame size used by the prototype transport.
pub const MAX_FRAME_BYTES: usize = 64 * 1024;

/// An opaque bounded frame. The transport cannot inspect or authorize it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Frame(Vec<u8>);

impl Frame {
    /// Construct a frame if it fits the transport bound.
    pub fn new(bytes: &[u8]) -> Result<Self, TransportError> {
        if bytes.len() > MAX_FRAME_BYTES {
            return Err(TransportError::FrameTooLarge {
                actual: bytes.len(),
                limit: MAX_FRAME_BYTES,
            });
        }
        Ok(Self(bytes.to_vec()))
    }

    /// Borrow the opaque bytes for the application decoder.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Delivery path selected by the host.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Path {
    /// Direct peer path.
    Direct,
    /// Relay-backed path.
    Relay,
}

/// Bounded transport failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransportError {
    /// Frame exceeded the transport bound.
    FrameTooLarge {
        /// Number of supplied bytes.
        actual: usize,
        /// Maximum allowed bytes.
        limit: usize,
    },
    /// The receiver queue is full and backpressure must be applied.
    QueueFull,
}

/// A transport endpoint interface that carries only opaque frames.
pub trait Endpoint {
    /// Send one bounded frame.
    fn send(&mut self, frame: Frame) -> Result<(), TransportError>;
    /// Receive the next frame, if available.
    fn recv(&mut self) -> Option<Frame>;
}

/// Deterministic in-memory relay used by the steel thread and tests.
pub struct InMemoryRelay {
    max_queue: usize,
    queue: VecDeque<Frame>,
    path: Path,
}

impl InMemoryRelay {
    /// Create a relay with a bounded queue and explicit delivery path label.
    #[must_use]
    pub fn new(max_queue: usize, path: Path) -> Self {
        Self {
            max_queue,
            queue: VecDeque::new(),
            path,
        }
    }

    /// Return the configured path label; it has no authority meaning.
    #[must_use]
    pub const fn path(&self) -> Path {
        self.path
    }
}

impl Endpoint for InMemoryRelay {
    fn send(&mut self, frame: Frame) -> Result<(), TransportError> {
        if self.queue.len() >= self.max_queue {
            return Err(TransportError::QueueFull);
        }
        self.queue.push_back(frame);
        Ok(())
    }

    fn recv(&mut self) -> Option<Frame> {
        self.queue.pop_front()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn transport_preserves_opaque_bytes_and_path_is_only_metadata() {
        let mut relay = InMemoryRelay::new(1, Path::Relay);
        relay.send(Frame::new(b"signed bytes").unwrap()).unwrap();
        assert_eq!(relay.path(), Path::Relay);
        assert_eq!(relay.recv().unwrap().as_bytes(), b"signed bytes");
    }

    #[test]
    fn queue_and_frame_bounds_fail_closed() {
        let mut relay = InMemoryRelay::new(1, Path::Direct);
        assert_eq!(
            Frame::new(&vec![0; MAX_FRAME_BYTES + 1]),
            Err(TransportError::FrameTooLarge {
                actual: MAX_FRAME_BYTES + 1,
                limit: MAX_FRAME_BYTES
            })
        );
        relay.send(Frame::new(b"one").unwrap()).unwrap();
        assert_eq!(
            relay.send(Frame::new(b"two").unwrap()),
            Err(TransportError::QueueFull)
        );
    }
}
