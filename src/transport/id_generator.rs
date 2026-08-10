use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

/// A thread-safe, monotonically increasing 32-bit ID generator.
///
/// Used to allocate unique hop-by-hop and end-to-end identifiers for Diameter commands.
#[derive(Clone)]
pub struct IdGenerator {
    current_id: Arc<AtomicU32>,
}

impl IdGenerator {
    /// Creates a new `IdGenerator` starting at zero.
    pub fn new() -> Self {
        IdGenerator {
            current_id: Arc::new(AtomicU32::new(0)),
        }
    }

    /// Atomically increments the internal counter and returns the previous value.
    pub fn next_id(&self) -> u32 {
        self.current_id.fetch_add(1, Ordering::Relaxed)
    }
}
