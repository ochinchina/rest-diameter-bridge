use log::error;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::Mutex;
pub struct HopByHopIdMapper {
    map: Mutex<HashMap<u32, (u32, std::time::Instant)>>,
    next_cleanup_time: Arc<Mutex<Instant>>,
}

impl HopByHopIdMapper {
    pub fn new() -> Self {
        HopByHopIdMapper {
            map: Mutex::new(HashMap::new()),
            next_cleanup_time: Arc::new(Mutex::new(
                Instant::now() + std::time::Duration::from_secs(30),
            )),
        }
    }

    /// add a mapping from a new hop-by-hop ID to the original hop-by-hop ID.
    /// This method is called when sending a request, and it adds a mapping from the new hop-by-hop ID to the original hop-by-hop ID, along with a timeout for the mapping.
    /// # Arguments
    /// * `new_hop_by_hop_id` - The new hop-by-hop ID that was generated for the request.
    /// * `original_hop_by_hop_id` - The original hop-by-hop ID that was in the request.    
    pub async fn add_mapping(&self, new_hop_by_hop_id: u32, original_hop_by_hop_id: u32) {
        self.clean_expired_entries().await;

        let mut map = self.map.lock().await;
        map.insert(
            new_hop_by_hop_id,
            (
                original_hop_by_hop_id,
                std::time::Instant::now() + std::time::Duration::from_secs(300),
            ),
        );
    }

    /// Removes the mapping for the given new hop-by-hop ID and returns the original hop-by-hop ID that was mapped to it.
    /// This method is called when receiving an answer, and it removes the mapping for the new hop-by-hop ID and returns the original hop-by-hop ID that was mapped to it.
    /// # Arguments
    /// * `new_hop_by_hop_id` - The new hop-by-hop ID for which to remove the mapping.
    /// # Returns
    /// * `Option<u32>` - The original hop-by-hop ID that was mapped to the given new hop-by-hop ID, or None if no mapping was found.
    pub async fn remove_mapping(&self, new_hop_by_hop_id: u32) -> Option<u32> {
        let mut map = self.map.lock().await;

        if let Some((original_id, timeout)) = map.remove(&new_hop_by_hop_id) {
            if timeout < std::time::Instant::now() {
                error!(
                    "Mapping for new hop-by-hop ID {} has expired. Removing it.",
                    new_hop_by_hop_id
                );
                None
            } else {
                Some(original_id)
            }
        } else {
            None
        }
    }

    pub async fn get_original_id(&self, new_hop_by_hop_id: &u32) -> Option<u32> {
        let map = self.map.lock().await;
        if let Some((original_id, timeout)) = map.get(new_hop_by_hop_id) {
            if *timeout < std::time::Instant::now() {
                None
            } else {
                Some(*original_id)
            }
        } else {
            None
        }
    }

    async fn clean_expired_entries(&self) {
        {
            let now = std::time::Instant::now();
            let mut next_cleanup_time = self.next_cleanup_time.lock().await;
            if next_cleanup_time.gt(&now) {
                return;
            }

            *next_cleanup_time = now + std::time::Duration::from_secs(30);
        }

        let mut map = self.map.lock().await;

        map.retain(|new_id, (_original_id, timeout)| {
            if *timeout < std::time::Instant::now() {
                error!(
                    "Mapping for new hop-by-hop ID {} has expired. Removing it.",
                    new_id
                );
                false
            } else {
                true
            }
        });
    }
}
