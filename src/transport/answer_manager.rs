use crate::command::Command;
use log::error;
use log::info;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::Mutex;
use tokio::sync::Notify;

struct AnswerInfo {
    // The connection ID from which the command was sent. This is used to identify the connection when the answer is received.
    connection_id: String,
    // the host for which the answer is intended. This is used to identify the connection when the answer is received.
    answer_host: String,
    // the realm for which the answer is intended. This is used to identify the connection when the answer is received.
    answer_realm: String,
    notify: Arc<Notify>,
    answer: Arc<Mutex<Option<Command>>>,
    timeout: std::time::Instant,
}

impl AnswerInfo {
    fn new(
        connection_id: String,
        answer_host: String,
        answer_realm: String,
        timeout: std::time::Instant,
    ) -> Self {
        AnswerInfo {
            connection_id: connection_id,
            answer_host: answer_host,
            answer_realm: answer_realm,
            notify: Arc::new(Notify::new()),
            answer: Arc::new(Mutex::new(None)),
            timeout,
        }
    }

    async fn set_answer(&self, answer: Command) {
        {
            let mut answer_lock = self.answer.lock().await;
            *answer_lock = Some(answer);
        }
        self.notify.notify_one();
    }

    async fn wait_answer(&self) -> Option<Command> {
        self.notify.notified().await;
        let answer_lock = self.answer.lock().await;
        answer_lock.clone()
    }

    fn is_expired(&self) -> bool {
        std::time::Instant::now() > self.timeout
    }
}
pub struct AnswerManager {
    // A mapping hop_by_hop_id to AnswerInfo, which contains the original hop-by-hop ID and other information needed to handle the answer.
    map: Mutex<HashMap<u32, Arc<Box<AnswerInfo>>>>,
    next_cleanup_time: Arc<Mutex<Instant>>,
}

impl AnswerManager {
    pub fn new() -> Self {
        AnswerManager {
            map: Mutex::new(HashMap::new()),
            next_cleanup_time: Arc::new(Mutex::new(
                Instant::now() + std::time::Duration::from_secs(30),
            )),
        }
    }

    pub async fn prepare_for_answer(
        &self,
        hop_by_hop_id: u32,
        connection_id: String,
        answer_host: String,
        answer_realm: String,
    ) {
        self.clean_expired_entries().await;

        info!(
            "Preparing for answer: hop_by_hop_id={}, connection_id={}, answer_host={}, answer_realm={}",
            hop_by_hop_id, connection_id, answer_host, answer_realm
        );
        let answer_info = Arc::new(Box::new(AnswerInfo::new(
            connection_id,
            answer_host,
            answer_realm,
            std::time::Instant::now() + std::time::Duration::from_secs(60),
        )));
        let mut map = self.map.lock().await;
        map.insert(hop_by_hop_id,answer_info);
    }

    pub async fn wait_answer(&self, hop_by_hop_id: u32) -> Option<Command> {
        info!("Waiting for answer: hop_by_hop_id={}", hop_by_hop_id);
        if let Some(info) = self.get_answer_info(hop_by_hop_id).await {
            info.wait_answer().await            
        } else {
            None
        }
    }

    /// Cleans up expired entries from the map. This is called periodically to remove entries that have timed out.
    /// # Arguments
    /// * `answer` - The answer received for the request. This is used to determine if the entry should be removed from the map.
    /// # Returns
    /// * `Option<(String, String, String)>` - The connection ID, origin host, and origin realm associated with the hop-by-hop ID, or None if no mapping was found.
    pub async fn answer_received(&self, answer: Command) -> Option<(String, String, String)> {
        if let Some(info) = self.get_answer_info(answer.hop_by_hop_id).await {
            info.set_answer(answer).await;
            Some((
                info.connection_id.clone(),
                info.answer_host.clone(),
                info.answer_realm.clone(),
            ))
        } else {
            error!(
                "No mapping found for hop-by-hop ID {} when trying to set answer",
                answer.hop_by_hop_id
            );
            None
        }
    }

    async fn get_answer_info(&self, hop_by_hop_id: u32) -> Option<Arc<Box<AnswerInfo>>> {
        let map = self.map.lock().await;
        map.get(&hop_by_hop_id).map(|info| info.clone())
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

        map.retain(|hop_by_hop_id, info| {
            if info.is_expired() {
                error!(
                    "Mapping for hop-by-hop ID {} has expired. Removing it.",
                    hop_by_hop_id
                );
                false
            } else {
                true
            }
        });
    }
}
