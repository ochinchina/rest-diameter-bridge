use crate::command::Command;
use crate::transport::{Connection, ConnectionIterator, ConnectionList};
use log::{error, info};
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;

pub struct RoundRobinConnection {
    id: String,
    host: String,
    realm: String,
    connections: Arc<ConnectionList>,
    index: Arc<AtomicUsize>,
}

impl RoundRobinConnection {
    pub fn new(connections: Vec<Arc<Box<dyn Connection + Send + Sync>>>) -> Self {
        RoundRobinConnection {
            id: "round_robin-".to_owned() + &uuid::Uuid::new_v4().to_string(),
            host: "round_robin-host".to_string() + uuid::Uuid::new_v4().to_string().as_str(),
            realm: "round_robin-realm".to_string() + uuid::Uuid::new_v4().to_string().as_str(),
            connections: Arc::new(ConnectionList::new(connections)),

            index: Arc::new(AtomicUsize::new(0)),
        }
    }
}

#[async_trait::async_trait]
impl Connection for RoundRobinConnection {
    fn get_id(&self) -> String {
        self.id.clone()
    }

    async fn send(&self, command: &Command) -> Result<(), String> {
        let iter = self.iter();
        if iter.is_none() {
            return Err("No available connections in round robin".to_string());
        }

        for conn in iter.unwrap() {
            match conn.send(command).await {
                Ok(_) => return Ok(()),
                Err(e) => {
                    error!(
                        "Connection {} failed with error: {} in RoundRobinConnection. Trying next connection...",
                        conn.get_id(),
                        e
                    );
                }
            }
        }
        Err("Fail to send command after trying all connections in round robin".to_string())
    }
    async fn close(&self) -> Result<(), String> {
        for conn in self.iter().unwrap() {
            if let Err(e) = conn.close().await {
                error!(
                    "Connection {} failed to close with error: {} in RoundRobinConnection. Trying next connection...",
                    conn.get_id(),
                    e
                );
            }
        }
        Ok(())
    }

    async fn add_connection(&self, connection: Arc<Box<dyn Connection + Send + Sync>>) {
        info!(
            "Adding connection with id: {} to round robin connection: {}",
            connection.get_id(),
            self.id
        );
        self.connections.add_connection(connection).await;
    }

    async fn remove_connection(&self, connection: Arc<Box<dyn Connection + Send + Sync>>) {
        let id = connection.get_id();
        info!(
            "Removing connection with id: {} from round robin connection: {}",
            id, self.id
        );
        self.connections.remove_connection(connection).await;
    }

    async fn is_closed(&self) -> bool {
        for conn in self.iter().unwrap() {
            if !conn.is_closed().await {
                return false;
            }
        }
        true
    }

    fn iter(
        &self,
    ) -> Option<Box<dyn Iterator<Item = Arc<Box<dyn Connection + Send + Sync>>> + Send>> {
        let n = self.connections.len();
        let index = self.index.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        if n == 0 {
            return None;
        }
        Some(Box::new(ConnectionIterator::new(
            self.connections.clone(),
            AtomicUsize::new(index % n),
        )))
    }

    fn is_container(&self) -> bool {
        true
    }

    fn get_peer_host(&self) -> Result<String, String> {
        Ok(self.host.clone())
    }

    fn get_peer_realm(&self) -> Result<String, String> {
        Ok(self.realm.clone())
    }
}
