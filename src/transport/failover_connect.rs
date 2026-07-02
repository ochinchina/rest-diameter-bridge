use crate::command::Command;
use crate::transport::{Connection, ConnectionIterator, ConnectionList};
use log::error;
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;

pub struct FailOverConnection {
    id: String,
    connections: Arc<ConnectionList>,
    index: Arc<std::sync::atomic::AtomicUsize>,
}

impl FailOverConnection {
    pub fn new(connections: Vec<Arc<Box<dyn Connection + Send + Sync>>>) -> Self {
        FailOverConnection {
            id: "failover-".to_owned() + &uuid::Uuid::new_v4().to_string(),
            connections: Arc::new(ConnectionList::new(connections)),
            index: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        }
    }
}

#[async_trait::async_trait]
impl Connection for FailOverConnection {
    fn get_id(&self) -> String {
        self.id.clone()
    }

    async fn send(&self, command: &Command) -> Result<(), String> {
        let connections = self.connections.get_connections().await;
        let n = connections.len();
        if n == 0 {
            return Err("No available connections in failover".to_string());
        }

        for i in 0..n {
            let index = (self.index.load(std::sync::atomic::Ordering::Relaxed) + i) % n;
            let conn = &connections[index];
            match conn.send(command).await {
                Ok(_) => {
                    self.index
                        .store((index + 1) % n, std::sync::atomic::Ordering::Relaxed); // Move to the next connection for the next command
                    return Ok(());
                }
                Err(e) => {
                    error!(
                        "Connection {} failed with error: {} in FailOverConnection. Trying next connection...",
                        conn.get_id(),
                        e
                    );
                }
            }
        }
        Err("Fail to send command after trying all connections in failover".to_string())
    }

    async fn close(&self) -> Result<(), String> {
        for conn in self.iter().unwrap() {
            if let Err(e) = conn.close().await {
                error!(
                    "Connection {} failed to close with error: {} in FailOverConnection.",
                    conn.get_id(),
                    e
                );
            }
        }
        Ok(())
    }

    async fn add_connection(&self, connection: Arc<Box<dyn Connection + Send + Sync>>) {
        self.connections.add_connection(connection).await;
    }

    async fn remove_connection(&self, connection: Arc<Box<dyn Connection + Send + Sync>>) {
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
        if self.connections.len() == 0 {
            return None;
        }
        Some(Box::new(ConnectionIterator::new(
            self.connections.clone(),
            AtomicUsize::new(0),
        )))
    }

    fn is_container(&self) -> bool {
        true
    }

    fn get_peer_host(&self) -> Result<String, String> {
        Ok("failover".to_string())
    }

    fn get_peer_realm(&self) -> Result<String, String> {
        Ok("failover".to_string())
    }
}
