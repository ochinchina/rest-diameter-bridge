use crate::command::Command;
use crate::transport::{Connection, ConnectionIterator, ConnectionList};
use log::error;
use rand::prelude::*;
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;

pub struct RandomConnection {
    id: String,
    host: String,
    realm: String,
    connections: Arc<ConnectionList>,
}

impl RandomConnection {
    pub fn new(connections: Vec<Arc<Box<dyn Connection + Send + Sync>>>) -> Self {
        RandomConnection {
            id: "random-".to_owned() + &uuid::Uuid::new_v4().to_string(),
            host: "random-host".to_string() + uuid::Uuid::new_v4().to_string().as_str(),
            realm: "random-realm".to_string() + uuid::Uuid::new_v4().to_string().as_str(),
            connections: Arc::new(ConnectionList::new(connections)),
        }
    }
}

#[async_trait::async_trait]
impl Connection for RandomConnection {
    fn get_id(&self) -> String {
        self.id.clone()
    }

    async fn send(&self, command: &Command) -> Result<(), String> {
        let iter = self.iter();
        if iter.is_none() {
            return Err("No available connections in random strategy".to_string());
        }
        for conn in iter.unwrap() {
            match conn.send(command).await {
                Ok(_) => return Ok(()),
                Err(e) => {
                    error!(
                        "Connection {} failed with error: {} in RandomConnection. Trying next connection...",
                        conn.get_id(),
                        e
                    );
                }
            }
        }
        Err("Fail to send command after trying all connections in random strategy".to_string())
    }

    async fn add_connection(&self, connection: Arc<Box<dyn Connection + Send + Sync>>) {
        self.connections.add_connection(connection).await;
    }

    async fn remove_connection(&self, connection: Arc<Box<dyn Connection + Send + Sync>>) {
        self.connections.remove_connection(connection).await;
    }

    async fn close(&self) -> Result<(), String> {
        for conn in self.iter().unwrap() {
            if let Err(e) = conn.close().await {
                error!(
                    "Connection {} failed to close with error: {} in RandomConnection. Trying next connection...",
                    conn.get_id(),
                    e
                );
            }
        }
        Ok(())
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

        if n == 0 {
            return None;
        }

        Some(Box::new(ConnectionIterator::new(
            self.connections.clone(),
            AtomicUsize::new(rand::rng().random_range(0..n)),
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
