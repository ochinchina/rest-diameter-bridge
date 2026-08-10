use crate::command::Command;
use std::sync::Arc;

#[async_trait::async_trait]
pub trait Connection: Send + Sync {
    fn get_id(&self) -> String; // Unique identifier for the connection, e.g., "host:port"    

    /// Sends a command over the connection. The command is expected to be a Diameter command.
    /// # Arguments
    /// * `command` - The Diameter command to be sent.
    /// * `per_connection_timeout` - The command timeout duration for one connection.
    /// * `timeout_time` - The absolute time at which the operation should time out.
    /// # Returns
    /// * `Ok(())` if the command was sent successfully.
    /// * `Err(String)` if there was an error sending the command, with a descriptive error message.
    async fn send(&self, command: &Command) -> Result<(), String>;
    async fn close(&self) -> Result<(), String>;
    async fn is_closed(&self) -> bool;

    // get the peer host and realm for this connection, which may be needed for routing or other purposes
    fn get_peer_host(&self) -> Result<String, String>;
    fn get_peer_realm(&self) -> Result<String, String>;

    /// Adds a new connection to the container. This is only applicable for load balancer connections that manage multiple underlying connections.
    /// The default implementation does nothing, and should be overridden by load balancer connections.
    async fn add_connection(&self, _connection: Arc<Box<dyn Connection + Send + Sync>>) {
        // Default implementation does nothing, can be overridden by load balancer connections
    }

    /// Removes a connection from the container. This is only applicable for load balancer connections that manage multiple underlying connections.
    /// The default implementation does nothing, and should be overridden by load balancer connections.
    async fn remove_connection(&self, _connection: Arc<Box<dyn Connection + Send + Sync>>) {
        // Default implementation does nothing, can be overridden by load balancer connections
    }

    /// Returns true if this connection is a container (i.e., a load balancer connection that manages multiple underlying connections).
    /// The default implementation returns false, and should be overridden by load balancer connections.
    fn is_container(&self) -> bool {
        false // Default implementation returns false, can be overridden by load balancer connections
    }

    /// Returns a list of underlying connections if this connection is a container (i.e., a load balancer connection that manages multiple underlying connections).
    async fn get_connections(&self, _connections: &mut Vec<Arc<Box<dyn Connection + Send + Sync>>>);

    /// Returns an iterator over the underlying connections if this connection is a container (i.e., a load balancer connection that manages multiple underlying connections).
    /// The default implementation returns None, and should be overridden by load balancer connections.
    /// The iterator should yield Arc<Box<dyn Connection + Send + Sync>> for each underlying connection.
    /// The default implementation returns None, and should be overridden by load balancer connections.
    /// # Returns
    /// - Some(iterator) if this connection is a container and has underlying connections.
    /// - None if this connection is not a container or has no underlying connections.
    fn iter(
        &self,
    ) -> Option<Box<dyn Iterator<Item = Arc<Box<dyn Connection + Send + Sync>>> + Send>> {
        // Default implementation returns an empty iterator, can be overridden by load balancer connections
        None
    }
}

pub async fn get_underlying_connections(
    connection: Arc<Box<dyn Connection + Send + Sync>>,
) -> Vec<Arc<Box<dyn Connection + Send + Sync>>> {
    let mut connections = Vec::new();
    let mut checking_connections = vec![connection];

    loop {
        if checking_connections.is_empty() {
            break;
        }
        let current = checking_connections.pop().unwrap();
        if current.is_container() {
            current.get_connections(&mut checking_connections).await;
        } else {
            connections.push(current.clone());
        }
    }

    connections
}
