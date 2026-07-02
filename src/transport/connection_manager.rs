use crate::command::Command;
use crate::metrics::RETRIED_REQUESTS;
use crate::transport::{
    Connection, ConnectionMap, HopByHopIdMapper, RoundRobinConnection, RoutingConnectionManager,
};
use log::{error, info};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

pub struct ConnectionManager {
    // Fields for managing multiple connections
    per_conn_timeout: Duration,
    total_timeout: Duration,
    connections: ConnectionMap,
    host_realm_connections: HashMap<String, Arc<Box<RoundRobinConnection>>>,
    routing_manager: Option<RoutingConnectionManager>,
    hop_by_hop_id_mapper: Arc<HopByHopIdMapper>,
    retryable_result_codes: Vec<u32>, // List of retryable result codes
}

impl ConnectionManager {
    pub fn new(
        per_conn_timeout: Duration,
        total_timeout: Duration,
        routing_manager: Option<RoutingConnectionManager>,
        hop_by_hop_id_mapper: Arc<HopByHopIdMapper>,
        retryable_result_codes: Vec<u32>,
    ) -> Self {
        ConnectionManager {
            per_conn_timeout,
            total_timeout,
            connections: HashMap::new(),
            host_realm_connections: HashMap::new(),
            routing_manager: routing_manager,
            hop_by_hop_id_mapper: hop_by_hop_id_mapper,
            retryable_result_codes,
        }
    }

    /// Returns the total number of active connections in the connection manager.
    pub fn connection_count(&self) -> usize {
        self.connections.len()
    }

    pub async fn add_connection(&mut self, connection: Arc<Box<dyn Connection + Send + Sync>>) {
        let id = connection.get_id();
        let host = connection.get_peer_host().unwrap_or_default();
        let realm = connection.get_peer_realm().unwrap_or_default();
        let host_realm_key = format!("{}@{}", host, realm);

        info!(
            "Adding connection with ID: {}, host: {}, realm: {} to connection manager",
            id, host, realm
        );
        self.connections.insert(id.clone(), connection.clone());

        if let Some(routing_manager) = &self.routing_manager {
            routing_manager.add_connection(connection.clone()).await;
        }

        match self.host_realm_connections.get(&host_realm_key) {
            Some(conn) => {
                info!(
                    "Found existing round robin connection for host: {}, realm: {}. Adding connection to it.",
                    host, realm
                );
                conn.add_connection(connection.clone()).await;
            }
            None => {
                info!(
                    "No existing round robin connection for host: {}, realm: {}. Creating a new one.",
                    host, realm
                );
                let new_conn = Arc::new(Box::new(RoundRobinConnection::new(vec![])));
                self.host_realm_connections
                    .insert(host_realm_key.clone(), new_conn.clone());
                new_conn.add_connection(connection.clone()).await;
            }
        }
    }

    pub async fn remove_connection(&mut self, connection: Arc<Box<dyn Connection + Send + Sync>>) {
        // Remove a connection from the manager by its ID
        let id = connection.get_id();
        let host = connection.get_peer_host().unwrap_or_default();
        let realm = connection.get_peer_realm().unwrap_or_default();
        let host_realm = format!("{}@{}", host, realm);

        info!(
            "Removing connection with ID: {}, host: {}, realm: {}",
            id, host, realm
        );
        if let Some(routing_manager) = &mut self.routing_manager {
            routing_manager.remove_connection(connection.clone()).await;
        }
        self.host_realm_connections.remove(&realm);
        self.host_realm_connections.remove(&host_realm);
        self.connections.remove(&id);
    }

    pub async fn remove_connection_by_id(&mut self, id: &str) {
        if let Some(connection) = self.connections.remove(id) {
            let host = connection.get_peer_host().unwrap_or_default();
            let realm = connection.get_peer_realm().unwrap_or_default();
            let host_realm = format!("{}@{}", host, realm);
            if let Some(routing_manager) = &mut self.routing_manager {
                routing_manager.remove_connection(connection.clone()).await;
            }
            self.host_realm_connections.remove(&realm);
            self.host_realm_connections.remove(&host_realm);
        } else {
            error!(
                "Attempted to remove non-existent connection with ID: {}",
                id
            );
        }
    }

    pub async fn find_send_command(&self, command: &Command) -> Result<(), String> {
        let host = command.get_destination_host().unwrap_or_default();
        let realm = command.get_destination_realm().unwrap_or_default();
        let host_realm = format!("{}@{}", host, realm);
        let app_id = command.get_application_id();

        info!(
            "try to find connection for command with destination host: {}, realm: {}, app_id: {}",
            host, realm, app_id
        );

        // First try to find a connection that matches the host and realm
        if let Some(conn) = self.host_realm_connections.get(&host_realm) {
            info!(
                "Found direct connection for host: {}, realm: {}. Sending command through this connection.",
                host, realm
            );
            if conn.is_container() {
                let mut iter = conn.iter().unwrap();
                match tokio::time::timeout(
                    self.total_timeout,
                    Self::send_command_with_timeout(
                        command,
                        &mut *iter,
                        self.per_conn_timeout,
                        self.total_timeout,
                        &self.hop_by_hop_id_mapper,
                        &self.retryable_result_codes,
                    ),
                )
                .await
                {
                    Ok(result) => return result,
                    Err(_) => {
                        error!(
                            "Connection {} timed out after {:?}. Trying next connection...",
                            conn.get_id(),
                            self.total_timeout
                        );
                    }
                }
            } else {
                match tokio::time::timeout(self.total_timeout, conn.send(command)).await {
                    Ok(_) => return Ok(()),
                    Err(_) => {
                        error!(
                            "Connection {} timed out after {:?}. Trying next connection...",
                            conn.get_id(),
                            self.total_timeout
                        );
                    }
                }
            }
        } else if let Some(routing_manager) = &self.routing_manager {
            // Try to find a routing connection if no direct match is found
            info!(
                "try to find routing connection for command with destination host: {}, realm: {}, app_id: {}",
                host, realm, app_id
            );
            return routing_manager.find_send_command(command).await;
        }

        error!(
            "No available connection found for command with destination host: {}, realm: {}, app_id: {}",
            host, realm, app_id
        );
        Err("No available connection found".to_string())
    }

    async fn send_command_with_timeout(
        command: &Command,
        iter: &mut (dyn Iterator<Item = Arc<Box<dyn Connection + Send + Sync>>> + Send),
        per_conn_timeout: Duration,
        total_timeout: Duration,
        hop_by_hop_id_mapper: &Arc<HopByHopIdMapper>,
        retryable_result_codes: &Vec<u32>,
    ) -> Result<(), String> {
        let end_time = tokio::time::Instant::now() + total_timeout;

        loop {
            if end_time <= tokio::time::Instant::now() {
                return Err("Total timeout reached".to_string()); // Total timeout reached, return error
            }

            let conn = iter.next();

            if conn.is_none() {
                return Err("No more connections to try".to_string()); // No more connections to try, return error
            }
            let conn = conn.unwrap();

            match tokio::time::timeout(
                per_conn_timeout,
                Self::send_command(command, &conn, hop_by_hop_id_mapper),
            )
            .await
            {
                Ok(result) => match result {
                    Ok(result_code) => {
                        if retryable_result_codes.contains(&result_code) {
                            RETRIED_REQUESTS.inc();
                            error!(
                                "Connection {} returned retryable result code: {}. Trying next connection...",
                                conn.get_id(),
                                result_code
                            );
                        } else {
                            return Ok(()); // Command sent successfully and result code is not retryable
                        }
                    }
                    Err(e) => {
                        error!(
                            "Connection {} failed with error: {}. Trying next connection...",
                            conn.get_id(),
                            e
                        );
                    }
                },
                Err(_) => {
                    error!(
                        "Connection {} timed out after {:?}. Trying next connection...",
                        conn.get_id(),
                        per_conn_timeout
                    );
                }
            }
        }
    }

    /**
     * Sends a command through the specified connection and waits for the answer.
     * Returns the result code of the answer.
     */
    async fn send_command(
        command: &Command,
        conn: &Arc<Box<dyn Connection + Send + Sync>>,
        hop_by_hop_id_mapper: &Arc<HopByHopIdMapper>,
    ) -> Result<u32, String> {
        match conn.send(command).await {
            Ok(_) => {
                let result_code = hop_by_hop_id_mapper
                    .wait_for_answer(command.hop_by_hop_id)
                    .await;
                Ok(result_code)
            }
            Err(e) => {
                error!(
                    "Connection {} failed with error: {} in send_command_with_timeout. Trying next connection...",
                    conn.get_id(),
                    e
                );
                Err(e)
            }
        }
    }
}
