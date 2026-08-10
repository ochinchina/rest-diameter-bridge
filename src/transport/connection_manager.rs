use crate::avp::ResultCode;
use crate::command::Command;
use crate::metrics::RETRIED_REQUESTS;
use crate::transport::{
    AnswerManager, Connection, RedirectHostManager, RoundRobinConnection, RoutingConnectionManager,
    get_underlying_connections,
};
use log::{error, info};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;

/// A type alias for the map that stores active connections keyed by their unique ID.
pub type ConnectionMap = std::collections::HashMap<String, Arc<Box<dyn Connection + Send + Sync>>>;

/// Manages the full set of Diameter peer connections for a stack instance.
///
/// Handles connection registration, removal, routing, hop-by-hop ID remapping, and
/// per-request timeouts with optional retry on transient errors.
pub struct ConnectionManager {
    // Fields for managing multiple connections
    per_conn_timeout: Duration,
    total_timeout: Duration,
    connections: Arc<Mutex<ConnectionMap>>,
    host_realm_connections: Arc<Mutex<HashMap<String, Arc<Box<dyn Connection + Send + Sync>>>>>,
    routing_manager: Option<RoutingConnectionManager>,
    answer_manager: Arc<Box<AnswerManager>>,
    retryable_result_codes: Vec<u32>, // List of retryable result codes
    redirect_host_manager: Arc<Box<RedirectHostManager>>,
}

impl ConnectionManager {
    /// Creates a new `ConnectionManager`.
    ///
    /// # Arguments
    /// * `per_conn_timeout` - Maximum time to wait for a single connection attempt before moving to the next.
    /// * `total_timeout` - Maximum total time budget across all connection attempts for one request.
    /// * `routing_manager` - Optional routing manager for policy-based next-hop selection.
    /// * `answer_manager` - Shared manager for handling answers to requests.
    /// * `retryable_result_codes` - Diameter result codes that should trigger a retry on another connection.
    pub fn new(
        per_conn_timeout: Duration,
        total_timeout: Duration,
        routing_manager: Option<RoutingConnectionManager>,
        answer_manager: Arc<Box<AnswerManager>>,
        retryable_result_codes: Vec<u32>,
        redirect_host_manager: Arc<Box<RedirectHostManager>>,
    ) -> Self {
        ConnectionManager {
            per_conn_timeout,
            total_timeout,
            connections: Arc::new(Mutex::new(ConnectionMap::new())),
            host_realm_connections: Arc::new(Mutex::new(HashMap::new())),
            routing_manager: routing_manager,
            answer_manager: answer_manager,
            retryable_result_codes,
            redirect_host_manager: redirect_host_manager,
        }
    }

    /// Returns the total number of active connections in the connection manager.
    pub async fn connection_count(&self) -> usize {
        self.connections.lock().await.len()
    }

    /// Adds a new connection to the connection manager. If a RoundRobinConnection already exists for the given host and realm, the new connection is added to it. Otherwise, a new RoundRobinConnection is created and the new connection is added to it.
    /// # Arguments
    /// * `connection` - An Arc-wrapped Box containing a type that implements the Connection trait. This is the connection to be added to the manager.
    pub async fn add_connection(&self, connection: Arc<Box<dyn Connection + Send + Sync>>) {
        let id = connection.get_id();
        let host = connection.get_peer_host().unwrap_or_default();
        let realm = connection.get_peer_realm().unwrap_or_default();
        let host_realm_key = format!("{}@{}", host, realm);

        info!(
            "Adding connection with ID: {}, host: {}, realm: {} to connection manager",
            id, host, realm
        );

        // If a routing manager is present, add the connection to it as well. This allows the routing manager to manage connections for routing purposes.
        if let Some(routing_manager) = &self.routing_manager {
            routing_manager.add_connection(connection.clone()).await;
        }
        let mut connections = self.connections.lock().await;
        connections.insert(id.clone(), connection.clone());

        let mut host_realm_connections = self.host_realm_connections.lock().await;
        // Check if a RoundRobinConnection already exists for the given host and realm. If it does, add the new connection to it. If not, create a new RoundRobinConnection and add the new connection to it.
        match host_realm_connections.get(&host_realm_key) {
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
                let new_conn = Box::new(RoundRobinConnection::new("unknown-peer".to_string(), "unknown-realm".to_string(), vec![]))
                    as Box<dyn Connection + Send + Sync>;
                let new_conn = Arc::new(new_conn);

                host_realm_connections.insert(host_realm_key.clone(), new_conn.clone());
                new_conn.add_connection(connection.clone()).await;
            }
        }
    }

    /// Removes a connection from the connection manager. If the connection is part of a RoundRobinConnection, it is removed from that as well. If the RoundRobinConnection becomes empty after removal, it is also removed from the manager.
    /// # Arguments
    /// * `connection` - An Arc-wrapped Box containing a type that implements the Connection trait. This is the connection to be removed from the manager.
    pub async fn remove_connection(&self, connection: Arc<Box<dyn Connection + Send + Sync>>) {
        // Remove a connection from the manager by its ID
        let id = connection.get_id();
        let host = connection.get_peer_host().unwrap_or_default();
        let realm = connection.get_peer_realm().unwrap_or_default();
        let host_realm = format!("{}@{}", host, realm);

        info!(
            "Removing connection with ID: {}, host: {}, realm: {}",
            id, host, realm
        );
        if let Some(routing_manager) = &self.routing_manager {
            routing_manager.remove_connection(connection.clone()).await;
        }
        let mut host_realm_connections = self.host_realm_connections.lock().await;
        host_realm_connections.remove(&realm);
        host_realm_connections.remove(&host_realm);

        self.connections.lock().await.remove(&id);
    }

    /// Removes the connection whose ID equals `id` from the manager and from any associated routing entries.
    pub async fn remove_connection_by_id(&self, id: &str) {
        if let Some(connection) = self.connections.lock().await.remove(id) {
            let host = connection.get_peer_host().unwrap_or_default();
            let realm = connection.get_peer_realm().unwrap_or_default();
            let host_realm = format!("{}@{}", host, realm);
            if let Some(routing_manager) = &self.routing_manager {
                routing_manager.remove_connection(connection.clone()).await;
            }
            let mut host_realm_connections = self.host_realm_connections.lock().await;
            host_realm_connections.remove(&realm);
            host_realm_connections.remove(&host_realm);
        } else {
            error!(
                "Attempted to remove non-existent connection with ID: {}",
                id
            );
        }
    }

    /// send a request through the connection manager. It will find the appropriate connection based on the destination host and realm specified in the command. If a direct connection is found, it sends the command through that connection. If no direct connection is found, it attempts to find a routing connection if a routing manager is present. If no suitable connection is found, it returns an error.
    /// # Arguments
    /// * `request` - A reference to the Command that needs to be sent. The command contains information about the destination host and realm.
    /// # Returns
    /// * `Result<Command, String>` - Returns Ok(Command) if the request is sent successfully, or an Err(String) with an error message if no suitable connection is found or if sending the command fails.
    pub async fn send_request(&self, request: &Command) -> Result<Command, String> {
        let connections = self.get_connections_for_request(request).await?;
        let timeout_time = tokio::time::Instant::now() + self.total_timeout;

        for conn in connections {
            match Self::send_request_with_timeout(
                request,
                &conn,
                self.per_conn_timeout,
                timeout_time,
                &self.answer_manager,
                &self.retryable_result_codes,
            )
            .await
            {
                Ok(answer) => {
                    let result_code = answer
                        .get_result_code()
                        .unwrap_or(ResultCode::DiameterSuccess as u32);
                    if result_code == ResultCode::DiameterRedirectIndication.as_u32() {
                        info!(
                            "Connection {} returned DiameterRedirectIndication for command with hop-by-hop ID {}. This may trigger a retry on another connection.",
                            conn.get_id(),
                            request.hop_by_hop_id
                        );
                        self.redirect_host_manager.add_redirect(&answer).await;
                        if let Some(redirect_hosts) = answer.get_redirect_hosts() {
                            info!(
                                "Redirect hosts received: {:?}. Updating redirect host manager.",
                                redirect_hosts
                            );
                            if let Some(connections) =
                                self.get_connections_by_hosts(&redirect_hosts).await
                            {
                                info!(
                                    "Found {} connections for redirect hosts {:?}. Retrying request through these connections.",
                                    connections.len(),
                                    redirect_hosts
                                );
                                return self
                                    .redirect_request(request, &connections, timeout_time)
                                    .await;
                            } else {
                                error!(
                                    "No available connections found for redirect hosts: {:?}",
                                    redirect_hosts
                                );
                                return Err(
                                    "No available connections found for redirect hosts".to_string()
                                );
                            }
                        }
                    } else {
                        return Ok(answer); // Command sent successfully and result code is not retryable
                    }
                }
                Err(e) => {
                    error!(
                        "Connection {} failed with error: {} in find_send_command. Trying next connection...",
                        conn.get_id(),
                        e
                    );
                }
            }
            if timeout_time <= tokio::time::Instant::now() {
                return Err("Total timeout reached".to_string());
            }
        }

        Err("Fail to send command".to_string())
    }

    async fn redirect_request(
        &self,
        request: &Command,
        connections: &Vec<Arc<Box<dyn Connection + Send + Sync>>>,
        timeout_time: tokio::time::Instant,
    ) -> Result<Command, String> {
        for conn in connections {
            match Self::send_request_with_timeout(
                request,
                &conn,
                self.per_conn_timeout,
                timeout_time,
                &self.answer_manager,
                &self.retryable_result_codes,
            )
            .await
            {
                Ok(answer) => {
                    return Ok(answer); // Command sent successfully through redirect connection
                }
                Err(e) => {
                    error!(
                        "Connection {} failed with error: {} in redirect_request. Trying next connection...",
                        conn.get_id(),
                        e
                    );
                }
            }
            if timeout_time <= tokio::time::Instant::now() {
                return Err("Total timeout reached".to_string());
            }
        }
        Err("Fail to send command after redirect".to_string())
    }

    /// Sends `response` back through the connection identified by `connection_id` (or falls back
    /// to a connection matching `host`/`realm` if the primary ID is not found).
    ///
    /// # Arguments
    /// * `connection_id` - The ID of the inbound connection that originally delivered the request.
    /// * `host` - Destination Diameter host for fallback lookup.
    /// * `realm` - Destination Diameter realm for fallback lookup.
    /// * `response` - The answer command to be transmitted.
    pub async fn send_response(
        &self,
        connection_id: &str,
        host: &str,
        realm: &str,
        response: &Command,
    ) -> Result<(), String> {
        if let Some(connection) =
            if let Some(connection) = self.get_connection_by_id(connection_id).await {
                Some(connection)
            } else if let Some(connection) = self.get_connection_by_host_realm(host, realm).await {
                Some(connection)
            } else {
                None
            }
        {
            match connection.send(response).await {
                Ok(_) => Ok(()),
                Err(e) => {
                    error!(
                        "Connection {} failed with error: {} in send_response.",
                        connection.get_id(),
                        e
                    );
                    Err(e)
                }
            }
        } else {
            error!(
                "No available connection found for response with connection_id: {}, host: {}, realm: {}",
                connection_id, host, realm
            );
            Err("No available connection found".to_string())
        }
    }

    async fn get_connection_by_id(
        &self,
        connection_id: &str,
    ) -> Option<Arc<Box<dyn Connection + Send + Sync>>> {
        let connections = self.connections.lock().await;
        connections.get(connection_id).cloned()
    }

    async fn get_connection_by_host_realm(
        &self,
        host: &str,
        realm: &str,
    ) -> Option<Arc<Box<dyn Connection + Send + Sync>>> {
        let host_realm = format!("{}@{}", host, realm);
        let host_realm_connections = self.host_realm_connections.lock().await;
        host_realm_connections.get(&host_realm).cloned()
    }

    async fn get_redirect_connections(
        &self,
        request: &Command,
    ) -> Option<Vec<Arc<Box<dyn Connection + Send + Sync>>>> {
        if let Some(redirect_hosts) = self.redirect_host_manager.get_redirect(request).await {
            let connections = self.connections.lock().await;
            let matching_connections = connections
                .values()
                .filter(|conn| redirect_hosts.contains(&conn.get_peer_host().unwrap_or_default()))
                .cloned()
                .collect::<Vec<_>>();

            let mut result = vec![];

            for conn in &matching_connections {
                info!(
                    "Found redirect connection with ID: {}, host: {}, realm: {} for command with hop-by-hop ID {}",
                    conn.get_id(),
                    conn.get_peer_host().unwrap_or_default(),
                    conn.get_peer_realm().unwrap_or_default(),
                    request.hop_by_hop_id
                );
                result.append(&mut get_underlying_connections(conn.clone()).await);
            }
            if !result.is_empty() {
                return Some(result);
            }
        }
        None
    }

    async fn get_connections_by_hosts(
        &self,
        hosts: &Vec<String>,
    ) -> Option<Vec<Arc<Box<dyn Connection + Send + Sync>>>> {
        let connections = self.connections.lock().await;
        let connections = connections
            .values()
            .filter(|conn| hosts.contains(&conn.get_peer_host().unwrap_or_default()))
            .cloned()
            .collect::<Vec<_>>();

        let mut result = vec![];

        for conn in &connections {
            info!(
                "Found redirect connection with ID: {}, host: {}, realm: {}",
                conn.get_id(),
                conn.get_peer_host().unwrap_or_default(),
                conn.get_peer_realm().unwrap_or_default(),
            );
            result.append(&mut get_underlying_connections(conn.clone()).await);
        }

        if result.is_empty() {
            None
        } else {
            Some(result)
        }
    }

    async fn get_connections_for_request(
        &self,
        request: &Command,
    ) -> Result<Vec<Arc<Box<dyn Connection + Send + Sync>>>, String> {
        // If a redirect host is found for the request, filter the connections to only include those that match the redirect hosts.
        // If no matching connections are found, continue to look for direct or routing connections.
        if let Some(redirect_connections) = self.get_redirect_connections(request).await {
            info!(
                "Found redirect connections for command with destination host: {}, realm: {}",
                request.get_destination_host().unwrap_or_default(),
                request.get_destination_realm().unwrap_or_default()
            );
            return Ok(redirect_connections);
        }

        let host = request.get_destination_host().unwrap_or_default();
        let realm = request.get_destination_realm().unwrap_or_default();
        let host_realm = format!("{}@{}", host, realm);
        let app_id = request.get_application_id();

        info!(
            "try to find connection for command with destination host: {}, realm: {}, app_id: {}",
            host, realm, app_id
        );

        // First try to find a connection that matches the host and realm
        if let Some(conn) = self.host_realm_connections.lock().await.get(&host_realm) {
            info!(
                "Found direct connection for host: {}, realm: {}. Sending command through this connection.",
                host, realm
            );
            let connections = get_underlying_connections(conn.clone()).await;
            return Ok(connections);
        } else if let Some(routing_manager) = &self.routing_manager {
            // Try to find a routing connection if no direct match is found
            info!(
                "try to find routing connection for command with destination host: {}, realm: {}, app_id: {}",
                host, realm, app_id
            );
            let mut connections = vec![];
            routing_manager
                .get_connections_for_command(request, &mut connections)
                .await;
            return Ok(connections);
        }

        error!(
            "No available connection found for command with destination host: {}, realm: {}, app_id: {}",
            host, realm, app_id
        );
        Err("No available connection found".to_string())
    }

    /// Sends a request through the specified connection with a timeout. If the request fails or times out, it tries the next available connection until all connections have been tried or the total timeout is reached.
    /// # Arguments
    /// * `request` - A reference to the Command that needs to be sent.
    /// * `conn` - A reference to the connection through which the request will be sent.
    /// * `per_conn_timeout` - The timeout duration for each individual connection attempt.
    /// * `total_timeout` - The total timeout duration for the entire operation.
    /// * `answer_manager` - An Arc-wrapped AnswerManager used to wait for the answer of the command.
    /// * `retryable_result_codes` - A reference to a vector of result codes that are considered retryable. If a command returns one of these codes, the next connection will be tried.
    /// # Returns
    /// * `Result<u32, String>` - Returns Ok(result_code) if the request is sent successfully, or an Err(String) with an error message if all connections fail or the total timeout is reached.
    pub async fn send_request_with_timeout(
        request: &Command,
        conn: &Arc<Box<dyn Connection + Send + Sync>>,
        per_conn_timeout: Duration,
        timeout_time: tokio::time::Instant,
        answer_manager: &Arc<Box<AnswerManager>>,
        retryable_result_codes: &Vec<u32>,
    ) -> Result<Command, String> {
        let remaining = timeout_time.duration_since(tokio::time::Instant::now());
        if remaining <= Duration::from_secs(0) {
            return Err("Total timeout reached".to_string());
        }

        let per_conn_timeout = if remaining < per_conn_timeout {
            remaining
        } else {
            per_conn_timeout
        };

        match tokio::time::timeout(
            per_conn_timeout,
            Self::send_request_command(request, &conn, &answer_manager),
        )
        .await
        {
            Ok(result) => match result {
                Ok(answer) => {
                    let result_code = answer
                        .get_result_code()
                        .unwrap_or(ResultCode::DiameterSuccess as u32);

                    if retryable_result_codes.contains(&result_code) {
                        RETRIED_REQUESTS.inc();
                        error!(
                            "Connection {} returned retryable result code: {}. Trying next connection...",
                            conn.get_id(),
                            result_code
                        );
                        return Err(format!(
                            "Connection {} returned retryable result code: {}",
                            conn.get_id(),
                            result_code
                        ));
                    } else {
                        return Ok(answer); // Command sent successfully and result code is not retryable
                    }
                }
                Err(e) => {
                    error!(
                        "Connection {} failed with error: {}. Trying next connection...",
                        conn.get_id(),
                        e
                    );
                    return Err(e);
                }
            },
            Err(_) => {
                error!(
                    "Connection {} timed out after {:?}. Trying next connection...",
                    conn.get_id(),
                    per_conn_timeout
                );
                return Err(format!(
                    "Connection {} timed out after {:?}",
                    conn.get_id(),
                    per_conn_timeout
                ));
            }
        }
    }

    /// Sends a request through the specified connection and waits for the answer. If the request fails, it returns an error. This function is used internally by `send_request_with_timeout` to handle the actual sending of the command and waiting for the response.
    /// # Arguments
    /// * `request` - A reference to the Command that needs to be sent.
    /// * `conn` - An Arc-wrapped Box containing a type that implements the Connection trait. This is the connection through which the command will be sent.
    /// * `hop_by_hop_id_mapper` - An Arc-wrapped HopByHopIdMapper used to wait for the answer of the command.
    /// # Returns
    ///
    async fn send_request_command(
        request: &Command,
        conn: &Arc<Box<dyn Connection + Send + Sync>>,
        answer_manager: &Arc<Box<AnswerManager>>,
    ) -> Result<Command, String> {
        match conn.send(request).await {
            Ok(_) => {
                if let Some(answer) = answer_manager.wait_answer(request.hop_by_hop_id).await {
                    Ok(answer)
                } else {
                    Err(format!(
                        "No answer received for command with hop-by-hop ID {}",
                        request.hop_by_hop_id
                    ))
                }
            }
            Err(e) => {
                error!(
                    "Connection {} failed with error: {} in send_request_with_timeout. Trying next connection...",
                    conn.get_id(),
                    e
                );
                Err(e)
            }
        }
    }
}
