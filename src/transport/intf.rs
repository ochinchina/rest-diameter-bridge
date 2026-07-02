use crate::{
    avp::{AvpMap, ResultCode},
    command::{
        Command, CommandBuffer, CommandFlags, CommandMap, create_command_from_json_value,
        create_json_from_command, create_json_from_command_pretty,
    },
    metrics::{PROCESSED_REQUESTS, REQUESTS_RECEIVED, RESPONSES_RECEIVED},
};

use log::{error, info};
use tokio::sync::Notify;

use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicI32, AtomicU32, AtomicUsize, Ordering},
    },
};
use tokio::io::{AsyncRead, AsyncReadExt};

#[async_trait::async_trait]
pub trait Connection: Send + Sync {
    fn get_id(&self) -> String; // Unique identifier for the connection, e.g., "host:port"    
    async fn send(&self, command: &Command) -> Result<(), String>;
    async fn close(&self) -> Result<(), String>;
    async fn is_closed(&self) -> bool;

    // get the peer host and realm for this connection, which may be needed for routing or other purposes
    fn get_peer_host(&self) -> Result<String, String>;
    fn get_peer_realm(&self) -> Result<String, String>;

    async fn add_connection(&self, _connection: Arc<Box<dyn Connection + Send + Sync>>) {
        // Default implementation does nothing, can be overridden by load balancer connections
    }

    async fn remove_connection(&self, _connection: Arc<Box<dyn Connection + Send + Sync>>) {
        // Default implementation does nothing, can be overridden by load balancer connections
    }

    fn is_container(&self) -> bool {
        false // Default implementation returns false, can be overridden by load balancer connections
    }

    fn iter(
        &self,
    ) -> Option<Box<dyn Iterator<Item = Arc<Box<dyn Connection + Send + Sync>>> + Send>> {
        // Default implementation returns an empty iterator, can be overridden by load balancer connections
        None
    }
}

pub type ConnectionMap = std::collections::HashMap<String, Arc<Box<dyn Connection + Send + Sync>>>;

#[derive(Clone)]
pub struct ConnectionList {
    connections: Arc<tokio::sync::Mutex<Vec<Arc<Box<dyn Connection + Send + Sync>>>>>,
}

impl Default for ConnectionList {
    fn default() -> Self {
        ConnectionList::new(Vec::new())
    }
}

impl ConnectionList {
    pub fn new(connections: Vec<Arc<Box<dyn Connection + Send + Sync>>>) -> Self {
        ConnectionList {
            connections: Arc::new(tokio::sync::Mutex::new(connections)),
        }
    }

    pub async fn add_connection(&self, connection: Arc<Box<dyn Connection + Send + Sync>>) {
        let mut connections = self.connections.lock().await;
        connections.push(connection);
    }

    pub async fn remove_connection(&self, connection: Arc<Box<dyn Connection + Send + Sync>>) {
        let mut connections = self.connections.lock().await;
        connections.retain(|conn| !Arc::ptr_eq(conn, &connection));
    }

    pub fn len(&self) -> usize {
        let connections = futures::executor::block_on(self.connections.lock());
        connections.len()
    }

    pub async fn is_empty(&self) -> bool {
        let connections = self.connections.lock().await;
        connections.is_empty()
    }

    pub async fn get_connection(
        &self,
        index: usize,
    ) -> Option<Arc<Box<dyn Connection + Send + Sync>>> {
        let connections = self.connections.lock().await;
        connections.get(index).cloned()
    }

    pub async fn get_connections(&self) -> Vec<Arc<Box<dyn Connection + Send + Sync>>> {
        let connections = self.connections.lock().await;
        connections.clone()
    }
}

pub struct ConnectionIterator {
    connections: Arc<ConnectionList>,
    index: AtomicUsize,
    sub_iter: Option<Box<dyn Iterator<Item = Arc<Box<dyn Connection + Send + Sync>>> + Send>>,
    tried_times: AtomicUsize,
}

impl ConnectionIterator {
    pub fn new(connections: Arc<ConnectionList>, index: AtomicUsize) -> Self {
        ConnectionIterator {
            connections,
            index,
            sub_iter: None, // Initialize sub_iter with None
            tried_times: AtomicUsize::new(0),
        }
    }

    fn get_next(
        connections: &Vec<Arc<Box<dyn Connection + Send + Sync>>>,
        index: &AtomicUsize,
    ) -> Option<Arc<Box<dyn Connection + Send + Sync>>> {
        let n = connections.len();
        if n == 0 {
            return None;
        }
        let i = index.load(std::sync::atomic::Ordering::Relaxed);
        let conn = connections.get(i % n).cloned();
        index.store((i + 1) % n, std::sync::atomic::Ordering::Relaxed);

        conn
    }
}

impl Iterator for ConnectionIterator {
    type Item = Arc<Box<dyn Connection + Send + Sync>>;

    fn next(&mut self) -> Option<Self::Item> {
        let connections = futures::executor::block_on(self.connections.get_connections());
        let n = connections.len();
        if n == 0 || self.tried_times.load(std::sync::atomic::Ordering::Relaxed) >= n {
            return None;
        }

        // If we have an active sub_iter, drain it first before advancing the outer index
        if let Some(sub_iter) = &mut self.sub_iter {
            if let Some(sub_conn) = sub_iter.next() {
                return Some(sub_conn);
            } else {
                // Sub-iterator exhausted, move on to the next outer connection
                self.sub_iter = None;
                self.tried_times
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                if self.tried_times.load(std::sync::atomic::Ordering::Relaxed) >= n {
                    return None;
                }
            }
        }

        loop {
            match Self::get_next(&connections, &self.index) {
                Some(conn) => {
                    if conn.is_container() {
                        self.sub_iter = conn.iter();
                        if let Some(sub_iter) = &mut self.sub_iter {
                            if let Some(sub_conn) = sub_iter.next() {
                                return Some(sub_conn);
                            } else {
                                // Empty container, count it and continue
                                self.sub_iter = None;
                                self.tried_times
                                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                if self.tried_times.load(std::sync::atomic::Ordering::Relaxed) >= n
                                {
                                    return None;
                                }
                                continue;
                            }
                        } else {
                            // iter() returned None — empty container, skip it
                            self.tried_times
                                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            if self.tried_times.load(std::sync::atomic::Ordering::Relaxed) >= n {
                                return None;
                            }
                            continue;
                        }
                    } else {
                        self.tried_times
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        return Some(conn);
                    }
                }
                None => return None,
            }
        }
    }
}

pub struct IdGenerator {
    current_id: AtomicU32,
}

impl IdGenerator {
    pub fn new() -> Self {
        IdGenerator {
            current_id: AtomicU32::new(0),
        }
    }

    pub fn next_id(&self) -> u32 {
        self.current_id.fetch_add(1, Ordering::Relaxed)
    }
}

struct HopByHopAnswerInfo {
    original_id: u32,
    notify: Arc<Notify>,
    answer_result_code: Arc<Mutex<Option<u32>>>,
    timeout: std::time::Instant,
}

impl HopByHopAnswerInfo {
    fn new(original_id: u32, notify: Arc<Notify>, timeout: std::time::Instant) -> Self {
        HopByHopAnswerInfo {
            original_id,
            notify,
            answer_result_code: Arc::new(Mutex::new(None)),
            timeout,
        }
    }

    fn set_answer_result_code(&self, result_code: u32) {
        let mut answer_result_code = self.answer_result_code.lock().unwrap();
        *answer_result_code = Some(result_code);
    }

    fn get_answer_result_code(&self) -> Option<u32> {
        let answer_result_code = self.answer_result_code.lock().unwrap();
        *answer_result_code
    }

    fn is_timeout(&self) -> bool {
        std::time::Instant::now() > self.timeout
    }
}
pub struct HopByHopIdMapper {
    hop_by_hop_id_generator: Arc<IdGenerator>,
    map: std::sync::Mutex<std::collections::HashMap<u32, Arc<HopByHopAnswerInfo>>>,
    next_cleanup_time: std::sync::Mutex<std::time::Instant>,
}

impl HopByHopIdMapper {
    pub fn new(hop_by_hop_id_generator: Arc<IdGenerator>) -> Self {
        HopByHopIdMapper {
            hop_by_hop_id_generator,
            map: std::sync::Mutex::new(std::collections::HashMap::new()),
            next_cleanup_time: std::sync::Mutex::new(
                std::time::Instant::now() + std::time::Duration::from_secs(30),
            ),
        }
    }

    pub fn allocate(&self, original_id: u32) -> u32 {
        self.clean_expired_entries();

        let new_id = self.hop_by_hop_id_generator.next_id();
        let notify = Arc::new(Notify::new());
        info!(
            "Mapping original hop-by-hop ID {} to new hop-by-hop ID {}",
            original_id, new_id
        );
        let mut map = self.map.lock().unwrap();
        map.insert(
            new_id,
            Arc::new(HopByHopAnswerInfo::new(
                original_id,
                notify.clone(),
                std::time::Instant::now() + std::time::Duration::from_secs(30),
            )),
        );
        new_id
    }

    pub async fn wait_for_answer(&self, original_id: u32) -> u32 {
        if let Some(info) = self.get_answer_info(original_id) {
            info.notify.notified().await;
            info.get_answer_result_code()
                .unwrap_or(ResultCode::DiameterSuccess as u32)
        } else {
            ResultCode::DiameterSuccess as u32
        }
    }

    fn get_answer_info(&self, original_id: u32) -> Option<Arc<HopByHopAnswerInfo>> {
        let map = self.map.lock().unwrap();
        map.get(&original_id).map(|info| info.clone())
    }

    pub fn get(&self, original_id: &u32) -> Option<u32> {
        let map = self.map.lock().unwrap();
        map.get(original_id).map(|info| info.original_id)
    }

    /**
     * Removes the mapping for the given original hop-by-hop ID and returns the new hop-by-hop ID if it exists. It also notifies any waiters that the answer has been received.
     */
    pub fn remove(&self, new_id: &u32, result_code: u32) -> Option<u32> {
        info!(
            "Removing mapping for new hop-by-hop ID {} with result code {}",
            new_id, result_code
        );
        let mut map = self.map.lock().unwrap();

        map.remove(new_id)
            .map(|info| {
                info.set_answer_result_code(result_code);
                info.notify.notify_waiters();
                info.original_id
            })
            .or_else(|| {
                error!(
                    "No mapping found for new hop-by-hop ID {} when trying to remove it",
                    new_id
                );
                None
            })
    }

    fn clean_expired_entries(&self) {
        let now = std::time::Instant::now();
        if self.next_cleanup_time.lock().unwrap().gt(&now) {
            return;
        }
        self.update_clean_time();

        let mut map = self.map.lock().unwrap();
        map.retain(|new_id, info| {
            if info.is_timeout() {
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

    fn update_clean_time(&self) {
        let now = std::time::Instant::now();
        let mut next_cleanup_time = self.next_cleanup_time.lock().unwrap();
        *next_cleanup_time = now + std::time::Duration::from_secs(30);
    }
}

async fn send_command_with_url(
    url: &str,
    command: &Command,
    command_map: &CommandMap,
    avp_map: &AvpMap,
) -> Result<(), String> {
    // Implement the logic to send the command to the specified HTTP endpoint
    // This is a placeholder implementation
    let body = serde_json::to_string(&create_json_from_command(command, command_map, avp_map))
        .map_err(|e| format!("Failed to serialize command: {}", e))?;

    match reqwest::Client::new()
        .post(url)
        .header("Content-Type", "application/json")
        .body(body)
        .send()
        .await
    {
        Ok(response) => {
            let status_code = response.status().as_u16();
            if status_code >= 200 && status_code < 400 {
                info!("Successfully sent command to {}: HTTP {}", url, status_code);
                Ok(())
            } else {
                Err(format!(
                    "Failed to send command to {}: HTTP {}",
                    url, status_code
                ))
            }
        }
        Err(e) => Err(format!("Failed to send command to {}: {}", url, e)),
    }
}

#[async_trait::async_trait]
pub trait CommandHandler: Send + Sync {
    async fn handle_command(&self, command: &Command) -> Result<Option<Command>, String>;
}

pub struct HandlerEntry {
    pub timeout: std::time::Instant,
    pub url: Option<String>,
    pub sender: Option<tokio::sync::mpsc::Sender<Command>>,
    pub original_request: Option<Command>,
    pub retry_count: u32,
}

impl HandlerEntry {
    pub fn new(
        timeout: std::time::Instant,
        url: Option<String>,
        sender: Option<tokio::sync::mpsc::Sender<Command>>,
    ) -> Self {
        HandlerEntry {
            timeout,
            url,
            sender,
            original_request: None,
            retry_count: 0,
        }
    }

    pub fn with_request(mut self, request: Command) -> Self {
        self.original_request = Some(request);
        self
    }

    pub fn with_retry_count(mut self, count: u32) -> Self {
        self.retry_count = count;
        self
    }

    fn is_expired(&self) -> bool {
        std::time::Instant::now() > self.timeout
    }

    async fn send_command(
        &self,
        command: &Command,
        command_map: &CommandMap,
        avp_map: &AvpMap,
    ) -> Result<(), String> {
        if self.is_expired() {
            return Err("Handler entry has expired".to_string());
        }

        if let Some(url) = &self.url {
            // Implement the logic to send the command to the specified HTTP endpoint
            // This is a placeholder implementation
            send_command_with_url(url, command, command_map, avp_map).await
        } else if let Some(sender) = &self.sender {
            sender
                .send(command.clone())
                .await
                .map_err(|e| format!("Failed to send command through channel: {}", e))
        } else {
            error!("No valid URL or sender for sending the answer.");
            Err("No valid URL or sender for sending the answer.".to_string())
        }
    }
}

pub struct RequestProcessor {
    command_codes: Vec<u32>,
    application_ids: Vec<u32>,
    urls: Vec<String>,
    timeout: std::time::Duration,
}

impl RequestProcessor {
    pub fn new(
        command_codes: Vec<u32>,
        application_ids: Vec<u32>,
        urls: Vec<String>,
        timeout: std::time::Duration,
    ) -> Self {
        RequestProcessor {
            command_codes,
            application_ids,
            urls,
            timeout,
        }
    }

    pub fn matches(&self, command: &Command) -> bool {
        if (self.command_codes.is_empty() || self.command_codes.contains(&command.code))
            && (self.application_ids.is_empty()
                || self.application_ids.contains(&command.get_application_id()))
        {
            true
        } else {
            false
        }
    }

    pub async fn send_request(
        &self,
        request: &Command,
        command_map: &CommandMap,
        avp_map: &AvpMap,
    ) -> Result<Command, String> {
        for url in &self.urls {
            info!(
                "Sending request with code {} and hop-by-hop ID {} to URL: {}",
                request.code, request.hop_by_hop_id, url
            );
            // Implement the logic to send the command to the specified URL
            // This is a placeholder implementation
            match reqwest::Client::new()
                .post(url)
                .timeout(self.timeout)
                .header("Content-Type", "application/json")
                .json(&create_json_from_command(request, command_map, avp_map))
                .send()
                .await
            {
                Ok(response) => {
                    let status_code = response.status().as_u16();
                    if status_code >= 200 && status_code < 400 {
                        info!(
                            "Successfully sent request with command code {} to {}: HTTP status code {}",
                            request.code, url, status_code
                        );
                        if let Ok(body) = response.text().await {
                            return self.create_answer(&body, request, command_map, avp_map);
                        } else {
                            error!(
                                "Failed to read response body for request with command code {} from {}",
                                request.code, url
                            );
                        }
                    } else {
                        error!(
                            "Failed to send request with command code {} to {}: HTTP status code {}",
                            request.code, url, status_code
                        );
                    }
                }
                Err(e) => {
                    error!(
                        "Failed to send request with command code {} to {}: {}",
                        request.code, url, e
                    );
                }
            }
        }
        let mut response = request.create_response();
        response.set_result_code(3002);
        Ok(response)
    }

    fn create_answer(
        &self,
        response: &String,
        request: &Command,
        command_map: &CommandMap,
        avp_map: &AvpMap,
    ) -> Result<Command, String> {
        let mut v = serde_json::from_str::<serde_json::Value>(response).map_err(|e| {
            format!(
                "Failed to parse response JSON for request with code {} and hop-by-hop ID {}: {}",
                request.code, request.hop_by_hop_id, e
            )
        })?;

        if !v.is_object() {
            return Err(format!(
                "Response is not a valid JSON object for request with code {} and hop-by-hop ID {}: {}",
                request.code, request.hop_by_hop_id, response
            ));
        }

        if v.get("code").is_none() && v.get("name").is_none() {
            v.as_object_mut()
                .unwrap()
                .insert("code".to_string(), serde_json::json!(request.code));
        }

        match create_command_from_json_value(&v, command_map, avp_map) {
            Ok(mut answer) => {
                answer.hop_by_hop_id = request.hop_by_hop_id; // Ensure the hop-by-hop ID matches the request
                answer.end_to_end_id = request.end_to_end_id; // Ensure the end-to-end ID matches the request
                answer.flags = request.flags & !(CommandFlags::Request as u8); // Ensure the flags match the request
                if request.get_application_id() != 0 {
                    answer.application_id = request.get_application_id();
                }
                if request.get_destination_realm().is_some() {
                    answer.set_origin_realm(&request.get_destination_realm().unwrap_or_default());
                }
                if request.get_destination_host().is_some() {
                    answer.set_origin_host(&request.get_destination_host().unwrap_or_default());
                }
                if request.get_origin_host().is_some() {
                    answer.set_destination_host(&request.get_origin_host().unwrap_or_default());
                }
                if request.get_origin_realm().is_some() {
                    answer.set_destination_realm(&request.get_origin_realm().unwrap_or_default());
                }
                info!(
                    "Received answer for request with code {} and hop-by-hop ID {}: {}",
                    answer.code,
                    answer.hop_by_hop_id,
                    create_json_from_command_pretty(&answer, command_map, avp_map)
                );

                Ok(answer)
            }
            Err(e) => {
                error!(
                    "Failed to create answer for request with code {} and hop-by-hop ID {} from: {}. Error: {}",
                    request.code, request.hop_by_hop_id, response, e
                );
                Err("Failed to create answer from response".to_string())
            }
        }
    }
}
pub struct DefaultCommandHandler {
    request_processors: Vec<RequestProcessor>,
    command_map: CommandMap,
    avp_map: AvpMap,
    expires: std::time::Duration,
    handlers: Arc<Mutex<HashMap<u32, HandlerEntry>>>,
    next_clean_expiration_check: AtomicI32,
    connection_manager: Option<Arc<tokio::sync::Mutex<crate::transport::ConnectionManager>>>,
    hop_by_hop_id_generator: Option<Arc<IdGenerator>>,
}

impl DefaultCommandHandler {
    pub fn new(
        request_processors: Vec<RequestProcessor>,
        command_map: &CommandMap,
        avp_map: &AvpMap,
    ) -> Self {
        DefaultCommandHandler {
            request_processors,
            handlers: Arc::new(Mutex::new(HashMap::new())),
            command_map: command_map.clone(),
            avp_map: avp_map.clone(),
            expires: std::time::Duration::from_secs(300),
            next_clean_expiration_check: AtomicI32::new(
                (std::time::Instant::now() + std::time::Duration::from_secs(60))
                    .elapsed()
                    .as_secs() as i32,
            ),
            connection_manager: None,
            hop_by_hop_id_generator: None,
        }
    }

    pub fn set_connection_manager(
        &mut self,
        connection_manager: Arc<tokio::sync::Mutex<crate::transport::ConnectionManager>>,
    ) {
        self.connection_manager = Some(connection_manager);
    }

    pub fn set_hop_by_hop_id_generator(&mut self, generator: Arc<IdGenerator>) {
        self.hop_by_hop_id_generator = Some(generator);
    }

    /**
     * Adds a new answer handler entry for the given hop-by-hop ID with the specified URL. The entry will expire after the configured duration.
     */
    pub fn add_answer_url(&self, hop_by_hop_id: u32, url: &str) {
        let mut handlers = self.handlers.lock().unwrap();

        self.remove_expired_entries(&mut handlers);
        handlers.insert(
            hop_by_hop_id,
            HandlerEntry::new(
                std::time::Instant::now() + self.expires,
                Some(url.to_string()),
                None,
            ),
        );
    }

    /**
     * Adds a new answer handler entry for the given hop-by-hop ID with the specified URL and stores the original request for retry.
     */
    pub fn add_answer_url_with_request(&self, hop_by_hop_id: u32, url: &str, request: &Command) {
        let mut handlers = self.handlers.lock().unwrap();

        self.remove_expired_entries(&mut handlers);
        handlers.insert(
            hop_by_hop_id,
            HandlerEntry::new(
                std::time::Instant::now() + self.expires,
                Some(url.to_string()),
                None,
            )
            .with_request(request.clone()),
        );
    }

    /**
     * Adds a new answer handler entry for the given hop-by-hop ID with the specified sender. The entry will expire after the configured duration.
     */
    pub fn add_answer_sender(
        &self,
        hop_by_hop_id: u32,
        sender: tokio::sync::mpsc::Sender<Command>,
    ) {
        let mut handlers = self.handlers.lock().unwrap();
        self.remove_expired_entries(&mut handlers);
        handlers.insert(
            hop_by_hop_id,
            HandlerEntry::new(std::time::Instant::now() + self.expires, None, Some(sender)),
        );
    }

    /**
     * Adds a new answer handler entry for the given hop-by-hop ID with the specified sender and stores the original request for retry.
     */
    pub fn add_answer_sender_with_request(
        &self,
        hop_by_hop_id: u32,
        sender: tokio::sync::mpsc::Sender<Command>,
        request: &Command,
    ) {
        let mut handlers = self.handlers.lock().unwrap();
        self.remove_expired_entries(&mut handlers);
        handlers.insert(
            hop_by_hop_id,
            HandlerEntry::new(std::time::Instant::now() + self.expires, None, Some(sender))
                .with_request(request.clone()),
        );
    }

    fn get_answer_handler(&self, hop_by_hop_id: u32) -> Option<HandlerEntry> {
        let mut handlers = self.handlers.lock().unwrap();
        handlers.remove(&hop_by_hop_id)
    }

    async fn handle_answer(&self, command: &Command) -> Result<(), String> {
        if let Some(handler_entry) = self.get_answer_handler(command.hop_by_hop_id) {
            handler_entry
                .send_command(command, &self.command_map, &self.avp_map)
                .await
        } else {
            error!(
                "No handler found for answer with hop-by-hop ID: {}",
                command.hop_by_hop_id
            );
            Err(format!(
                "No handler found for answer with hop-by-hop ID: {}",
                command.hop_by_hop_id
            ))
        }
    }

    fn is_expired_entry_check_time(&self) -> bool {
        let now = std::time::Instant::now();
        let next_check = self.next_clean_expiration_check.load(Ordering::Relaxed);
        if now.elapsed().as_secs() as i32 >= next_check {
            self.next_clean_expiration_check.store(
                (now + std::time::Duration::from_secs(60))
                    .elapsed()
                    .as_secs() as i32,
                Ordering::Relaxed,
            );
            true
        } else {
            false
        }
    }

    fn remove_expired_entries(&self, handlers: &mut HashMap<u32, HandlerEntry>) {
        if self.is_expired_entry_check_time() {
            self.next_clean_expiration_check.store(
                (std::time::Instant::now() + std::time::Duration::from_secs(60))
                    .elapsed()
                    .as_secs() as i32,
                Ordering::Relaxed,
            );
            let now = std::time::Instant::now();
            handlers.retain(|_, entry| entry.timeout > now);
        }
    }
}

#[async_trait::async_trait]
impl CommandHandler for DefaultCommandHandler {
    async fn handle_command(&self, command: &Command) -> Result<Option<Command>, String> {
        if command.is_request() {
            REQUESTS_RECEIVED.inc();
            for processor in &self.request_processors {
                if processor.matches(command) {
                    PROCESSED_REQUESTS.inc();
                    if let Ok(answer) = processor
                        .send_request(command, &self.command_map, &self.avp_map)
                        .await
                    {
                        return Ok(Some(answer));
                    }
                }
            }
            Err(format!(
                "No processor found for command with hop-by-hop ID: {}",
                command.hop_by_hop_id
            ))
        } else {
            RESPONSES_RECEIVED.inc();
            match self.handle_answer(command).await {
                Ok(_) => Ok(None),
                Err(e) => Err(format!(
                    "Failed to handle answer with hop-by-hop ID: {}. Error: {}",
                    command.hop_by_hop_id, e
                )),
            }
        }
    }
}

/**
 * Helper function to read a Diameter command from a TCP stream. This function reads the Diameter message length first, then reads the full message, and finally parses it into a Command struct.
 * This is used in both the TcpClientConnection and TcpServerConnection to read incoming Diameter messages after the initial CER/CEA exchange.
 */
pub async fn read_command(reader: &mut (impl AsyncRead + Unpin)) -> Result<Command, String> {
    let mut length_buffer = [0; 4];

    reader
        .read_exact(&mut length_buffer)
        .await
        .map_err(|e| format!("Failed to read message length: {}", e))?;

    let message_length = u32::from_be_bytes(length_buffer) & 0x00FFFFFF; // Diameter message length is in the last 3 bytes
    let mut buffer = vec![0; message_length as usize - 4];

    reader
        .read_exact(&mut buffer)
        .await
        .map_err(|e| format!("Failed to read message body: {}", e))?;
    let mut command_buffer = CommandBuffer::from_bytes(&length_buffer);
    command_buffer.append(&buffer);
    let command = command_buffer
        .read_command()
        .ok_or_else(|| "Failed to parse CEA command".to_string())?;
    Ok(command)
}

/**
 * Replaces the hop-by-hop ID in the given command using the provided HopByHopIdMapper.
 * If the command is a request, it allocates a new hop-by-hop ID and updates the command.
 * If the command is a response, it retrieves the original hop-by-hop ID from the mapper and updates the command accordingly.
 * If no mapping is found for a response, it logs an error.
 */
pub fn replace_hop_by_hop_id(command: &mut Command, mapper: &HopByHopIdMapper) {
    if command.is_request() {
        let new_hop_by_hop_id = mapper.allocate(command.hop_by_hop_id);
        command.hop_by_hop_id = new_hop_by_hop_id;
    } else {
        match mapper.remove(
            &command.hop_by_hop_id,
            command
                .get_result_code()
                .unwrap_or(ResultCode::DiameterSuccess as u32),
        ) {
            Some(old_id) => command.hop_by_hop_id = old_id,
            None => error!(
                "Received response with unknown hop-by-hop ID: {}. This may indicate a mismatch in request-response mapping.",
                command.hop_by_hop_id
            ),
        }
    }
}
