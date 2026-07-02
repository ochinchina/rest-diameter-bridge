use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use log::{error, info};
use tokio::sync::Mutex;

use crate::alarm::{AlarmSender, AlarmStore};
use crate::avp::AvpMap;
use crate::avp::load_avp_definition_from_yaml_files;

use crate::command::{CommandMap, load_command_definition_from_yaml_files};
use crate::config::StackConfig;
use crate::http_rest_listener::HttpRestListener;
use crate::transport::DefaultCommandHandler;
use crate::transport::HopByHopIdMapper;
use crate::transport::RequestProcessor;
use crate::transport::RoutingConnectionManager;
use crate::transport::{
    Connection, ConnectionManager, FailOverConnection,
    IdGenerator, RandomConnection, RoundRobinConnection, TcpClientConnection, TcpDiameterServer,
};


#[derive(Debug, Clone)]
pub enum LoadBalancerStrategy {
    RoundRobin(String),
    FailOver(String), // Failover to a specific peer
    Random(String),
    Value(Vec<String>), // Custom value-based strategy
}

impl LoadBalancerStrategy {
    pub fn from_str(strategy: &str) -> Option<Self> {
        let strategy = strategy.to_lowercase();
        let n = strategy.len();
        let mut start = 0;
        let mut values = Vec::new();
        let mut level = 0;
        let mut index = 0;
        while index < n {
            let c = strategy.chars().nth(index).unwrap();
            if c == '(' {
                level += 1;
            } else if c == ')' {
                level -= 1;
            }
            if level == 0 && c == ';' {
                values.push(strategy[start..index].trim().to_string());
                start = index + 1;
            } else if level == 0 && index + 1 >= n && start > 0 {
                values.push(strategy[start..].trim().to_string());
            }
            index += 1;
        }

        if level != 0 {
            error!(
                "Unbalanced parentheses in load balancer strategy: {}",
                strategy
            );
            return None;
        }

        if !values.is_empty() {
            return Some(LoadBalancerStrategy::Value(values));
        }

        if Self::starts_with_one_of(&strategy, vec!["round-robin(", "rr(", "roundrobin("])
            && strategy.ends_with(')')
        {
            return strategy
                .splitn(2, "(")
                .nth(1)
                .and_then(|s| s.strip_suffix(')'))
                .map(|s| LoadBalancerStrategy::RoundRobin(s.to_string()));
        } else if Self::starts_with_one_of(&strategy, vec!["failover(", "fo(", "fail-over("])
            && strategy.ends_with(')')
        {
            return strategy
                .splitn(2, "(")
                .nth(1)
                .and_then(|s| s.strip_suffix(')'))
                .map(|s| LoadBalancerStrategy::FailOver(s.to_string()));
        } else if Self::starts_with_one_of(&strategy, vec!["random(", "rand("])
            && strategy.ends_with(')')
        {
            return strategy
                .splitn(2, "(")
                .nth(1)
                .and_then(|s| s.strip_suffix(')'))
                .map(|s| LoadBalancerStrategy::Random(s.to_string()));
        } else {
            return Some(LoadBalancerStrategy::Value(vec![strategy]));
        }
    }

    fn starts_with_one_of(v: &str, prefixes: Vec<&str>) -> bool {
        for prefix in prefixes {
            if v.starts_with(prefix) {
                return true;
            }
        }
        false
    }
}

pub struct ListenParameters {
    pub parameters: HashMap<String, String>,
}
impl ListenParameters {
    pub fn new() -> Self {
        ListenParameters {
            parameters: HashMap::new(),
        }
    }

    pub fn from_str(param_str: &str) -> Self {
        let mut parameters = ListenParameters::new();
        for param in param_str.split('&') {
            let kv: Vec<&str> = param.split('=').collect();
            if kv.len() == 2 {
                parameters.insert(kv[0].to_string(), kv[1].to_string());
            }
        }
        parameters
    }

    pub fn insert(&mut self, key: String, value: String) {
        self.parameters.insert(key, value);
    }

    pub fn get(&self, key: &str) -> Option<&String> {
        self.parameters.get(key)
    }

    pub fn get_bool(&self, key: &str) -> Option<bool> {
        self.parameters
            .get(key)
            .and_then(|value| value.parse::<bool>().ok())
    }

    pub fn get_u16(&self, key: &str) -> Option<u16> {
        self.parameters
            .get(key)
            .and_then(|value| value.parse::<u16>().ok())
    }

    pub fn get_u32(&self, key: &str) -> Option<u32> {
        self.parameters
            .get(key)
            .and_then(|value| value.parse::<u32>().ok())
    }
}
pub struct ListenAddress {
    pub protocol: String,
    pub hosts: Vec<String>,
    pub port: u16,
    pub parameters: Option<ListenParameters>,
}

impl ListenAddress {
    /**
     * Parses a listen address string in the format "protocol://host1,host2:port?param1=value1&param2=value2" and returns a ListenAddress struct.
     */
    pub fn from_str(address: &str) -> Result<Self, String> {
        let parts: Vec<&str> = address.split('?').collect();

        let main_part = parts[0];
        let parameters = if parts.len() > 1 {
            Some(ListenParameters::from_str(parts[1]))
        } else {
            None
        };

        let parts: Vec<&str> = main_part.split("://").collect();
        if parts.len() != 2 {
            return Err(format!("Invalid listen address format: {}", address));
        }
        let protocol = parts[0].to_string();
        let addr_parts: Vec<&str> = parts[1].rsplitn(2, ':').collect();

        if addr_parts.len() != 2 {
            return Err(format!("Invalid listen address format: {}", address));
        }

        let port_part = addr_parts[0];
        let hosts_part = addr_parts[1];
        let hosts: Vec<String> = hosts_part
            .split(',')
            .map(|s| s.trim().to_string())
            .collect();
        let port = port_part
            .parse::<u16>()
            .map_err(|e| format!("Invalid port number in listen address: {}", e))?;
        Ok(ListenAddress {
            protocol,
            hosts,
            port,
            parameters: parameters,
        })
    }
}
pub struct DiameterStack {
    config: StackConfig,
    // Fields for the Diameter stack
    connection_manager: Arc<Mutex<ConnectionManager>>,
    hop_by_hop_id_generator: Arc<IdGenerator>,
    end_to_end_id_generator: Arc<IdGenerator>,
    hop_by_hop_id_mapper: Arc<HopByHopIdMapper>,
    alarm_sender: Option<AlarmSender>,
    alarm_store: Option<AlarmStore>,
}

impl DiameterStack {
    pub fn new(config: StackConfig) -> Self {
        let routing_manager = if config.routing.is_some() {
            Some(RoutingConnectionManager::new(config.routing.clone().unwrap()))
        } else {
            None
        };
        let hop_by_hop_id_generator = Arc::new(IdGenerator::new());
        let per_conn_timeout = config.connection_request_timeout.map_or(Duration::from_millis(60 * 1000), |t| Duration::from_millis(t));
        let total_timeout = config.request_timeout.map_or(Duration::from_millis(10 * 1000), |t| Duration::from_millis(t));
        let hop_by_hop_id_mapper = Arc::new(HopByHopIdMapper::new(hop_by_hop_id_generator.clone()));
        let conn_manager = ConnectionManager::new(per_conn_timeout, total_timeout, routing_manager.clone(), hop_by_hop_id_mapper.clone(), config.request_retry_result_codes.clone().unwrap_or_default());

        // Initialize alarm store and sender
        let db_path = config
            .alarm_management
            .as_ref()
            .and_then(|am| am.alarm_db.as_ref())
            .and_then(|db| db.path.clone());

        let alarm_store = db_path.and_then(|path| {
            match AlarmStore::new(&path) {
                Ok(store) => Some(store),
                Err(e) => {
                    error!("Failed to initialize alarm store: {}", e);
                    None
                }
            }
        });

        let alarm_url = config
            .alarm_management
            .as_ref()
            .and_then(|am| am.alarm_manager_url.clone());            

        let alarm_cert_file = config.alarm_management.as_ref().and_then(|am| am.cert_file.clone());
        let alarm_key_file = config.alarm_management.as_ref().and_then(|am| am.key_file.clone());
        let alarm_ca_cert_file = config.alarm_management.as_ref().and_then(|am| am.ca_cert_file.clone());

        let alarm_sender = alarm_store.as_ref().map(|store| {
            AlarmSender::new(alarm_url, store.clone(), alarm_cert_file, alarm_key_file, alarm_ca_cert_file)
        });

        DiameterStack {
            config,
            connection_manager: Arc::new(Mutex::new(conn_manager)),
            hop_by_hop_id_generator: hop_by_hop_id_generator.clone(),
            end_to_end_id_generator: Arc::new(IdGenerator::new()),
            hop_by_hop_id_mapper: hop_by_hop_id_mapper.clone(),
            alarm_sender,
            alarm_store,
        }
    }

    fn create_request_processors( &self) -> Vec<RequestProcessor> {
        let mut request_processors = Vec::new();
        if let Some(processors) = &self.config.my_request_processors {
            for processor in processors {
                let command_codes = processor.command_codes.clone().unwrap_or_default();
                let application_ids = processor.application_ids.clone().unwrap_or_default();
                let urls = processor.urls.clone().unwrap_or_default();
                let timeout = processor.timeout.map_or(Duration::from_secs(30), |t| Duration::from_millis(t));
                info!(
                    "Creating processor for command codes: {:?}, application IDs: {:?}, URLs: {:?}, timeout: {:?}",
                    command_codes, application_ids, urls, timeout
                );
                request_processors.push(RequestProcessor::new(
                    command_codes,
                    application_ids,
                    urls,
                    timeout,
                ));
            }
        } else {
            error!("No processors configured for stack '{}'", self.config.name);
        }
        request_processors
    }

    pub async fn start(&mut self) {
        // Start the Diameter stack, initialize connections, etc.
        info!("load command files: {:?}", self.config.command_files);
        info!("load avp files: {:?}", self.config.avp_files);
        let command_map = Self::load_command_definitions(self.config.command_files.clone());
        let avp_map = Self::load_avp_definitions(self.config.avp_files.clone());        
        let handler = DefaultCommandHandler::new(
                    self.create_request_processors(),
                    &command_map,
                    &avp_map
                );

        let command_handler = Arc::new(handler);

        self.start_listeners(&command_map, &avp_map, &command_handler);
        self.start_rest_listeners(&command_map, &avp_map, &command_handler);
        self.connect_to_peers(&avp_map, &command_map, &command_handler).await;
    }

    fn start_listeners(&self, command_map: &CommandMap, avp_map: &AvpMap, command_handler: &Arc<DefaultCommandHandler>) {
        // Start listeners based on the configuration
        if let Some(listeners) = &self.config.listen {
            listeners.iter().for_each(|listener| {
                
                 
                let listen_address = ListenAddress::from_str(&listener.address);
                if let Err(e) = listen_address {
                    error!(
                        "Failed to parse listen address '{}': {}",
                        listener.address, e
                    );
                    return;
                }
                let connection_manager = self.connection_manager.clone();

                if listen_address.is_err() {
                    error!(
                        "Failed to parse listen address '{}': {}",
                        listener.address,
                        listen_address.err().unwrap()
                    );
                    return;
                }
                let listen_address = listen_address.unwrap();
                if listen_address.protocol.to_lowercase() == "tcp" {
                    listen_address.hosts.iter().for_each(|host| {
                        let address = format!("{}:{}", host, listen_address.port);
                        let connection_manager = connection_manager.clone();
                        let command_map_clone: CommandMap = command_map.clone();
                        let avp_map_clone = avp_map.clone();
                        let dia_host = self.config.host.clone();
                        let dia_realm = self.config.realm.clone();
                        let key_file = listener.key_file.clone().unwrap_or_default();
                        let cert_file = listener.cert_file.clone().unwrap_or_default();
                        let ca_cert_file = listener.ca_cert_file.clone().unwrap_or_default();
                        let capability = self.config.capability.clone();
                        let hop_by_hop_id_mapper = self.hop_by_hop_id_mapper.clone();
                        let command_handler = command_handler.clone();
                        let alarm_sender = self.alarm_sender.clone();
                        tokio::spawn(async move {
                            let server = TcpDiameterServer::new(
                                dia_host,
                                dia_realm,
                                capability,
                                key_file,
                                cert_file,
                                ca_cert_file,
                                address.clone(),
                                connection_manager,
                                command_map_clone,
                                avp_map_clone,
                                hop_by_hop_id_mapper,
                                command_handler,
                                alarm_sender,
                            );
                            info!("Starting TCP Diameter server on {}", address);
                            if let Err(e) = server.start().await {
                                error!("TcpDiameterServer error: {}", e);
                            }
                        });
                    });
                } else  if listen_address.protocol.to_lowercase() == "sctp" {
                    info!(
                        "SCTP protocol is not yet supported for listen address '{}'",
                        listener.address
                    );
                } else {
                    error!(
                        "Unsupported protocol in listen address '{}': {}",
                        listener.address, listen_address.protocol
                    );
                    return;
                }
            });
        } else {
            error!("No listeners configured for stack '{}'", self.config.name);
        }
    }

    fn start_rest_listeners(&self, command_map: &CommandMap, avp_map: &AvpMap, command_handler: &Arc<DefaultCommandHandler>) {
        if self.config.rest_listen.is_none() {
            info!("No REST listeners configured for stack '{}'", self.config.name);
            return;
        }
        let alarm_rest_path = self.config
            .alarm_management
            .as_ref()
            .and_then(|am| am.alarm_rest_path.clone())
            .unwrap_or_else(|| "/alarms".to_string());

        for rest_listener in self.config.rest_listen.as_ref().unwrap() {
            let address = rest_listener.address.clone();
            let path = rest_listener.path.clone().unwrap_or("/".to_string());
            let cert_file = rest_listener.cert_file.clone().unwrap_or_default();
            let key_file = rest_listener.key_file.clone().unwrap_or_default();
            let ca_cert_file = rest_listener.ca_cert_file.clone().unwrap_or_default();
            let dia_host = self.config.host.clone();
            let dia_realm = self.config.realm.clone();
            let connection_manager = self.connection_manager.clone();
            let hop_by_hop_id_generator = self.hop_by_hop_id_generator.clone();
            let end_to_end_id_generator = self.end_to_end_id_generator.clone();
            let command_handler = command_handler.clone();
            let command_map = command_map.clone();
            let avp_map = avp_map.clone();
            let alarm_store = self.alarm_store.clone();
            let alarm_rest_path = Some(alarm_rest_path.clone());

            tokio::spawn(async move {
                let http_listener = HttpRestListener::new(
                    address,
                    dia_host,
                    dia_realm,
                    path,
                    command_handler,
                    cert_file,
                    key_file,
                    ca_cert_file,
                    connection_manager,
                    avp_map,
                    command_map,
                    hop_by_hop_id_generator,
                    end_to_end_id_generator,
                    alarm_store,
                    alarm_rest_path,
                );
                if let Err(e) = http_listener.start().await {
                    error!("HttpRestListener error: {}", e);
                }
            });
        }
    }

    fn load_avp_definitions(avp_files: Option<Vec<String>>) -> AvpMap {
        // Load AVP and command definitions from the specified files in the configuration
        avp_files.map_or_else(
            || AvpMap::new(vec![]),
            |avp_files| {
                let avps =
                    load_avp_definition_from_yaml_files(avp_files).unwrap_or_else(|_| vec![]);
                AvpMap::new(avps)
            },
        )
    }
    fn load_command_definitions(command_files: Option<Vec<String>>) -> CommandMap {
        // Load AVP and command definitions from the specified files in the configuration
        command_files.map_or_else(
            || CommandMap::new(vec![]),
            |command_files| {
                let commands = load_command_definition_from_yaml_files(command_files)
                    .unwrap_or_else(|_| vec![]);
                CommandMap::new(commands)
            },
        )
    }

    async fn connect_to_peers(&self, avp_map: &AvpMap, command_map: &CommandMap, command_handler: &Arc<DefaultCommandHandler>) {
        // Implement logic to connect to Diameter peers based on the PeerConfig
        // This may involve parsing the connection URL, establishing a TCP connection, etc.
        if let Some(peers) = &self.config.peers {
            info!(
                "Configuring {} peers for stack '{}'",
                peers.len(),
                self.config.name
            );
            for peer in peers {
                let mut host_parts = peer.host.splitn(2, '@');
                let my_host = self.config.host.clone();
                let my_realm = self.config.realm.clone();
                let peer_host = host_parts.next().unwrap_or_default().to_string();
                let peer_realm = host_parts.next().unwrap_or_default().to_string();
                info!("Configured peer with host {} and realm {} at {}", peer_host.clone(), peer_realm.clone(), peer.connection_url);
                let conns = Self::create_connections(
                    peer.connection_url.as_str(),
                    &my_host,
                    &my_realm,
                    &peer_host,
                    &peer_realm,
                    &peer.cert_file.clone().unwrap_or_default(),
                    &peer.key_file.clone().unwrap_or_default(),
                    &peer.ca_cert_file.clone().unwrap_or_default(),
                    avp_map,
                    command_map,
                    &self.config,
                    &self.hop_by_hop_id_generator,
                    &self.end_to_end_id_generator,
                    &self.connection_manager,
                    &self.hop_by_hop_id_mapper,
                    command_handler,
                    &self.alarm_sender,
                );
                info!("Created {} connection(s) for peer {}@{} at {}", conns.len(), peer_host.clone(), peer_realm.clone(), peer.connection_url);
                for conn in conns {
                    info!("Adding connection {}@{} to connection manager at {}", conn.get_peer_host().unwrap_or_default(), conn.get_peer_realm().unwrap_or_default(), peer.connection_url);
                    self.connection_manager
                        .lock()
                        .await
                        .add_connection(Arc::new(conn as Box<dyn Connection + Send + Sync>)).await;
                }
            }
        } else {
            error!("No peers configured for stack '{}'", self.config.name);
        }
    }

    fn create_connections(
        connection_url: &str,
        my_host: &String,
        my_realm: &String,
        peer_host: &String,
        peer_realm: &String,
        cert_file: &String,
        key_file: &String,
        ca_cert_file: &String,
        avp_map: &AvpMap,
        command_map: &CommandMap,
        stack_config: &StackConfig,
        hop_to_hop_id_generator: &Arc<IdGenerator>,
        end_to_end_id_generator: &Arc<IdGenerator>,
        connection_manager: &Arc<Mutex<ConnectionManager>>,
        hop_by_hop_id_mapper: &Arc<HopByHopIdMapper>,
        command_handler: &Arc<DefaultCommandHandler>,
        alarm_sender: &Option<AlarmSender>,
    ) -> Vec<Box<dyn Connection + Send + Sync>> {
        // Implement the logic to connect to a single peer
        // This may involve parsing the connection URL, establishing a TCP connection, etc.
        // Here you would typically initiate connections to the peer based on the connection_url
        LoadBalancerStrategy::from_str(connection_url)
            .map(|strategy| {
                info!(
                    "Parsed load balancer strategy for peer {}: {:?}",
                    connection_url, strategy
                );
                match strategy {
                    LoadBalancerStrategy::RoundRobin(peers) => {
                        info!("Connecting to peers in round-robin: {}", peers);
                        // Implement round-robin connection logic here
                        let conns = Self::create_connections(&peers, 
                            my_host, 
                            my_realm, 
                            peer_host, 
                            peer_realm, 
                            cert_file,
                            key_file, 
                            ca_cert_file, 
                            avp_map, 
                            command_map, 
                            stack_config, 
                            hop_to_hop_id_generator, 
                            end_to_end_id_generator, 
                            connection_manager,
                            hop_by_hop_id_mapper,
                            command_handler,
                            alarm_sender,);
                        if conns.len() > 1 {
                            let arc_conns: Vec<Arc<Box<dyn Connection + Send + Sync>>> = conns.into_iter().map(|c| Arc::new(c)).collect();
                            let conn = RoundRobinConnection::new(arc_conns);
                            vec![Box::new(conn) as Box<dyn Connection + Send + Sync>]
                        } else {
                            conns
                        }
                    }
                    LoadBalancerStrategy::FailOver(peers) => {
                        info!("Connecting to peers with failover: {}", peers);
                        // Implement failover connection logic here
                        let conns = Self::create_connections(&peers, 
                            my_host, 
                            my_realm,
                            peer_host, 
                            peer_realm, 
                            cert_file, 
                            key_file, 
                            ca_cert_file, 
                            avp_map, 
                            command_map, 
                            stack_config, 
                            hop_to_hop_id_generator, 
                            end_to_end_id_generator, 
                            connection_manager,
                            hop_by_hop_id_mapper,
                            command_handler,
                            alarm_sender,
                            );
                        if conns.len() > 1 {
                            let arc_conns: Vec<Arc<Box<dyn Connection + Send + Sync>>> = conns.into_iter().map(|c| Arc::new(c)).collect();
                            let conn = FailOverConnection::new(arc_conns);
                            vec![Box::new(conn) as Box<dyn Connection + Send + Sync>]
                        } else {
                            conns
                        }
                    }
                    LoadBalancerStrategy::Random(peers) => {
                        info!("Connecting to peers randomly: {}", peers);
                        // Implement random connection logic here
                        let conns = Self::create_connections(&peers, 
                            my_host, 
                            my_realm, 
                            peer_host, 
                            peer_realm, 
                            cert_file, 
                            key_file, 
                            ca_cert_file, 
                            avp_map, 
                            command_map, 
                            stack_config, 
                            hop_to_hop_id_generator, 
                            end_to_end_id_generator, 
                            connection_manager,
                        hop_by_hop_id_mapper,
                        command_handler,
                        alarm_sender,);
                        if conns.len() > 1 {
                            let arc_conns: Vec<Arc<Box<dyn Connection + Send + Sync>>> = conns.into_iter().map(|c| Arc::new(c)).collect();
                            let conn = RandomConnection::new(arc_conns);
                            vec![Box::new(conn) as Box<dyn Connection + Send + Sync>]
                        } else {
                            conns
                        }
                    }
                    LoadBalancerStrategy::Value(values) => {
                        if values.len() == 1 && values[0] == connection_url {
                            info!("Connecting to single peer: {} with host: {}, realm: {}", values[0], peer_host, peer_realm);                            
                            if let Some(conn) = ListenAddress::from_str(&values[0])
                                .map_err(|e| {
                                    error!("Failed to parse connection URL '{}': {}", values[0], e);
                                    e
                                })
                                .ok()
                                .and_then(|addr| {
                                    
                                    if addr.protocol.to_lowercase() == "tcp" {
                                        let conn = TcpClientConnection::new(
                                            format!("{}:{}", addr.hosts[0], addr.port),
                                            my_host.clone(),
                                            my_realm.clone(),
                                            peer_host.clone(),
                                            peer_realm.clone(),
                                            stack_config.capability.clone(),
                                            key_file.clone(),
                                            cert_file.clone(),
                                            ca_cert_file.clone(),
                                            hop_to_hop_id_generator.clone(),
                                            end_to_end_id_generator.clone(),
                                            stack_config.cer_timeout.unwrap_or(3),
                                            connection_manager.clone(),
                                            hop_by_hop_id_mapper.clone(),
                                            command_handler.clone(),
                                            alarm_sender.clone(),
                                        );
                                        conn.spawn_start();
                                        Some(Box::new(conn) as Box<dyn Connection + Send + Sync>)
                                    } else if addr.protocol.to_lowercase() == "sctp" {
                                        error!("SCTP protocol is not yet supported for connection URL '{}'", values[0]);
                                        None
                                    }  else {
                                        error!("Unsupported protocol in connection URL '{}': {}", values[0], addr.protocol);
                                        None
                                    }
                                }) {
                                    vec![conn]
                                } else {
                                    error!("Failed to create connection for URL '{}'", values[0]);
                                    vec![]
                                }
                                
                        } else {
                            info!("Connecting using custom strategy with values: {:?}", values);
                            // Implement custom value-based connection logic here
                            values
                                .into_iter()
                                .flat_map(|v| Self::create_connections(&v, my_host, my_realm, peer_host, peer_realm, cert_file, key_file, ca_cert_file, avp_map, command_map, stack_config, hop_to_hop_id_generator, end_to_end_id_generator, connection_manager, hop_by_hop_id_mapper, command_handler, alarm_sender))
                                .collect()
                        }
                    }
                }
            })
            .unwrap_or_default()
    }

    // Additional methods for managing the stack, sending commands, etc.
}
