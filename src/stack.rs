use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use log::{error, info};

use crate::alarm::{AlarmSender, AlarmStore};
use crate::avp::AvpMap;
use crate::avp::load_avp_definition_from_yaml_files;

use crate::command::{CommandMap, load_command_definition_from_yaml_files};
use crate::config::StackConfig;
use crate::http_rest_listener::HttpRestListener;
use crate::transport::{AnswerManager, DefaultCommandHandler, RedirectHostManager, answer_manager};
use crate::transport::HopByHopIdMapper;
use crate::transport::RequestProcessor;
use crate::transport::RoutingConnectionManager;
#[cfg(target_os = "linux")]
use crate::transport::sctp_transport::{SctpClientConnection, SctpDiameterServer};
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
    connection_manager: Arc<Box<ConnectionManager>>,
    hop_by_hop_id_generator: Arc<Box<IdGenerator>>,
    end_to_end_id_generator: Arc<Box<IdGenerator>>,
    hop_by_hop_id_mapper: Arc<Box<HopByHopIdMapper>>,
    answer_manager: Arc<Box<AnswerManager>>,
    alarm_sender: Option<AlarmSender>,
    alarm_store: Option<AlarmStore>,
    redirect_host_manager: Arc<Box<RedirectHostManager>>,

}

impl DiameterStack {
    pub fn new(config: StackConfig) -> Self {
        let routing_manager = if config.routing.is_some() {
            Some(RoutingConnectionManager::new(&config.routing.clone().unwrap()))
        } else {
            None
        };
        let hop_by_hop_id_generator = Arc::new(Box::new(IdGenerator::new()));
        let per_conn_timeout = config.connection_request_timeout.map_or(Duration::from_millis(60 * 1000), |t| Duration::from_millis(t));
        let total_timeout = config.request_timeout.map_or(Duration::from_millis(10 * 1000), |t| Duration::from_millis(t));
        let redirect_host_manager = Arc::new(Box::new(RedirectHostManager::new()));
        let hop_by_hop_id_mapper = Arc::new(Box::new(HopByHopIdMapper::new()));
        let answer_manager = Arc::new(Box::new(answer_manager::AnswerManager::new()));
        let conn_manager = ConnectionManager::new(per_conn_timeout, total_timeout, routing_manager.clone(), answer_manager.clone(), config.request_retry_result_codes.clone().unwrap_or_default(), redirect_host_manager.clone());

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
            connection_manager: Arc::new(Box::new(conn_manager)),
            hop_by_hop_id_generator: hop_by_hop_id_generator.clone(),
            end_to_end_id_generator: Arc::new(Box::new(IdGenerator::new())),
            hop_by_hop_id_mapper: hop_by_hop_id_mapper.clone(),
            answer_manager,
            alarm_sender,
            alarm_store,       
            redirect_host_manager: redirect_host_manager.clone(),     
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
        self.start_rest_listeners(&command_map, &avp_map);
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
                                                
                        let server = TcpDiameterServer::new(
                                self.config.host.clone(),
                                self.config.realm.clone(),
                                self.config.capability.clone(),
                                listener.key_file.clone().unwrap_or_default(),
                                listener.cert_file.clone().unwrap_or_default(),
                                listener.ca_cert_file.clone().unwrap_or_default(),
                                address.clone(),
                                connection_manager.clone(),
                                command_map.clone(),
                                avp_map.clone(),
                                self.hop_by_hop_id_generator.clone(),
                                self.hop_by_hop_id_mapper.clone(),
                                self.answer_manager.clone(),
                                command_handler.clone(),
                                self.alarm_sender.clone(),
                                self.redirect_host_manager.clone(),
                            );

                        tokio::spawn(async move {
                            
                            info!("Starting TCP Diameter server on {}", address);
                            if let Err(e) = server.start().await {
                                error!("TcpDiameterServer error: {}", e);
                            }
                        });
                    });
                } else  if listen_address.protocol.to_lowercase() == "sctp" {
                    #[cfg(target_os = "linux")]
                    {
                        let addresses: Vec<String> = listen_address.hosts.iter()
                            .map(|host| format!("{}:{}", host, listen_address.port))
                            .collect();                        
                        
                        let server = SctpDiameterServer::new(
                                self.config.host.clone(),
                                self.config.realm.clone(),
                                self.config.capability.clone(),
                                listener.key_file.clone().unwrap_or_default(),
                                listener.cert_file.clone().unwrap_or_default(),
                                listener.ca_cert_file.clone().unwrap_or_default(),
                                addresses.clone(),
                                connection_manager.clone(),
                                command_map.clone(),
                                avp_map.clone(),
                                self.hop_by_hop_id_mapper.clone(),
                                self.hop_by_hop_id_generator.clone(),    
                                command_handler.clone(),
                                self.alarm_sender.clone(),
                                self.answer_manager.clone(),
                                self.redirect_host_manager.clone(),
                            );

                        tokio::spawn(async move {
                            
                            info!("Starting SCTP Diameter server on {:?}", addresses);
                            if let Err(e) = server.start().await {
                                error!("SctpDiameterServer error: {}", e);
                            }
                        });
                    }
                    #[cfg(not(target_os = "linux"))]
                    {
                        error!(
                            "SCTP protocol is only supported on Linux for listen address '{}'",
                            listener.address
                        );
                    }
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

    fn start_rest_listeners(&self, command_map: &CommandMap, avp_map: &AvpMap) {
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
            let http_listener = HttpRestListener::new(
                    rest_listener.address.clone(),
                    self.config.host.clone(),
                    self.config.realm.clone(),
                    rest_listener.path.clone().unwrap_or("/".to_string()),
                    rest_listener.cert_file.clone().unwrap_or_default(),
                    rest_listener.key_file.clone().unwrap_or_default(),
                    rest_listener.ca_cert_file.clone().unwrap_or_default(),
                    self.connection_manager.clone(),
                    avp_map.clone(),
                    command_map.clone(),
                    self.hop_by_hop_id_generator.clone(),
                    self.end_to_end_id_generator.clone(),
                    self.alarm_store.clone(),
                    Some(alarm_rest_path.clone()),
                    self.answer_manager.clone(),
                );

            tokio::spawn(async move {
                
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
                let peer_host = host_parts.next().unwrap_or_default().to_string();
                let peer_realm = host_parts.next().unwrap_or_default().to_string();
                info!("Configured peer with host {} and realm {} at {}", peer_host.clone(), peer_realm.clone(), peer.connection_url);
                let conns = self.create_connections(
                    peer.connection_url.as_str(),
                    &peer_host,
                    &peer_realm,
                    &peer.cert_file.clone().unwrap_or_default(),
                    &peer.key_file.clone().unwrap_or_default(),
                    &peer.ca_cert_file.clone().unwrap_or_default(),
                    command_map,
                    avp_map,
                    command_handler,
                );
                info!("Created {} connection(s) for peer {}@{} at {}", conns.len(), peer_host.clone(), peer_realm.clone(), peer.connection_url);
                for conn in conns {
                    info!("Adding connection {}@{} to connection manager at {}", conn.get_peer_host().unwrap_or_default(), conn.get_peer_realm().unwrap_or_default(), peer.connection_url);
                    self.connection_manager
                        .add_connection(Arc::new(conn as Box<dyn Connection + Send + Sync>)).await;
                }
            }
        } else {
            error!("No peers configured for stack '{}'", self.config.name);
        }
    }

    fn create_connections(
        &self,
        connection_url: &str,       
        peer_host: &String,
        peer_realm: &String,
        key_file: &String,
        cert_file: &String,
        ca_cert_file: &String,
        command_map: &CommandMap,
        avp_map: &AvpMap,
        command_handler: &Arc<DefaultCommandHandler>,
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
                        let conns = self.create_connections(&peers, peer_host, peer_realm, key_file, cert_file, ca_cert_file, command_map, avp_map, command_handler);
                        if conns.len() > 1 {
                            let arc_conns: Vec<Arc<Box<dyn Connection + Send + Sync>>> = conns.into_iter().map(|c| Arc::new(c)).collect();
                            let conn = RoundRobinConnection::new(peer_host.clone(), peer_realm.clone(), arc_conns);
                            vec![Box::new(conn) as Box<dyn Connection + Send + Sync>]
                        } else {
                            conns
                        }
                    }
                    LoadBalancerStrategy::FailOver(peers) => {
                        info!("Connecting to peers with failover: {}", peers);
                        // Implement failover connection logic here
                        let conns = self.create_connections(&peers, peer_host, peer_realm, key_file, cert_file, ca_cert_file, command_map, avp_map, command_handler);
                        if conns.len() > 1 {
                            let arc_conns: Vec<Arc<Box<dyn Connection + Send + Sync>>> = conns.into_iter().map(|c| Arc::new(c)).collect();
                            let conn = FailOverConnection::new(peer_host.clone(), peer_realm.clone(), arc_conns);
                            vec![Box::new(conn) as Box<dyn Connection + Send + Sync>]
                        } else {
                            conns
                        }
                    }
                    LoadBalancerStrategy::Random(peers) => {
                        info!("Connecting to peers randomly: {}", peers);
                        // Implement random connection logic here
                        let conns = self.create_connections(&peers, peer_host, peer_realm, key_file, cert_file, ca_cert_file, command_map, avp_map, command_handler);
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
                                            self.config.host.clone(),
                                            self.config.realm.clone(),
                                            peer_host.clone(),
                                            peer_realm.clone(),
                                            self.config.capability.clone(),
                                            key_file.clone(),
                                            cert_file.clone(),
                                            ca_cert_file.clone(),
                                            self.hop_by_hop_id_generator.clone(),
                                            self.end_to_end_id_generator.clone(),                                            
                                            command_map.clone(),
                                            avp_map.clone(),
                                            self.config.cer_timeout.map_or(Duration::from_secs(3), |t| Duration::from_millis(t)),
                                            self.connection_manager.clone(),
                                            self.hop_by_hop_id_mapper.clone(),        
                                            self.answer_manager.clone(),                                    
                                            command_handler.clone(),
                                            self.alarm_sender.clone(),
                                            self.redirect_host_manager.clone()
                                        );
                                        conn.spawn_start();
                                        Some(Box::new(conn) as Box<dyn Connection + Send + Sync>)
                                    } else if addr.protocol.to_lowercase() == "sctp" {
                                        #[cfg(target_os = "linux")]
                                        {
                                            let addresses = addr
                                                .hosts
                                                .iter()
                                                .map(|host| format!("{}:{}", host, addr.port))
                                                .collect();
                                            let conn = SctpClientConnection::new(
                                                addresses,
                                                self.config.host.clone(),
                                                self.config.realm.clone(),
                                                peer_host.clone(),
                                                peer_realm.clone(),
                                                key_file.clone(),
                                                cert_file.clone(),
                                                ca_cert_file.clone(),
                                                self.hop_by_hop_id_generator.clone(),
                                                self.end_to_end_id_generator.clone(),
                                                self.hop_by_hop_id_mapper.clone(),
                                                command_map.clone(),
                                                avp_map.clone(),
                                                self.connection_manager.clone(),
                                                self.answer_manager.clone(),
                                                self.redirect_host_manager.clone(),
                                                command_handler.clone(),
                                            );
                                            conn.spawn_start();
                                            Some(Box::new(conn) as Box<dyn Connection + Send + Sync>)
                                        }
                                        #[cfg(not(target_os = "linux"))]
                                        {
                                            error!(
                                                "SCTP protocol is only supported on Linux for connection URL '{}'",
                                                values[0]
                                            );
                                            None
                                        }
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
                                .flat_map(|v| self.create_connections(&v,  peer_host, peer_realm, cert_file, key_file, ca_cert_file, command_map, avp_map, command_handler))
                                .collect()
                        }
                    }
                }
            })
            .unwrap_or_default()
    }


    // Additional methods for managing the stack, sending commands, etc.
}
