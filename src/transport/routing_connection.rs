use crate::command::Command;
use crate::config::{RoutingItemConfig, RoutingPolicy, StackRoutingConfig};
use crate::stack::LoadBalancerStrategy;
use crate::transport::{Connection, FailOverConnection, RandomConnection, RoundRobinConnection};
use log::{error, info};
use std::collections::HashMap;
use std::sync::Arc;

#[derive(Clone)]
struct RoutingItem {
    application_ids: Option<Vec<u32>>,
    host_realms: Option<Vec<String>>,
    routing_connection: Arc<Box<dyn Connection + Send + Sync>>,
}

impl RoutingItem {
    fn contains_app_id(&self, app_id: u32) -> bool {
        if self.application_ids.is_none() {
            return true; // If no application IDs specified, it matches all
        }

        self.application_ids
            .as_ref()
            .map_or(false, |ids| ids.contains(&app_id))
    }

    async fn add_connection(&self, connection: Arc<Box<dyn Connection + Send + Sync>>) {
        self.routing_connection.add_connection(connection).await;
    }

    async fn remove_connection(&self, connection: Arc<Box<dyn Connection + Send + Sync>>) {
        self.routing_connection.remove_connection(connection).await;
    }
}

#[derive(Clone)]
pub struct RoutingConnectionManager {
    // Fields for managing routing connections
    policy: RoutingPolicy,
    routing_connections: Arc<HashMap<String, RoutingItem>>,
    default_routing_connection: Option<Arc<Box<dyn Connection + Send + Sync>>>,
}

impl RoutingConnectionManager {
    pub fn new(stack_routing: StackRoutingConfig) -> Self {
        let mut manager = RoutingConnectionManager {
            policy: RoutingPolicy::from_str(&stack_routing.policy).unwrap_or(RoutingPolicy::Realm),
            routing_connections: Arc::new(HashMap::new()),
            default_routing_connection: None,
        };
        if let Some(default_route) = stack_routing.default.clone() {
            info!(
                "Setting up default routing connection with config: {}",
                default_route
            );
            manager.default_routing_connection =
                Some(Arc::new(Box::new(RoutingConnection::new(default_route))));
            info!("Default routing connection set up successfully.");
        } else {
            info!("No default routing connection specified in the configuration.");
        }

        if let Some(items) = stack_routing.items.clone() {
            info!("Setting up routing items with count: {}", items.len());
            items.into_iter().for_each(|item| {
                info!(
                    "Processing routing item with application IDs: {:?} and host/realms: {:?}",
                    item.application_ids, item.host_realms
                );
                let routing_item = Self::create_routing_item(&item);
                info!(
                    "Created routing item with application IDs: {:?} and host/realms: {:?}",
                    routing_item.application_ids, routing_item.host_realms
                );
                if let Some(host_realms) = routing_item.host_realms.clone() {
                    host_realms.into_iter().for_each(|hr| {
                        info!(
                            "Adding routing item for host/realm: {} with application IDs: {:?}",
                            hr, routing_item.application_ids
                        );
                        Arc::get_mut(&mut manager.routing_connections)
                            .unwrap()
                            .insert(hr, routing_item.clone());
                    });
                }
            });
        } else {
            info!("No routing items specified in the configuration.");
        }

        manager
    }

    pub async fn add_connection(&self, connection: Arc<Box<dyn Connection + Send + Sync>>) {
        let host = connection.get_peer_host().unwrap_or_default();
        let realm = connection.get_peer_realm().unwrap_or_default();
        let key = format!("{}@{}", host, realm);

        info!(
            "Try to add connection with host: {}, realm: {} to routing manager",
            host, realm
        );
        for key in [realm.clone(), key.clone()] {
            if let Some(item) = self.routing_connections.get(&key) {
                info!(
                    "Adding connection with host: {}, realm: {} to routing item with key: {}",
                    host, realm, key
                );
                item.add_connection(connection.clone()).await;
            } else {
                info!(
                    "No routing item found for host: {}, realm: {} with key: {}, skipping routing item addition",
                    host, realm, key
                );
            }
        }

        if let Some(default_conn) = &self.default_routing_connection {
            info!(
                "Try to add connection with host: {}, realm: {} to default routing connection",
                host, realm
            );
            default_conn.add_connection(connection).await;
        }
        info!(
            "Finished adding connection with host: {}, realm: {} to routing manager",
            host, realm
        );
    }

    pub async fn remove_connection(&self, connection: Arc<Box<dyn Connection + Send + Sync>>) {
        let host = connection.get_peer_host().unwrap_or_default();
        let realm = connection.get_peer_realm().unwrap_or_default();
        let key = format!("{}@{}", host, realm);

        for key in [realm.clone(), key.clone()] {
            if let Some(item) = self.routing_connections.get(&key) {
                item.remove_connection(connection.clone()).await;
            }
        }

        if let Some(default_conn) = &self.default_routing_connection {
            default_conn.remove_connection(connection).await;
        }
    }

    pub async fn find_send_command(&self, command: &Command) -> Result<(), String> {
        let host = command.get_destination_host().unwrap_or_default();
        let realm = command.get_destination_realm().unwrap_or_default();
        let app_id = command.get_application_id();

        let key = match self.policy {
            RoutingPolicy::Realm => realm.to_string(),
            RoutingPolicy::Host => format!("{}@{}", host, realm),
        };

        if let Some(item) = self.routing_connections.get(&key) {
            if item.contains_app_id(app_id) {
                info!(
                    "Found routing connection for host: {}, realm: {}, app_id: {} with key: {}",
                    host, realm, app_id, key
                );

                item.routing_connection.send(command).await?;
                return Ok(());
            }
        }

        if self.default_routing_connection.is_some() {
            info!(
                "Using default routing connection for host: {}, realm: {}, app_id: {}",
                host, realm, app_id
            );
            self.default_routing_connection
                .as_ref()
                .unwrap()
                .send(command)
                .await?;
            return Ok(());
        }
        error!(
            "No routing connection found for host: {}, realm: {}, app_id: {} with key: {}",
            host, realm, app_id, key
        );
        Err("No routing connection found".to_string())
    }

    fn create_routing_item(item: &RoutingItemConfig) -> RoutingItem {
        let conn = RoutingConnection::new(item.route.clone());
        RoutingItem {
            application_ids: item.application_ids.clone(),
            host_realms: item.host_realms.clone(),
            routing_connection: Arc::new(Box::new(conn)),
        }
    }
}

pub struct RoutingConnection {
    id: String,
    connection: Arc<Box<dyn Connection + Send + Sync>>,
    host_realm_connections: HashMap<String, Arc<Box<dyn Connection + Send + Sync>>>, // Map of (host, realm) to connections
}

impl RoutingConnection {
    pub fn new(config: String) -> Self {
        let mut rc = RoutingConnection {
            id: "routing-connection-".to_owned() + &uuid::Uuid::new_v4().to_string(),
            connection: Arc::new(Box::new(RoundRobinConnection::new(vec![]))),
            host_realm_connections: HashMap::new(),
        };
        if let Some(connections) =
            Self::create_connection_from(config.clone(), &mut rc.host_realm_connections)
        {
            if connections.len() == 1 {
                rc.connection = connections[0].clone();
            } else if connections.len() > 1 {
                rc.connection = Arc::new(Box::new(RoundRobinConnection::new(connections.clone())));
            } else {
                error!(
                    "No valid connections created from config: {}, using empty routing connection",
                    config
                );
            }
        } else {
            error!(
                "Failed to create routing connection from config: {}",
                config
            );
        }
        rc
    }

    pub fn create_connection_from(
        config: String,
        host_realm_connections: &mut HashMap<String, Arc<Box<dyn Connection + Send + Sync>>>,
    ) -> Option<Vec<Arc<Box<dyn Connection + Send + Sync>>>> {
        info!("Creating routing connection(s) from: {}", config);
        if let Some(strategy) = LoadBalancerStrategy::from_str(&config) {
            info!(
                "Creating routing connection(s) using strategy: {:?} for config: {}",
                strategy, config
            );
            match strategy {
                LoadBalancerStrategy::RoundRobin(s) => {
                    if let Some(connections) =
                        Self::create_connection_from(s, host_realm_connections)
                    {
                        return Some(vec![Arc::new(Box::new(RoundRobinConnection::new(
                            connections,
                        )))]);
                    }
                }
                LoadBalancerStrategy::Random(s) => {
                    if let Some(connections) =
                        Self::create_connection_from(s, host_realm_connections)
                    {
                        return Some(vec![Arc::new(Box::new(RandomConnection::new(connections)))]);
                    }
                }
                LoadBalancerStrategy::FailOver(s) => {
                    if let Some(connections) =
                        Self::create_connection_from(s, host_realm_connections)
                    {
                        return Some(vec![Arc::new(Box::new(FailOverConnection::new(
                            connections,
                        )))]);
                    }
                }
                LoadBalancerStrategy::Value(v) => {
                    if v.len() == 1 {
                        info!(
                            "Creating single routing connection for config: {}",
                            v[0].clone()
                        );
                        let conn: Arc<Box<dyn Connection + Send + Sync>> =
                            Arc::new(Box::new(RoundRobinConnection::new(vec![])));

                        host_realm_connections.insert(v[0].clone(), conn.clone());
                        return Some(vec![conn]);
                    } else {
                        let r: Vec<Arc<Box<dyn Connection + Send + Sync>>> = v
                            .iter()
                            .filter_map(|s| {
                                Self::create_connection_from(s.clone(), host_realm_connections)
                            })
                            .flatten()
                            .collect();
                        return Some(r);
                    }
                }
            };
        }
        None
    }
}

#[async_trait::async_trait]
impl Connection for RoutingConnection {
    fn get_id(&self) -> String {
        self.id.clone()
    }

    async fn send(&self, command: &Command) -> Result<(), String> {
        self.connection.send(command).await
    }

    async fn close(&self) -> Result<(), String> {
        self.connection.close().await
    }

    async fn is_closed(&self) -> bool {
        self.connection.is_closed().await
    }

    async fn add_connection(&self, connection: Arc<Box<dyn Connection + Send + Sync>>) {
        let host = connection.get_peer_host().unwrap_or_default();
        let realm = connection.get_peer_realm().unwrap_or_default();
        let key = format!("{}@{}", host, realm);
        info!(
            "Try to add connection with host: {}, realm: {} to routing connection",
            host, realm
        );

        for k in vec![key.clone(), realm.clone()] {
            if let Some(conn) = self.host_realm_connections.get(&k) {
                info!("Adding connection to existing routing item for key: {}", k);
                conn.add_connection(connection.clone()).await;
            } else {
                error!(
                    "No routing item found for key: {}. Connection with host: {}, realm: {} will not be added to any routing item.",
                    k, host, realm
                );
            }
        }
    }

    async fn remove_connection(&self, connection: Arc<Box<dyn Connection + Send + Sync>>) {
        let host = connection.get_peer_host().unwrap_or_default();
        let realm = connection.get_peer_realm().unwrap_or_default();
        let key = format!("{}@{}", host, realm);

        for k in vec![key.clone(), realm.clone()] {
            if let Some(conn) = self.host_realm_connections.get(&k) {
                info!("Removing connection from routing item for key: {}", k);
                conn.remove_connection(connection.clone()).await;
            } else {
                error!(
                    "No routing item found for key: {}. Connection with host: {}, realm: {} will not be removed from any routing item.",
                    k, host, realm
                );
            }
        }
    }

    fn iter(
        &self,
    ) -> Option<Box<dyn Iterator<Item = Arc<Box<dyn Connection + Send + Sync>>> + Send>> {
        self.connection.iter()
    }

    fn get_peer_host(&self) -> Result<String, String> {
        self.connection.get_peer_host()
    }

    fn get_peer_realm(&self) -> Result<String, String> {
        self.connection.get_peer_realm()
    }
}
