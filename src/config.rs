use log::{error, info};
use std::collections::HashMap;

/// Determines how incoming Diameter commands are matched to routing entries.
#[derive(serde::Deserialize, Debug, Clone)]
pub enum RoutingPolicy {
    /// Match on the Destination-Realm AVP only.
    Realm,
    /// Match on both Destination-Host and Destination-Realm (formatted as `host@realm`).
    Host,
}

impl RoutingPolicy {
    /// Parses a `RoutingPolicy` from a string slice (case-insensitive).
    /// Returns `None` if the value is not `"REALM"`, `"HOST"`.
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_uppercase().as_str() {
            "REALM" => Some(RoutingPolicy::Realm),
            "HOST" => Some(RoutingPolicy::Host),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            RoutingPolicy::Realm => "REALM",
            RoutingPolicy::Host => "HOST",
        }
    }
}

impl Default for RoutingPolicy {
    fn default() -> Self {
        RoutingPolicy::Realm
    }
}
/// Configuration for a single remote Diameter peer.
#[derive(serde::Deserialize, Debug, Clone)]
pub struct PeerConfig {
    pub host: String,
    #[serde(rename = "connection-url")]
    pub connection_url: String,
    #[serde(rename = "cert-file")]
    pub cert_file: Option<String>,
    #[serde(rename = "key-file")]
    pub key_file: Option<String>,
    #[serde(rename = "ca-cert-file")]
    pub ca_cert_file: Option<String>,
    #[serde(flatten)]
    pub _extra: HashMap<String, serde_yaml::Value>,
}

/// A single entry in the routing table that maps one or more host/realm keys and
/// optional application IDs to a next-hop route expression.
#[derive(serde::Deserialize, Debug, Clone)]
pub struct RoutingItemConfig {
    // e.g., destination realm, application ID, etc.
    #[serde(rename = "host-realms")]
    pub host_realms: Option<Vec<String>>,
    #[serde(rename = "application-ids")]
    pub application_ids: Option<Vec<u32>>,
    pub route: String, // e.g., "RoundRobin(node1;node2)", "FailOver(node1;node2)", etc.
    #[serde(flatten)]
    pub _extra: HashMap<String, serde_yaml::Value>,
}

/// Top-level routing configuration for a Diameter stack.
///
/// Controls which [`RoutingPolicy`] is applied and lists the individual routing items.
#[derive(serde::Deserialize, Debug, Clone)]
pub struct StackRoutingConfig {
    pub policy: String,          // e.g., "REALM", "HOST", "REDIRECT", etc.
    pub default: Option<String>, // default next-hop if no routing item matches
    pub items: Option<Vec<RoutingItemConfig>>, // list of routing items
    #[serde(flatten)]
    pub _extra: HashMap<String, serde_yaml::Value>,
}

impl StackRoutingConfig {
    /// Creates a new `StackRoutingConfig`.
    ///
    /// # Arguments
    /// * `policy` - Routing policy string (`"REALM"` or `"HOST"`).
    /// * `default` - Optional default route expression used when no routing item matches.
    /// * `items` - Optional list of specific routing entries.
    pub fn new(
        policy: String,
        default: Option<String>,
        items: Option<Vec<RoutingItemConfig>>,
    ) -> Self {
        StackRoutingConfig {
            policy,
            default,
            items,
            _extra: HashMap::new(),
        }
    }
}

/// Vendor-Specific-Application-Id grouped AVP contents used in capability exchange.
#[derive(serde::Deserialize, Debug, Clone)]
pub struct VendorSpecificApplicationId {
    #[serde(rename = "vendor-id")]
    pub vendor_id: u32,
    #[serde(rename = "auth-application-id")]
    pub auth_application_id: Option<u32>,
    #[serde(rename = "acct-application-id")]
    pub acct_application_id: Option<u32>,
}

/// Local Diameter stack capability settings sent in Capabilities-Exchange-Request messages.
#[derive(serde::Deserialize, Debug, Clone)]
pub struct StackCapability {
    #[serde(rename = "vendor-id")]
    pub vendor_id: u32,
    #[serde(rename = "product-name")]
    pub product_name: String,
    #[serde(rename = "host-ips")]
    pub host_ips: Option<Vec<String>>,
    #[serde(rename = "supported-vendor-ids")]
    pub supported_vendor_ids: Option<Vec<u32>>,
    #[serde(rename = "auth-application-ids")]
    pub auth_application_ids: Option<Vec<u32>>,
    #[serde(rename = "acct-application-ids")]
    pub acct_application_ids: Option<Vec<u32>>,
    #[serde(rename = "vendor-specific-application-ids")]
    pub vendor_specific_application_ids: Option<Vec<VendorSpecificApplicationId>>,
    #[serde(rename = "inband-security-ids")]
    pub inband_security_ids: Option<Vec<u32>>,
    #[serde(rename = "firmware-revision")]
    pub firmware_revision: Option<u32>,
    #[serde(flatten)]
    pub _extra: HashMap<String, serde_yaml::Value>,
}

/// Configuration for an HTTP/REST processor that receives forwarded Diameter commands.
#[derive(serde::Deserialize, Debug, Clone)]
pub struct ProcessorConfig {
    pub timeout: Option<u64>, // timeout in milliseconds
    #[serde(rename = "command-codes")]
    pub command_codes: Option<Vec<u32>>,
    #[serde(rename = "application-ids")]
    pub application_ids: Option<Vec<u32>>,
    pub urls: Option<Vec<String>>, // e.g., "http://localhost:8080/diameter"
}

/// Configuration for the REST/HTTP listener that accepts commands from external clients.
#[derive(serde::Deserialize, Debug, Clone)]
pub struct RestListenerConfig {
    pub address: String, // the address in host:port format, e.g., "127.0.0.1:8080"
    pub path: Option<String>, // the path for the REST endpoint, e.g., "/diameter"
    pub cert_file: Option<String>,
    pub key_file: Option<String>,
    pub ca_cert_file: Option<String>,
}

/// Configuration for an inbound Diameter TCP/SCTP listener.
#[derive(serde::Deserialize, Debug, Clone)]
pub struct ListenerConfig {
    pub address: String,
    #[serde(rename = "cert-file")]
    pub cert_file: Option<String>,
    #[serde(rename = "key-file")]
    pub key_file: Option<String>,
    #[serde(rename = "ca-cert-file")]
    pub ca_cert_file: Option<String>,
    #[serde(flatten)]
    pub _extra: HashMap<String, serde_yaml::Value>,
}

/// Configuration for the SQLite database used to persist active alarms across restarts.
#[derive(serde::Deserialize, Debug, Clone)]
pub struct AlarmDbConfig {
    pub path: Option<String>,
    #[serde(flatten)]
    pub _extra: HashMap<String, serde_yaml::Value>,
}

/// Configuration for the external alarm manager integration.
#[derive(serde::Deserialize, Debug, Clone)]
pub struct AlarmManagementConfig {
    #[serde(rename = "alarm-manager-url")]
    pub alarm_manager_url: Option<String>,
    #[serde(rename = "cert-file")]
    pub cert_file: Option<String>,
    #[serde(rename = "key-file")]
    pub key_file: Option<String>,
    #[serde(rename = "ca-cert-file")]
    pub ca_cert_file: Option<String>,
    #[serde(rename = "alarm-db")]
    pub alarm_db: Option<AlarmDbConfig>,
    #[serde(rename = "alarm-rest-path")]
    pub alarm_rest_path: Option<String>,
    #[serde(flatten)]
    pub _extra: HashMap<String, serde_yaml::Value>,
}

/// Complete configuration for one Diameter stack instance, loaded from the YAML config file.
#[derive(serde::Deserialize, Debug, Clone)]
pub struct StackConfig {
    pub name: String,
    pub host: String,
    pub realm: String,
    #[serde(rename = "request-timeout")]
    pub request_timeout: Option<u64>,
    #[serde(rename = "connection-request-timeout")]
    pub connection_request_timeout: Option<u64>,
    #[serde(rename = "cer-timeout")]
    pub cer_timeout: Option<u64>,
    #[serde(rename = "dpr-timeout")]
    pub dpr_timeout: Option<u64>,
    #[serde(rename = "dwr-timeout")]
    pub dwr_timeout: Option<u64>,
    #[serde(rename = "alarm-management")]
    pub alarm_management: Option<AlarmManagementConfig>,
    pub listen: Option<Vec<ListenerConfig>>,
    #[serde(rename = "rest-listen")]
    pub rest_listen: Option<Vec<RestListenerConfig>>,
    #[serde(rename = "my-request-processors")]
    pub my_request_processors: Option<Vec<ProcessorConfig>>,
    #[serde(rename = "request-retry-result-codes")]
    pub request_retry_result_codes: Option<Vec<u32>>,
    pub peers: Option<Vec<PeerConfig>>,
    pub capability: StackCapability,
    pub routing: Option<StackRoutingConfig>,
    #[serde(rename = "avp-files")]
    pub avp_files: Option<Vec<String>>,
    #[serde(rename = "command-files")]
    pub command_files: Option<Vec<String>>,
    #[serde(flatten)]
    pub _extra: HashMap<String, serde_yaml::Value>,
}

/// Parses one or more [`StackConfig`] entries from a YAML configuration file.
///
/// The file must contain a top-level `stacks` sequence.
///
/// # Arguments
/// * `filename` - Path to the YAML configuration file.
///
/// # Returns
/// * `Ok(Vec<StackConfig>)` containing all successfully parsed stack configurations.
/// * `Err(String)` if the file cannot be read or parsed.
pub fn load_stack_configs(filename: &str) -> Result<Vec<StackConfig>, String> {
    let s = std::fs::read_to_string(filename)
        .map_err(|e| format!("Failed to read stack config file: {}", e))?;
    let yaml: serde_yaml::Value = serde_yaml::from_str(&s)
        .map_err(|e| format!("Failed to parse stack config file: {}", e))?;
    // Convert the serde_yaml::Value to Vec<StackConfig>
    if yaml.is_mapping() && yaml.get("stacks").is_some() {
        let stacks = yaml.get("stacks").unwrap();
        if stacks.is_sequence() {
            let mut configs: Vec<StackConfig> = Vec::new();
            stacks.as_sequence().unwrap().iter().for_each(|stack| {
                info!(
                    "Parsing stack config: {}",
                    serde_yaml::to_string(stack).unwrap()
                );
                if let Ok(stack_config) = serde_yaml::from_value::<StackConfig>(stack.clone()) {
                    configs.push(stack_config);
                } else {
                    error!(
                        "Failed to parse stack config: {}",
                        serde_yaml::to_string(stack).unwrap()
                    );
                }
            });
            Ok(configs)
        } else {
            Err("The 'stacks' key should contain a sequence of stack configurations".to_string())
        }
    } else {
        Err("Invalid stack config format".to_string())
    }
}
