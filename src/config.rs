use log::{error, info};
use std::collections::HashMap;

#[derive(serde::Deserialize, Debug, Clone)]
pub enum RoutingPolicy {
    Realm,
    Host,
}

impl RoutingPolicy {
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_uppercase().as_str() {
            "REALM" => Some(RoutingPolicy::Realm),
            "HOST" => Some(RoutingPolicy::Host),
            _ => None,
        }
    }
}

#[derive(serde::Deserialize, Debug, Clone)]
pub struct PeerConfig {
    // Configuration fields for a Diameter peer
    // e.g., peer URI, supported applications, etc.
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

#[derive(serde::Deserialize, Debug, Clone)]
pub struct RoutingItemConfig {
    // Configuration fields for routing entries
    // e.g., destination realm, application ID, etc.
    #[serde(rename = "host-realms")]
    pub host_realms: Option<Vec<String>>,
    #[serde(rename = "application-ids")]
    pub application_ids: Option<Vec<u32>>,
    pub route: String, // e.g., "RoundRobin(node1;node2)", "FailOver(node1;node2)", etc.
    #[serde(flatten)]
    pub _extra: HashMap<String, serde_yaml::Value>,
}

#[derive(serde::Deserialize, Debug, Clone)]
pub struct StackRoutingConfig {
    pub policy: String,                        // e.g., "REALM", "HOST", etc.
    pub default: Option<String>,               // default next-hop if no routing item matches
    pub items: Option<Vec<RoutingItemConfig>>, // list of routing items
    #[serde(flatten)]
    pub _extra: HashMap<String, serde_yaml::Value>,
}

impl StackRoutingConfig {
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

#[derive(serde::Deserialize, Debug, Clone)]
pub struct VendorSpecificApplicationId {
    #[serde(rename = "vendor-id")]
    pub vendor_id: u32,
    #[serde(rename = "auth-application-id")]
    pub auth_application_id: Option<u32>,
    #[serde(rename = "acct-application-id")]
    pub acct_application_id: Option<u32>,
}

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

#[derive(serde::Deserialize, Debug, Clone)]
pub struct ProcessorConfig {
    pub timeout: Option<u64>, // timeout in milliseconds
    #[serde(rename = "command-codes")]
    pub command_codes: Option<Vec<u32>>,
    #[serde(rename = "application-ids")]
    pub application_ids: Option<Vec<u32>>,
    pub urls: Option<Vec<String>>, // e.g., "http://localhost:8080/diameter"
}

#[derive(serde::Deserialize, Debug, Clone)]
pub struct RestListenerConfig {
    pub address: String, // the address in host:port format, e.g., "127.0.0.1:8080"
    pub path: Option<String>, // the path for the REST endpoint, e.g., "/diameter"
    pub cert_file: Option<String>,
    pub key_file: Option<String>,
    pub ca_cert_file: Option<String>,
}

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

#[derive(serde::Deserialize, Debug, Clone)]
pub struct AlarmDbConfig {
    pub path: Option<String>,
    #[serde(flatten)]
    pub _extra: HashMap<String, serde_yaml::Value>,
}

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
                info!("Parsing stack config: {:?}", stack);
                if let Ok(stack_config) = serde_yaml::from_value::<StackConfig>(stack.clone()) {
                    configs.push(stack_config);
                } else {
                    error!("Failed to parse stack config: {:?}", stack);
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
