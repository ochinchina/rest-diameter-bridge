#![cfg(target_os = "linux")]

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use rest_diameter_bridge::avp::{AvpJson, AvpMap, AvpType};
use rest_diameter_bridge::command::{Command, CommandCode, CommandFlags, CommandJson, CommandMap};
use rest_diameter_bridge::config::StackCapability;
use rest_diameter_bridge::transport::sctp_transport::{SctpClientConnection, SctpDiameterServer};
use rest_diameter_bridge::transport::{
    AnswerManager, CommandHandler, Connection, ConnectionManager, HopByHopIdMapper, IdGenerator,
    RedirectHostManager,
};

struct NoopCommandHandler;

#[async_trait::async_trait]
impl CommandHandler for NoopCommandHandler {
    async fn handle_command(&self, _command: &Command) -> Result<Option<Command>, String> {
        Ok(None)
    }
}

fn make_avp_map() -> AvpMap {
    AvpMap::new(vec![
        AvpJson::new(
            "Origin-Host".to_string(),
            264,
            AvpType::UTF8String,
            true,
            None,
        ),
        AvpJson::new(
            "Origin-Realm".to_string(),
            296,
            AvpType::UTF8String,
            true,
            None,
        ),
        AvpJson::new(
            "Result-Code".to_string(),
            268,
            AvpType::Unsigned32,
            true,
            None,
        ),
        AvpJson::new(
            "Vendor-Id".to_string(),
            266,
            AvpType::Unsigned32,
            true,
            None,
        ),
    ])
}

fn make_command_map() -> CommandMap {
    CommandMap::new(vec![CommandJson::new(
        "Capabilities-Exchange".to_string(),
        "CER".to_string(),
        257,
        0,
        true,
        false,
        false,
        vec![],
    )])
}

fn make_capability() -> StackCapability {
    StackCapability {
        vendor_id: 0,
        product_name: "test".to_string(),
        host_ips: None,
        supported_vendor_ids: None,
        auth_application_ids: Some(vec![4]),
        acct_application_ids: None,
        vendor_specific_application_ids: None,
        inband_security_ids: None,
        firmware_revision: None,
        _extra: HashMap::new(),
    }
}

fn make_connection_manager(
    answer_manager: Arc<Box<AnswerManager>>,
    redirect_host_manager: Arc<Box<RedirectHostManager>>,
) -> Arc<Box<ConnectionManager>> {
    Arc::new(Box::new(ConnectionManager::new(
        Duration::from_secs(5),
        Duration::from_secs(30),
        None,
        answer_manager,
        vec![],
        redirect_host_manager,
    )))
}

fn make_sctp_client(addresses: Vec<String>) -> SctpClientConnection {
    let hop_gen = Arc::new(Box::new(IdGenerator::new()));
    let e2e_gen = Arc::new(Box::new(IdGenerator::new()));
    let hop_mapper = Arc::new(Box::new(HopByHopIdMapper::new()));
    let answer_manager = Arc::new(Box::new(AnswerManager::new()));
    let redirect_host_manager = Arc::new(Box::new(RedirectHostManager::new()));
    let manager = make_connection_manager(answer_manager.clone(), redirect_host_manager.clone());

    SctpClientConnection::new(
        addresses,
        "my-host".to_string(),
        "my-realm".to_string(),
        "peer-host".to_string(),
        "peer-realm".to_string(),
        String::new(),
        String::new(),
        String::new(),
        hop_gen,
        e2e_gen,
        hop_mapper,
        make_command_map(),
        make_avp_map(),
        manager,
        answer_manager,
        redirect_host_manager,
        Arc::new(NoopCommandHandler),
    )
}

fn make_sctp_server(addresses: Vec<String>) -> SctpDiameterServer {
    let hop_gen = Arc::new(Box::new(IdGenerator::new()));
    let hop_mapper = Arc::new(Box::new(HopByHopIdMapper::new()));
    let answer_manager = Arc::new(Box::new(AnswerManager::new()));
    let redirect_host_manager = Arc::new(Box::new(RedirectHostManager::new()));
    let manager = make_connection_manager(answer_manager.clone(), redirect_host_manager.clone());

    SctpDiameterServer::new(
        "server-host".to_string(),
        "server-realm".to_string(),
        make_capability(),
        String::new(),
        String::new(),
        String::new(),
        addresses,
        manager,
        make_command_map(),
        make_avp_map(),
        hop_mapper,
        hop_gen,
        Arc::new(NoopCommandHandler),
        None,
        answer_manager,
        redirect_host_manager,
    )
}

#[test]
fn test_sctp_client_connection_new() {
    let conn = make_sctp_client(vec![
        "127.0.0.1:3868".to_string(),
        "127.0.0.2:3868".to_string(),
    ]);

    assert_eq!(conn.get_id(), "127.0.0.1:3868,127.0.0.2:3868");
    assert_eq!(conn.get_peer_host().unwrap(), "peer-host");
    assert_eq!(conn.get_peer_realm().unwrap(), "peer-realm");
}

#[test]
fn test_sctp_client_connection_can_set_dtls_paths() {
    let hop_gen = Arc::new(Box::new(IdGenerator::new()));
    let e2e_gen = Arc::new(Box::new(IdGenerator::new()));
    let hop_mapper = Arc::new(Box::new(HopByHopIdMapper::new()));
    let answer_manager = Arc::new(Box::new(AnswerManager::new()));
    let redirect_host_manager = Arc::new(Box::new(RedirectHostManager::new()));
    let manager = make_connection_manager(answer_manager.clone(), redirect_host_manager.clone());

    let conn = SctpClientConnection::new(
        vec!["10.0.0.1:5868".to_string()],
        "my-host".to_string(),
        "my-realm".to_string(),
        "dtls-host".to_string(),
        "dtls-realm".to_string(),
        "/tmp/key.pem".to_string(),
        "/tmp/cert.pem".to_string(),
        "/tmp/ca.pem".to_string(),
        hop_gen,
        e2e_gen,
        hop_mapper,
        make_command_map(),
        make_avp_map(),
        manager,
        answer_manager,
        redirect_host_manager,
        Arc::new(NoopCommandHandler),
    );

    assert_eq!(conn.get_id(), "10.0.0.1:5868");
    assert_eq!(conn.get_peer_host().unwrap(), "dtls-host");
    assert_eq!(conn.get_peer_realm().unwrap(), "dtls-realm");
}

#[tokio::test]
async fn test_sctp_client_connection_send_without_connection_fails() {
    let conn = make_sctp_client(vec!["127.0.0.1:3868".to_string()]);
    let command = Command::new(
        CommandCode::DeviceWatchdog as u32,
        CommandFlags::Request as u8,
        0,
        1,
        1,
        vec![],
    );

    let result = conn.send(&command).await;
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("connection not established"));
}

#[tokio::test]
async fn test_sctp_client_connection_trait_methods() {
    let conn = make_sctp_client(vec!["127.0.0.1:3868".to_string()]);

    assert!(!conn.is_container());
    assert!(conn.iter().is_none());
    assert!(!conn.is_closed().await);

    let mut connections: Vec<Arc<Box<dyn Connection + Send + Sync>>> = Vec::new();
    conn.get_connections(&mut connections).await;
    assert!(connections.is_empty());

    assert!(conn.close().await.is_ok());
}

#[test]
fn test_sctp_client_connection_clone() {
    let conn = make_sctp_client(vec!["127.0.0.1:3868".to_string()]);
    let cloned = conn.clone();

    assert_eq!(conn.get_id(), cloned.get_id());
    assert_eq!(conn.get_peer_host(), cloned.get_peer_host());
    assert_eq!(conn.get_peer_realm(), cloned.get_peer_realm());
}

#[test]
fn test_sctp_diameter_server_construction() {
    let server = make_sctp_server(vec!["0.0.0.0:3868".to_string()]);
    drop(server);
}

#[tokio::test]
async fn test_sctp_diameter_server_bind_fails_on_invalid_address() {
    let server = make_sctp_server(vec!["invalid-address".to_string()]);
    let result = server.start().await;
    assert!(result.is_err());
}
