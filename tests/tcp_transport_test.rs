use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use rest_diameter_bridge::avp::{AvpJson, AvpMap, AvpType};
use rest_diameter_bridge::command::{Command, CommandCode, CommandFlags, CommandJson, CommandMap};
use rest_diameter_bridge::config::StackCapability;
use rest_diameter_bridge::transport::{
    AnswerManager, Connection, ConnectionManager, HopByHopIdMapper, IdGenerator,
    RedirectHostManager, TcpClientConnection, TcpDiameterServer, TcpServerConnection,
    answer_manager,
};

struct NoopCommandHandler;

#[async_trait::async_trait]
impl rest_diameter_bridge::transport::CommandHandler for NoopCommandHandler {
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
        AvpJson::new(
            "Disconnect-Cause".to_string(),
            273,
            AvpType::Unsigned32,
            true,
            None,
        ),
    ])
}

fn make_command_map() -> CommandMap {
    CommandMap::new(vec![
        CommandJson::new(
            "Capabilities-Exchange".to_string(),
            "CER".to_string(),
            257,
            0,
            true,
            false,
            false,
            vec![],
        ),
        CommandJson::new(
            "Device-Watchdog".to_string(),
            "DWR".to_string(),
            280,
            0,
            true,
            false,
            false,
            vec![],
        ),
        CommandJson::new(
            "Disconnect-Peer".to_string(),
            "DPR".to_string(),
            282,
            0,
            true,
            false,
            false,
            vec![],
        ),
    ])
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

fn make_connection_manager() -> Arc<Box<ConnectionManager>> {
    let redirect_host_manager = Arc::new(Box::new(RedirectHostManager::new()));
    let answer_manager = Arc::new(Box::new(answer_manager::AnswerManager::new()));
    Arc::new(Box::new(ConnectionManager::new(
        Duration::from_secs(5),
        Duration::from_secs(30),
        None,
        answer_manager.clone(),
        vec![],
        redirect_host_manager.clone(),
    )))
}

// === TcpClientConnection Construction Tests ===

#[test]
fn test_tcp_client_connection_new() {
    let hop_gen = Arc::new(Box::new(IdGenerator::new()));
    let e2e_gen = Arc::new(Box::new(IdGenerator::new()));
    let redirect_host_manager = Arc::new(Box::new(RedirectHostManager::new()));
    let hop_mapper = Arc::new(Box::new(HopByHopIdMapper::new()));
    let manager = make_connection_manager();

    let conn = TcpClientConnection::new(
        "127.0.0.1:3868".to_string(),
        "my-host".to_string(),
        "my-realm".to_string(),
        "peer-host".to_string(),
        "peer-realm".to_string(),
        make_capability(),
        String::new(),
        String::new(),
        String::new(),
        hop_gen,
        e2e_gen,
        make_command_map(),
        make_avp_map(),
        Duration::from_millis(10 * 1000),
        manager,
        hop_mapper,
        Arc::new(Box::new(AnswerManager::new())),
        Arc::new(NoopCommandHandler),
        None,
        redirect_host_manager.clone(),
    );

    assert_eq!(conn.get_id(), "127.0.0.1:3868");
    assert_eq!(conn.get_peer_host().unwrap(), "peer-host");
    assert_eq!(conn.get_peer_realm().unwrap(), "peer-realm");
}

#[test]
fn test_tcp_client_connection_clone() {
    let hop_gen = Arc::new(Box::new(IdGenerator::new()));
    let e2e_gen = Arc::new(Box::new(IdGenerator::new()));
    let redirect_host_manager = Arc::new(Box::new(RedirectHostManager::new()));
    let hop_mapper = Arc::new(Box::new(HopByHopIdMapper::new()));
    let manager = make_connection_manager();

    let conn = TcpClientConnection::new(
        "10.0.0.1:3868".to_string(),
        "host-a".to_string(),
        "realm-a".to_string(),
        "host-b".to_string(),
        "realm-b".to_string(),
        make_capability(),
        String::new(),
        String::new(),
        String::new(),
        hop_gen,
        e2e_gen,
        make_command_map(),
        make_avp_map(),
        Duration::from_millis(10 * 1000),
        manager,
        hop_mapper,
        Arc::new(Box::new(AnswerManager::new())),
        Arc::new(NoopCommandHandler),
        None,
        redirect_host_manager.clone(),
    );

    let cloned = conn.clone();
    assert_eq!(conn.get_id(), cloned.get_id());
    assert_eq!(conn.get_peer_host(), cloned.get_peer_host());
    assert_eq!(conn.get_peer_realm(), cloned.get_peer_realm());
}

// === TcpClientConnection Connection Trait Tests ===

#[tokio::test]
async fn test_tcp_client_connection_send_non_cer_without_connection_fails() {
    let hop_gen = Arc::new(Box::new(IdGenerator::new()));
    let e2e_gen = Arc::new(Box::new(IdGenerator::new()));
    let redirect_host_manager = Arc::new(Box::new(RedirectHostManager::new()));
    let hop_mapper = Arc::new(Box::new(HopByHopIdMapper::new()));
    let manager = make_connection_manager();

    let conn = TcpClientConnection::new(
        "127.0.0.1:3868".to_string(),
        "host".to_string(),
        "realm".to_string(),
        "peer".to_string(),
        "peer-realm".to_string(),
        make_capability(),
        String::new(),
        String::new(),
        String::new(),
        hop_gen,
        e2e_gen,
        make_command_map(),
        make_avp_map(),
        Duration::from_millis(10 * 1000),
        manager,
        hop_mapper,
        Arc::new(Box::new(AnswerManager::new())),
        Arc::new(NoopCommandHandler),
        None,
        redirect_host_manager.clone(),
    );

    // Sending a non-CER command without an established connection should fail
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
    assert!(
        result
            .unwrap_err()
            .contains("Connection not established, cannot send command")
    );
}

#[tokio::test]
async fn test_tcp_client_connection_send_cer_without_writer_fails() {
    let hop_gen = Arc::new(Box::new(IdGenerator::new()));
    let e2e_gen = Arc::new(Box::new(IdGenerator::new()));
    let redirect_host_manager = Arc::new(Box::new(RedirectHostManager::new()));
    let hop_mapper = Arc::new(Box::new(HopByHopIdMapper::new()));
    let manager = make_connection_manager();

    let conn = TcpClientConnection::new(
        "127.0.0.1:3868".to_string(),
        "host".to_string(),
        "realm".to_string(),
        "peer".to_string(),
        "peer-realm".to_string(),
        make_capability(),
        String::new(),
        String::new(),
        String::new(),
        hop_gen,
        e2e_gen,
        make_command_map(),
        make_avp_map(),
        Duration::from_millis(10 * 1000),
        manager,
        hop_mapper,
        Arc::new(Box::new(AnswerManager::new())),
        Arc::new(NoopCommandHandler),
        None,
        redirect_host_manager.clone(),
    );

    // CER bypasses the connected check but writer is None
    let cer = Command::new(
        CommandCode::CapabilitiesExchange as u32,
        CommandFlags::Request as u8,
        0,
        1,
        1,
        vec![],
    );

    let result = conn.send(&cer).await;
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("Connection not established"));
}

#[tokio::test]
async fn test_tcp_client_connection_is_not_container() {
    let hop_gen = Arc::new(Box::new(IdGenerator::new()));
    let e2e_gen = Arc::new(Box::new(IdGenerator::new()));
    let redirect_host_manager = Arc::new(Box::new(RedirectHostManager::new()));
    let hop_mapper = Arc::new(Box::new(HopByHopIdMapper::new()));
    let manager = make_connection_manager();

    let conn = TcpClientConnection::new(
        "127.0.0.1:3868".to_string(),
        "host".to_string(),
        "realm".to_string(),
        "peer".to_string(),
        "peer-realm".to_string(),
        make_capability(),
        String::new(),
        String::new(),
        String::new(),
        hop_gen,
        e2e_gen,
        make_command_map(),
        make_avp_map(),
        Duration::from_millis(10 * 1000),
        manager,
        hop_mapper,
        Arc::new(Box::new(AnswerManager::new())),
        Arc::new(NoopCommandHandler),
        None,
        redirect_host_manager.clone(),
    );

    assert!(!conn.is_container());
    assert!(conn.iter().is_none());
}

#[tokio::test]
async fn test_tcp_client_connection_get_connections_returns_empty() {
    let hop_gen = Arc::new(Box::new(IdGenerator::new()));
    let e2e_gen = Arc::new(Box::new(IdGenerator::new()));
    let redirect_host_manager = Arc::new(Box::new(RedirectHostManager::new()));
    let hop_mapper = Arc::new(Box::new(HopByHopIdMapper::new()));
    let manager = make_connection_manager();

    let conn = TcpClientConnection::new(
        "127.0.0.1:3868".to_string(),
        "host".to_string(),
        "realm".to_string(),
        "peer".to_string(),
        "peer-realm".to_string(),
        make_capability(),
        String::new(),
        String::new(),
        String::new(),
        hop_gen,
        e2e_gen,
        make_command_map(),
        make_avp_map(),
        Duration::from_millis(10 * 1000),
        manager,
        hop_mapper,
        Arc::new(Box::new(AnswerManager::new())),
        Arc::new(NoopCommandHandler),
        None,
        redirect_host_manager.clone(),
    );

    let mut connections: Vec<Arc<Box<dyn Connection + Send + Sync>>> = Vec::new();
    conn.get_connections(&mut connections).await;
    assert!(connections.is_empty());
}

// === TcpServerConnection Tests ===

#[tokio::test]
async fn test_tcp_server_connection_send_and_close() {
    let hop_gen = Arc::new(Box::new(IdGenerator::new()));
    let redirect_host_manager = Arc::new(Box::new(RedirectHostManager::new()));
    let hop_mapper = Arc::new(Box::new(HopByHopIdMapper::new()));
    let manager = make_connection_manager();

    // Create a pair of connected TCP streams
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let client_handle =
        tokio::spawn(async move { tokio::net::TcpStream::connect(addr).await.unwrap() });

    let (server_stream, peer_addr) = listener.accept().await.unwrap();
    let client_stream = client_handle.await.unwrap();

    let (reader, writer) = server_stream.into_split();
    let reader: Box<dyn tokio::io::AsyncRead + Send + Unpin> = Box::new(reader);
    let writer: Box<dyn tokio::io::AsyncWrite + Send + Unpin> = Box::new(writer);

    let conn = TcpServerConnection::new(
        peer_addr.to_string(),
        reader,
        writer,
        "my-host".to_string(),
        "my-realm".to_string(),
        "client-host".to_string(),
        "client-realm".to_string(),
        make_command_map(),
        make_avp_map(),
        manager,
        hop_gen,
        hop_mapper,
        Arc::new(Box::new(AnswerManager::new())),
        Arc::new(NoopCommandHandler),
        None,
        redirect_host_manager.clone(),
    );

    assert_eq!(conn.get_id(), peer_addr.to_string());
    assert_eq!(conn.get_peer_host().unwrap(), "client-host");
    assert_eq!(conn.get_peer_realm().unwrap(), "client-realm");
    assert!(!conn.is_container());
    assert!(conn.iter().is_none());
    assert!(!conn.is_closed().await);

    // Send a response command (no hop-by-hop remapping for responses)
    let command = Command::new(
        CommandCode::CapabilitiesExchange as u32,
        0,
        0,
        100,
        200,
        vec![],
    );
    let result = conn.send(&command).await;
    assert!(result.is_ok());

    // Verify data was received on the client side
    use tokio::io::AsyncReadExt;
    let mut client_stream = client_stream;
    let mut buf = [0u8; 4];
    let n = client_stream.read(&mut buf).await.unwrap();
    assert!(n > 0);

    // Close the connection
    let result = conn.close().await;
    assert!(result.is_ok());
    assert!(conn.is_closed().await);
}

#[tokio::test]
async fn test_tcp_server_connection_close_marks_closed() {
    let hop_gen = Arc::new(Box::new(IdGenerator::new()));
    let redirect_host_manager = Arc::new(Box::new(RedirectHostManager::new()));
    let hop_mapper = Arc::new(Box::new(HopByHopIdMapper::new()));
    let manager = make_connection_manager();

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let client_handle =
        tokio::spawn(async move { tokio::net::TcpStream::connect(addr).await.unwrap() });

    let (server_stream, peer_addr) = listener.accept().await.unwrap();
    let _client_stream = client_handle.await.unwrap();

    let (reader, writer) = server_stream.into_split();
    let reader: Box<dyn tokio::io::AsyncRead + Send + Unpin> = Box::new(reader);
    let writer: Box<dyn tokio::io::AsyncWrite + Send + Unpin> = Box::new(writer);

    let conn = TcpServerConnection::new(
        peer_addr.to_string(),
        reader,
        writer,
        "host".to_string(),
        "realm".to_string(),
        "peer".to_string(),
        "peer-realm".to_string(),
        make_command_map(),
        make_avp_map(),
        manager,
        hop_gen,
        hop_mapper,
        Arc::new(Box::new(AnswerManager::new())),
        Arc::new(NoopCommandHandler),
        None,
        redirect_host_manager.clone(),
    );

    assert!(!conn.is_closed().await);
    conn.close().await.unwrap();
    assert!(conn.is_closed().await);

    // Send after close should fail
    let command = Command::new(257, 0, 0, 1, 1, vec![]);
    let result = conn.send(&command).await;
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("closed"));
}

#[tokio::test]
async fn test_tcp_server_connection_get_connections_empty() {
    let hop_gen = Arc::new(Box::new(IdGenerator::new()));
    let redirect_host_manager = Arc::new(Box::new(RedirectHostManager::new()));
    let hop_mapper = Arc::new(Box::new(HopByHopIdMapper::new()));
    let manager = make_connection_manager();

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let client_handle =
        tokio::spawn(async move { tokio::net::TcpStream::connect(addr).await.unwrap() });

    let (server_stream, peer_addr) = listener.accept().await.unwrap();
    let _client_stream = client_handle.await.unwrap();

    let (reader, writer) = server_stream.into_split();
    let reader: Box<dyn tokio::io::AsyncRead + Send + Unpin> = Box::new(reader);
    let writer: Box<dyn tokio::io::AsyncWrite + Send + Unpin> = Box::new(writer);

    let conn = TcpServerConnection::new(
        peer_addr.to_string(),
        reader,
        writer,
        "host".to_string(),
        "realm".to_string(),
        "peer".to_string(),
        "peer-realm".to_string(),
        make_command_map(),
        make_avp_map(),
        manager,
        hop_gen,
        hop_mapper,
        Arc::new(Box::new(AnswerManager::new())),
        Arc::new(NoopCommandHandler),
        None,
        redirect_host_manager.clone(),
    );

    let mut connections: Vec<Arc<Box<dyn Connection + Send + Sync>>> = Vec::new();
    conn.get_connections(&mut connections).await;
    assert!(connections.is_empty());
}

// === TcpDiameterServer Tests ===

#[test]
fn test_tcp_diameter_server_construction() {
    let hop_gen = Arc::new(Box::new(IdGenerator::new()));
    let redirect_host_manager = Arc::new(Box::new(RedirectHostManager::new()));
    let hop_mapper = Arc::new(Box::new(HopByHopIdMapper::new()));
    let manager = make_connection_manager();

    let server = TcpDiameterServer::new(
        "server-host".to_string(),
        "server-realm".to_string(),
        make_capability(),
        String::new(),
        String::new(),
        String::new(),
        "0.0.0.0:3868".to_string(),
        manager,
        make_command_map(),
        make_avp_map(),
        hop_gen,
        hop_mapper,
        Arc::new(Box::new(AnswerManager::new())),
        Arc::new(NoopCommandHandler),
        None,
        redirect_host_manager.clone(),
    );

    drop(server);
}

#[tokio::test]
async fn test_tcp_diameter_server_bind_fails_on_invalid_address() {
    let hop_gen = Arc::new(Box::new(IdGenerator::new()));
    let redirect_host_manager = Arc::new(Box::new(RedirectHostManager::new()));
    let hop_mapper = Arc::new(Box::new(HopByHopIdMapper::new()));
    let manager = make_connection_manager();

    let server = TcpDiameterServer::new(
        "server-host".to_string(),
        "server-realm".to_string(),
        make_capability(),
        String::new(),
        String::new(),
        String::new(),
        "invalid-address-no-port".to_string(),
        manager,
        make_command_map(),
        make_avp_map(),
        hop_gen,
        hop_mapper,
        Arc::new(Box::new(AnswerManager::new())),
        Arc::new(NoopCommandHandler),
        None,
        redirect_host_manager.clone(),
    );

    let result = server.start().await;
    assert!(result.is_err());
}

// === TcpDiameterServer CER/CEA Integration Test ===

#[tokio::test]
async fn test_tcp_server_accepts_cer_and_sends_cea() {
    use rest_diameter_bridge::avp::{Avp, AvpCode, AvpFlags};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let hop_gen = Arc::new(Box::new(IdGenerator::new()));
    let redirect_host_manager = Arc::new(Box::new(RedirectHostManager::new()));
    let hop_mapper = Arc::new(Box::new(HopByHopIdMapper::new()));
    let manager = make_connection_manager();

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server = TcpDiameterServer::new(
        "server-host".to_string(),
        "server-realm".to_string(),
        make_capability(),
        String::new(),
        String::new(),
        String::new(),
        addr.to_string(),
        manager,
        make_command_map(),
        make_avp_map(),
        hop_gen,
        hop_mapper,
        Arc::new(Box::new(AnswerManager::new())),
        Arc::new(NoopCommandHandler),
        None,
        redirect_host_manager.clone(),
    );

    // Drop the listener so the server can rebind
    drop(listener);

    // Start the server in background
    let server_handle = tokio::spawn(async move { server.start().await });

    // Give the server a moment to start listening
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Connect as client and send CER
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();

    let cer = Command::new(
        CommandCode::CapabilitiesExchange as u32,
        CommandFlags::Request as u8,
        0,
        1,
        1,
        vec![
            Avp::from_utf8_string(
                AvpCode::OriginHost as u32,
                AvpFlags::Mandatory as u8,
                None,
                "client-host",
            ),
            Avp::from_utf8_string(
                AvpCode::OriginRealm as u32,
                AvpFlags::Mandatory as u8,
                None,
                "client-realm",
            ),
        ],
    );

    let encoded = cer.encode();
    stream.write_all(&encoded).await.unwrap();

    // Read CEA response
    let mut buf = vec![0u8; 4096];
    let n = stream.read(&mut buf).await.unwrap();
    assert!(n > 0);

    // Parse the response - first 4 bytes contain the length
    let message_length = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) & 0x00FFFFFF;
    assert_eq!(message_length as usize, n);

    // Verify it's a CEA (command code 257, answer)
    let command_code = u32::from_be_bytes([0, buf[5], buf[6], buf[7]]);
    assert_eq!(command_code, CommandCode::CapabilitiesExchange as u32);
    // Flags byte at offset 4 - should NOT have Request bit (0x80) set
    assert_eq!(
        buf[4] & 0x80,
        0,
        "CEA should be an answer (Request bit not set)"
    );

    // Clean up
    stream.shutdown().await.ok();
    server_handle.abort();
}

// === TcpClientConnection Integration Test ===

#[tokio::test]
async fn test_tcp_client_connects_and_exchanges_cer_cea() {
    use rest_diameter_bridge::avp::{Avp, AvpCode, AvpFlags};
    use rest_diameter_bridge::command::CommandBuffer;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let hop_gen = Arc::new(Box::new(IdGenerator::new()));
    let e2e_gen = Arc::new(Box::new(IdGenerator::new()));
    let redirect_host_manager = Arc::new(Box::new(RedirectHostManager::new()));
    let hop_mapper = Arc::new(Box::new(HopByHopIdMapper::new()));
    let manager = make_connection_manager();

    // Start a mock server that accepts CER and responds with CEA
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let mock_server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut buf = vec![0u8; 4096];

        // Read CER
        let n = stream.read(&mut buf).await.unwrap();
        assert!(n > 0);

        // Parse incoming CER
        let mut cmd_buf = CommandBuffer::new();
        cmd_buf.append(&buf[..n]);
        let commands = cmd_buf.read_commands();
        assert_eq!(commands.len(), 1);
        let cer = &commands[0];
        assert_eq!(cer.code, CommandCode::CapabilitiesExchange as u32);
        assert!(cer.is_request());

        // Send CEA response
        let cea = Command::new(
            CommandCode::CapabilitiesExchange as u32,
            0,
            0,
            cer.hop_by_hop_id,
            cer.end_to_end_id,
            vec![
                Avp::from_utf8_string(
                    AvpCode::OriginHost as u32,
                    AvpFlags::Mandatory as u8,
                    None,
                    "server-host",
                ),
                Avp::from_utf8_string(
                    AvpCode::OriginRealm as u32,
                    AvpFlags::Mandatory as u8,
                    None,
                    "server-realm",
                ),
                Avp::from_unsigned32(
                    AvpCode::ResultCode as u32,
                    AvpFlags::Mandatory as u8,
                    None,
                    2001,
                ),
            ],
        );
        stream.write_all(&cea.encode()).await.unwrap();

        // Keep connection open briefly then close
        tokio::time::sleep(Duration::from_millis(200)).await;
        stream.shutdown().await.ok();
    });

    // Give mock server time to start
    tokio::time::sleep(Duration::from_millis(50)).await;

    let mut conn = TcpClientConnection::new(
        addr.to_string(),
        "my-host".to_string(),
        "my-realm".to_string(),
        "server-host".to_string(),
        "server-realm".to_string(),
        make_capability(),
        String::new(),
        String::new(),
        String::new(),
        hop_gen,
        e2e_gen,
        make_command_map(),
        make_avp_map(),
        Duration::from_millis(10 * 1000),
        manager,
        hop_mapper,
        Arc::new(Box::new(AnswerManager::new())),
        Arc::new(NoopCommandHandler),
        None,
        redirect_host_manager.clone(),
    );

    // Start the client connection - it will connect, exchange CER/CEA,
    // then exit when the mock server closes the connection
    let client_handle = tokio::spawn(async move { conn.start().await });

    // Wait for mock server to finish
    mock_server.await.unwrap();

    // The client should eventually return after detecting server close
    tokio::time::sleep(Duration::from_millis(300)).await;
    client_handle.abort();
}

// === Type-level Tests ===

#[test]
fn test_tcp_client_connection_implements_connection_trait() {
    fn assert_connection<T: Connection + Clone + Send + Sync>() {}
    assert_connection::<TcpClientConnection>();
}

#[test]
fn test_tcp_server_connection_implements_connection_trait() {
    fn assert_connection<T: Connection + Clone + Send + Sync>() {}
    assert_connection::<TcpServerConnection>();
}
