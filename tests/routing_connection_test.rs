use rest_diameter_bridge::avp::ResultCode;
use rest_diameter_bridge::transport::{
    Connection, ConnectionManager, DummyConnection, HopByHopIdMapper, IdGenerator,
    RoutingConnection, RoutingConnectionManager,
};
use std::{sync::Arc, time::Duration};

#[tokio::test]
async fn test_routing_connection_creation() {
    let connection = Arc::new(Box::new(DummyConnection::new(
        "conn1".to_string(),
        "test".to_string(),
        "example.com".to_string(),
    )) as Box<dyn Connection + Send + Sync>);
    let routing_connection = RoutingConnection::new("RoundRobin(test@example.com)".to_string());

    routing_connection.add_connection(connection).await;

    let command = rest_diameter_bridge::command::Command::new(123, 0, 456, 1, 2, vec![]);
    routing_connection.send(&command).await.unwrap();
}

#[tokio::test]
async fn test_routing_connection_manager_default_creation() {
    let mut command = rest_diameter_bridge::command::Command::new(123, 0, 456, 1, 2, vec![]);
    command.set_destination_host(&"test".to_string());
    command.set_destination_realm(&"example.com".to_string());

    let routing_manager = rest_diameter_bridge::transport::RoutingConnectionManager::new(
        rest_diameter_bridge::config::StackRoutingConfig::new(
            "realm".to_string(),
            Some("RoundRobin(test@example.com)".to_string()),
            Some(vec![]),
        ),
    );

    let connection = Arc::new(Box::new(DummyConnection::new(
        "conn1".to_string(),
        "test".to_string(),
        "example.com".to_string(),
    )) as Box<dyn Connection + Send + Sync>);

    routing_manager.add_connection(connection).await;

    match routing_manager.find_send_command(&command).await {
        Ok(_) => println!("Successfully sent command through routing manager"),
        Err(e) => panic!("Failed to send command through routing manager: {}", e),
    }
}

#[tokio::test]
async fn test_routing_connection_manager_creation() {
    let _ = env_logger::builder().is_test(true).try_init();
    let routing_manager =
        RoutingConnectionManager::new(rest_diameter_bridge::config::StackRoutingConfig::new(
            "realm".to_string(),
            Some("RoundRobin(test@example.com)".to_string()),
            Some(vec![]),
        ));

    let mut manager = ConnectionManager::new(
        Duration::from_millis(10 * 1000),
        Duration::from_millis(60 * 1000),
        Some(routing_manager),
        Arc::new(HopByHopIdMapper::new(Arc::new(IdGenerator::new()))),
        vec![
            ResultCode::DiameterApplicationUnsupported as u32,
            ResultCode::DiameterUnableToDeliver as u32,
            ResultCode::DiameterTooBusy as u32,
        ],
    );
    let connection = Arc::new(Box::new(DummyConnection::new(
        "conn1".to_string(),
        "test".to_string(),
        "example.com".to_string(),
    )) as Box<dyn Connection + Send + Sync>);
    manager.add_connection(connection).await;
    let mut command = rest_diameter_bridge::command::Command::new(123, 0, 456, 1, 2, vec![]);
    command.set_destination_host(&"test2".to_string());
    command.set_destination_realm(&"example.com".to_string());

    match manager.find_send_command(&command).await {
        Ok(_) => println!("Command sent successfully through routing manager"),
        Err(e) => panic!("Failed to send command through routing manager: {}", e),
    }
}
