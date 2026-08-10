use rest_diameter_bridge::avp::ResultCode;
use rest_diameter_bridge::transport::{
    AnswerManager, Connection, ConnectionManager, DummyConnection, RoutingConnection,
    RoutingConnectionManager,
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
        &rest_diameter_bridge::config::StackRoutingConfig::new(
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
        RoutingConnectionManager::new(&rest_diameter_bridge::config::StackRoutingConfig::new(
            "realm".to_string(),
            Some("RoundRobin(test@example.com)".to_string()),
            Some(vec![]),
        ));

    let redirect_host_manager = Arc::new(Box::new(
        rest_diameter_bridge::transport::RedirectHostManager::new(),
    ));
    let answer_manager = Arc::new(Box::new(AnswerManager::new()));
    let connection_manager = ConnectionManager::new(
        Duration::from_millis(10 * 1000),
        Duration::from_millis(60 * 1000),
        Some(routing_manager),
        answer_manager.clone(),
        vec![
            ResultCode::DiameterApplicationUnsupported as u32,
            ResultCode::DiameterUnableToDeliver as u32,
            ResultCode::DiameterTooBusy as u32,
        ],
        redirect_host_manager.clone(),
    );
    let connection = Arc::new(Box::new(DummyConnection::new(
        "conn1".to_string(),
        "test".to_string(),
        "example.com".to_string(),
    )) as Box<dyn Connection + Send + Sync>);
    connection_manager.add_connection(connection).await;
    let hop_by_hop_id = 1;
    let mut request = rest_diameter_bridge::command::Command::new(123, rest_diameter_bridge::command::CommandFlags::Request as u8, 456, hop_by_hop_id, 2, vec![]);
    request.set_destination_host(&"test2".to_string());
    request.set_destination_realm(&"example.com".to_string());

    let answer = rest_diameter_bridge::command::Command::new(123, 0, 456, hop_by_hop_id, 2, vec![]);

    answer_manager.prepare_for_answer(hop_by_hop_id, "conn2".to_string(), "unknow-host".to_string(), "unknown-realm".to_string()).await;
    let answer_manager_clone = answer_manager.clone();
    tokio::spawn(async move {
        let conn_info = answer_manager_clone.answer_received(answer).await;
        assert!(conn_info.is_some());
    })  ;
    
    tokio::task::yield_now().await;
    match connection_manager.send_request(&request).await {
        Ok(_) => println!("Command sent successfully through routing manager"),
        Err(e) => panic!("Failed to send command through routing manager: {}", e),
    }
}
