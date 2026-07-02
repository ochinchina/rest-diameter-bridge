use std::sync::Arc;

use rest_diameter_bridge::transport::{Connection, DummyConnection};

#[tokio::test]
async fn test_round_robin_connection() {
    let mut command = rest_diameter_bridge::command::Command::new(123, 0, 456, 1, 2, vec![]);
    command.set_destination_host(&"test".to_string());
    command.set_destination_realm(&"example.com".to_string());

    let connection1 = Arc::new(Box::new(DummyConnection::new(
        "conn1".to_string(),
        "test".to_string(),
        "example.com".to_string(),
    )) as Box<dyn Connection + Send + Sync>);
    let connection2 = Arc::new(Box::new(DummyConnection::new(
        "conn2".to_string(),
        "test".to_string(),
        "example.com".to_string(),
    )) as Box<dyn Connection + Send + Sync>);
    let round_robin =
        rest_diameter_bridge::transport::RoundRobinConnection::new(vec![connection1, connection2]);
    round_robin.send(&command).await.unwrap()
}
