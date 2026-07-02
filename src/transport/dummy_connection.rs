use log::info;

use crate::command::Command;
use crate::transport::Connection;

#[derive(Clone)]
pub struct DummyConnection {
    id: String,
    peer_host: String,
    peer_realm: String,
}

impl DummyConnection {
    pub fn new(id: String, peer_host: String, peer_realm: String) -> Self {
        DummyConnection {
            id: id.clone(),
            peer_host: peer_host.clone(),
            peer_realm: peer_realm.clone(),
        }
    }
}

#[async_trait::async_trait]
impl Connection for DummyConnection {
    fn get_id(&self) -> String {
        self.id.clone()
    }

    async fn send(&self, _command: &Command) -> Result<(), String> {
        info!(
            "DummyConnection, send command with id: {}, peer_host: {}, peer_realm: {}, command: {:?}",
            self.id, self.peer_host, self.peer_realm, _command
        );
        Ok(())
    }

    async fn close(&self) -> Result<(), String> {
        info!(
            "DummyConnection closed with id: {}, peer_host: {}, peer_realm: {}",
            self.id, self.peer_host, self.peer_realm
        );
        Ok(())
    }

    async fn is_closed(&self) -> bool {
        false
    }

    fn get_peer_host(&self) -> Result<String, String> {
        Ok(self.peer_host.clone())
    }

    fn get_peer_realm(&self) -> Result<String, String> {
        Ok(self.peer_realm.clone())
    }
}
