use crate::alarm::AlarmSender;
use crate::avp::{Avp, AvpCode, AvpFlags, AvpMap, ResultCode, STANDARD_AVP_MAP, name_value_to_avp};
use crate::command::{
    Command, CommandCode, CommandFlags, CommandMap, STANDARD_COMMAND_MAP,
    create_json_from_command_pretty,
};
use crate::config::StackCapability;
use crate::transport::{
    Connection, ConnectionManager, HopByHopIdMapper, IdGenerator, read_command,
    replace_hop_by_hop_id,
};
use crate::utils::{creat_capability_avps, is_empty_file};
use log::{debug, error, info};
use serde_json::Value;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::select;
use tokio::sync::Mutex;
use tokio::time::interval;

type BoxedWriter = Box<dyn AsyncWrite + Send + Unpin>;
type BoxedReader = Box<dyn AsyncRead + Send + Unpin>;

#[derive(Clone)]
pub struct TcpClientConnection {
    address: String,
    my_host: String,
    my_realm: String,
    peer_host: String,
    peer_realm: String,
    capability: StackCapability,
    key_file: String,
    cert_file: String,
    ca_cert_file: String,
    cer_timeout: u64,
    hop_by_hop_id_generator: Arc<IdGenerator>,
    end_to_end_id_generator: Arc<IdGenerator>,
    command_map: CommandMap,
    avp_map: AvpMap,
    writer: Arc<Mutex<Option<BoxedWriter>>>,
    connection_manager: Arc<Mutex<ConnectionManager>>,
    connected: Arc<std::sync::atomic::AtomicBool>,
    hop_by_hop_id_mapper: Arc<HopByHopIdMapper>,
    command_handler: Arc<dyn crate::transport::CommandHandler + Send + Sync>,
    alarm_sender: Option<AlarmSender>,
}

impl TcpClientConnection {
    pub fn new(
        address: String,
        my_host: String,
        my_realm: String,
        peer_host: String,
        peer_realm: String,
        capability: StackCapability,
        key_file: String,
        cert_file: String,
        ca_cert_file: String,
        hop_by_hop_id_generator: Arc<IdGenerator>,
        end_to_end_id_generator: Arc<IdGenerator>,
        cer_timeout: u64,
        connection_manager: Arc<Mutex<ConnectionManager>>,
        hop_by_hop_id_mapper: Arc<HopByHopIdMapper>,
        command_handler: Arc<dyn crate::transport::CommandHandler + Send + Sync>,
        alarm_sender: Option<AlarmSender>,
    ) -> Self {
        TcpClientConnection {
            address,
            my_host,
            my_realm,
            peer_host,
            peer_realm,
            capability,
            key_file,
            cert_file,
            ca_cert_file,
            cer_timeout,
            hop_by_hop_id_generator,
            end_to_end_id_generator,
            command_map: STANDARD_COMMAND_MAP.clone(),
            avp_map: STANDARD_AVP_MAP.clone(),
            writer: Arc::new(Mutex::new(None)),
            connection_manager,
            connected: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            hop_by_hop_id_mapper,
            command_handler,
            alarm_sender,
        }
    }

    pub fn spawn_start(&self) {
        let mut conn = self.clone();
        tokio::spawn(async move {
            if let Err(e) = conn.start().await {
                error!("TcpClientConnection start error: {}", e);
            }
        });
    }

    fn build_tls_connector(&self) -> Result<Option<tokio_rustls::TlsConnector>, String> {
        if self.cert_file.is_empty() || self.key_file.is_empty() {
            return Ok(None);
        }
        if is_empty_file(&self.cert_file) || is_empty_file(&self.key_file) {
            return Ok(None);
        }

        let cert_pem = std::fs::read(&self.cert_file)
            .map_err(|e| format!("Failed to read cert file {}: {}", self.cert_file, e))?;
        let key_pem = std::fs::read(&self.key_file)
            .map_err(|e| format!("Failed to read key file {}: {}", self.key_file, e))?;

        let certs: Vec<rustls::pki_types::CertificateDer<'static>> =
            rustls_pemfile::certs(&mut &cert_pem[..])
                .filter_map(|r| r.ok())
                .collect();
        if certs.is_empty() {
            return Err(format!("No certificates found in {}", self.cert_file));
        }

        let key = rustls_pemfile::private_key(&mut &key_pem[..])
            .map_err(|e| format!("Failed to parse key file {}: {}", self.key_file, e))?
            .ok_or_else(|| format!("No private key found in {}", self.key_file))?;

        let root_store = if !self.ca_cert_file.is_empty() && !is_empty_file(&self.ca_cert_file) {
            // mTLS: use custom CA to verify server certificate
            let ca_pem = std::fs::read(&self.ca_cert_file)
                .map_err(|e| format!("Failed to read CA cert file {}: {}", self.ca_cert_file, e))?;
            let ca_certs: Vec<rustls::pki_types::CertificateDer<'static>> =
                rustls_pemfile::certs(&mut &ca_pem[..])
                    .filter_map(|r| r.ok())
                    .collect();

            let mut store = rustls::RootCertStore::empty();
            for cert in ca_certs {
                store
                    .add(cert)
                    .map_err(|e| format!("Failed to add CA cert: {}", e))?;
            }
            store
        } else {
            // Use default webpki roots for server verification
            let mut store = rustls::RootCertStore::empty();
            store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            store
        };

        let config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_client_auth_cert(certs, rustls::pki_types::PrivateKeyDer::from(key))
            .map_err(|e| format!("Failed to build TLS client config: {}", e))?;

        Ok(Some(tokio_rustls::TlsConnector::from(Arc::new(config))))
    }

    pub async fn start(&mut self) -> Result<(), String> {
        let tls_connector = self.build_tls_connector()?;
        loop {
            match TcpStream::connect(&self.address).await {
                Ok(stream) => {
                    info!("Successfully connected to server at {}", self.address);

                    let (mut reader, writer): (BoxedReader, BoxedWriter) =
                        if let Some(ref connector) = tls_connector {
                            let server_name =
                                rustls::pki_types::ServerName::try_from(self.peer_host.clone())
                                    .map_err(|e| format!("Invalid server name: {}", e))?;
                            let tls_stream = connector
                                .connect(server_name, stream)
                                .await
                                .map_err(|e| format!("TLS handshake failed: {}", e))?;
                            info!("TLS connection established to {}", self.address);
                            let (r, w) = tokio::io::split(tls_stream);
                            (Box::new(r), Box::new(w))
                        } else {
                            let (r, w) = stream.into_split();
                            (Box::new(r), Box::new(w))
                        };

                    self.writer.lock().await.replace(writer);
                    self.send_cer().await?;

                    select! {
                        r = self.receive_cea(&mut reader) => {
                            if r.is_err() {
                                error!("Failed to receive CEA: {}", r.err().unwrap());
                                self.close().await.ok();
                                continue;
                            } else {
                                info!("CEA received and processed successfully");
                                 self.connected.store(true, Ordering::Relaxed);
                                 if let Some(alarm_sender) = &self.alarm_sender {
                                     alarm_sender.clear_alarm(&self.address, &self.peer_host, &self.peer_realm).await;
                                 }
                                 self.handle_connection(reader).await?;
                                 // Connection lost after being established
                                 self.connected.store(false, Ordering::Relaxed);
                                 if let Some(alarm_sender) = &self.alarm_sender {
                                     alarm_sender.raise_alarm(
                                         &self.address,
                                         &self.peer_host,
                                         &self.peer_realm,
                                         &format!("Lost connection to diameter peer {}@{} at {}", self.peer_host, self.peer_realm, self.address),
                                     ).await;
                                 }
                            }

                        }
                        _ = tokio::time::sleep(Duration::from_secs(self.cer_timeout)) => {
                            error!("CER timeout after {} seconds", self.cer_timeout);
                            self.close().await.ok();
                            continue;
                        }
                    }
                }
                Err(e) => {
                    error!(
                        "Failed to connect to server at {}: {}. Retrying in 5 seconds...",
                        self.address, e
                    );
                    if let Some(alarm_sender) = &self.alarm_sender {
                        alarm_sender
                            .raise_alarm(
                                &self.address,
                                &self.peer_host,
                                &self.peer_realm,
                                &format!(
                                    "Failed to connect to diameter peer {}@{} at {}: {}",
                                    self.peer_host, self.peer_realm, self.address, e
                                ),
                            )
                            .await;
                    }
                }
            }
        }
    }

    async fn receive_cea(&self, reader: &mut BoxedReader) -> Result<(), String> {
        match read_command(reader).await {
            Ok(command) => {
                if command.code != CommandCode::CapabilitiesExchange as u32 || !command.is_answer()
                {
                    return Err(format!(
                        "Expected CEA with command code {}, got {}",
                        CommandCode::CapabilitiesExchange as u32,
                        command.code
                    ));
                }

                if let Some(result_code) = command.get_result_code() {
                    if result_code < 2000 || result_code >= 3000 {
                        return Err(format!(
                            "Connection rejected by server with result code {}",
                            result_code
                        ));
                    } else {
                        return Ok(());
                    }
                } else {
                    return Err("CEA response missing Result-Code AVP".to_string());
                }
            }
            Err(e) => Err(format!("Failed to read CEA response: {}", e)),
        }
    }

    async fn send_cer(&self) -> Result<(), String> {
        let mut avps = vec![
            name_value_to_avp(
                "Origin-Host",
                &Value::String(self.my_host.clone()),
                &self.avp_map,
            )
            .unwrap(),
            name_value_to_avp(
                "Origin-Realm",
                &Value::String(self.my_realm.clone()),
                &self.avp_map,
            )
            .unwrap(),
        ];

        avps.extend(creat_capability_avps(&self.capability, &self.avp_map));

        let cer_command = Command::new(
            CommandCode::CapabilitiesExchange as u32,
            CommandFlags::Request as u8 | CommandFlags::Proxiable as u8,
            0,
            self.hop_by_hop_id_generator.next_id(),
            self.end_to_end_id_generator.next_id(),
            avps,
        );
        info!(
            "Sending CER: {} to tcp server: {}",
            create_json_from_command_pretty(&cer_command, &self.command_map, &self.avp_map),
            self.address
        );
        self.send(&cer_command).await
    }

    fn is_connected(&self) -> bool {
        self.connected.load(Ordering::Relaxed)
    }

    async fn send_command(
        writer: Arc<Mutex<Option<BoxedWriter>>>,
        command: &Command,
    ) -> Result<(), String> {
        let data = command.encode();
        writer
            .lock()
            .await
            .as_mut()
            .ok_or_else(|| "Connection not established".to_string())?
            .write_all(&data)
            .await
            .map_err(|e| format!("Failed to write to connection: {}", e))?;
        Ok(())
    }

    async fn send_dwr(&self) -> Result<(), String> {
        let dwr_command = Command::new(
            CommandCode::DeviceWatchdog as u32,
            CommandFlags::Request as u8 | CommandFlags::Proxiable as u8,
            0,
            self.hop_by_hop_id_generator.next_id(),
            self.end_to_end_id_generator.next_id(),
            vec![
                name_value_to_avp(
                    "Origin-Host",
                    &Value::String(self.my_host.clone()),
                    &self.avp_map,
                )
                .unwrap(),
                name_value_to_avp(
                    "Origin-Realm",
                    &Value::String(self.my_realm.clone()),
                    &self.avp_map,
                )
                .unwrap(),
                //name_value_to_avp("Origin-State-Id", &Value::Number(1.into()), &self.avp_map).unwrap(),
            ],
        );
        info!(
            "Sending DWR: {} to tcp server: {}",
            create_json_from_command_pretty(&dwr_command, &self.command_map, &self.avp_map),
            self.address
        );
        Self::send_command(self.writer.clone(), &dwr_command).await
    }

    async fn send_dwa(&self) -> Result<(), String> {
        let dwa_command = Command::new(
            CommandCode::DeviceWatchdog as u32,
            CommandFlags::Proxiable as u8,
            0,
            self.hop_by_hop_id_generator.next_id(),
            self.end_to_end_id_generator.next_id(),
            vec![
                Avp::from_utf8_string(
                    AvpCode::OriginHost as u32,
                    AvpFlags::Mandatory as u8,
                    None,
                    &self.my_host,
                ),
                Avp::from_utf8_string(
                    AvpCode::OriginRealm as u32,
                    AvpFlags::Mandatory as u8,
                    None,
                    &self.my_realm,
                ),
            ],
        );
        info!(
            "Sending DWA: {} to tcp server: {}",
            create_json_from_command_pretty(&dwa_command, &self.command_map, &self.avp_map),
            self.address
        );
        Self::send_command(self.writer.clone(), &dwa_command).await
    }
    async fn send_dpr_command(&self) -> Result<(), String> {
        let dpr_command = Command::new(
            CommandCode::DisconnectPeer as u32,
            CommandFlags::Request as u8 | CommandFlags::Proxiable as u8,
            0,
            self.hop_by_hop_id_generator.next_id(),
            self.end_to_end_id_generator.next_id(),
            vec![
                Avp::from_utf8_string(
                    AvpCode::OriginHost as u32,
                    AvpFlags::Mandatory as u8,
                    None,
                    &self.my_host,
                ),
                Avp::from_utf8_string(
                    AvpCode::OriginRealm as u32,
                    AvpFlags::Mandatory as u8,
                    None,
                    &self.my_realm,
                ),
                Avp::from_unsigned32(
                    AvpCode::DisconnectCause as u32,
                    AvpFlags::Mandatory as u8,
                    None,
                    0,
                ),
            ],
        );
        info!(
            "Sending DPR: {} to tcp server: {}",
            create_json_from_command_pretty(&dpr_command, &self.command_map, &self.avp_map),
            self.address
        );
        Self::send_command(self.writer.clone(), &dpr_command).await?;
        Ok(())
    }

    async fn handle_connection(&self, mut reader: BoxedReader) -> Result<(), String> {
        let mut buffer = [0; 1024];
        let mut command_buffer = crate::command::CommandBuffer::new();
        let mut ticker = interval(Duration::from_secs(30));
        let mut first_tick = true;
        let address = self.address.clone();
        loop {
            tokio::select! {
                _ = ticker.tick() => {
                    info!("Connection idle for 30 seconds, send DWR.");
                    if first_tick {
                        first_tick = false;
                        continue; // Skip the first tick to avoid sending DWR immediately after connection
                    }
                    self.send_dwr().await?;
                }
                result = reader.read(&mut buffer) => {
                    match result {
                        Ok(0) => {
                            info!("Connection closed by server");
                            return Ok(());
                        }
                        Ok(n) => {
                            debug!("Received {} bytes: {:?}", n, &buffer[..n]);
                            command_buffer.append(&buffer[..n]);
                            let commands = command_buffer.read_commands();
                            for mut command in commands {
                                info!(
                                    "Received {} command: {} from tcp server: {}",
                                    if command.is_request() {
                                        "request"
                                    } else {
                                        "answer"
                                    },
                                    create_json_from_command_pretty(&command, &self.command_map, &self.avp_map),
                                    address
                                );
                                match self.process_command(&mut command).await {
                                    Ok(_) => (),
                                    Err(e) => {
                                        error!("Failed to process command: {}", e);
                                        return Err(format!("Failed to process command: {}", e));
                                    }
                                }

                            }
                        }
                        Err(e) => {
                            error!("Failed to read from connection: {}", e);
                            return Err(format!("Failed to read from connection: {}", e));
                        }
                    }
                }
            }
        }
    }

    async fn process_command(&self, command: &mut Command) -> Result<(), String> {
        if command.code == CommandCode::DeviceWatchdog as u32 {
            if command.is_request() {
                self.send_dwa().await?;
            } else {
                info!("Received DWA response from server, connection is healthy");
            }
        } else if command.code == CommandCode::DisconnectPeer as u32 && command.is_request() {
            self.process_dpr(command).await?;
        } else if self.is_my_origin_request(command) {
            error!(
                "Diameter loop detected for command with code {} and hop-by-hop ID {}. Sending error response.",
                command.code, command.hop_by_hop_id
            );
            let mut response = command.create_response();
            response.set_origin_host(&self.my_host);
            response.set_origin_realm(&self.my_realm);
            response.set_destination_host(&self.peer_host);
            response.set_destination_realm(&self.peer_realm);
            response.set_result_code(ResultCode::DiameterLoopDetected.as_u32());
            self.connection_manager
                .lock()
                .await
                .find_send_command(&response)
                .await
                .map_err(|e| format!("Failed to send response: {}", e))?;
        } else if self.is_my_command(&command) {
            info!(
                "The {} with code {} is for this stack (my_host: {}, my_realm: {}), processing locally",
                if command.is_request() {
                    "request"
                } else {
                    "answer"
                },
                command.code,
                self.my_host,
                self.my_realm
            );
            match self.command_handler.handle_command(command).await {
                Ok(Some(answer)) => {
                    info!(
                        "Generated answer for request with code {} and hop-by-hop ID {}: {}",
                        command.code,
                        command.hop_by_hop_id,
                        create_json_from_command_pretty(&answer, &self.command_map, &self.avp_map)
                    );
                    self.connection_manager
                        .lock()
                        .await
                        .find_send_command(&answer)
                        .await
                        .map_err(|e| format!("Failed to send answer: {}", e))?;
                }
                Ok(None) => {
                    info!(
                        "No answer generated for {} with code {} and hop-by-hop ID {}",
                        if command.is_request() {
                            "request"
                        } else {
                            "answer"
                        },
                        command.code,
                        command.hop_by_hop_id
                    );
                }
                Err(e) => {
                    error!(
                        "Failed to handle {} with code {} and hop-by-hop ID {}: {}",
                        if command.is_request() {
                            "request"
                        } else {
                            "answer"
                        },
                        command.code,
                        command.hop_by_hop_id,
                        e
                    );
                }
            }
        } else {
            info!(
                "The {} with code {} is not for this stack (my_host: {}, my_realm: {}), forwarding to connection manager",
                if command.is_request() {
                    "request"
                } else {
                    "answer"
                },
                command.code,
                self.my_host,
                self.my_realm
            );

            replace_hop_by_hop_id(command, &self.hop_by_hop_id_mapper);

            let guard = self.connection_manager.lock().await;
            match guard.find_send_command(&command).await {
                Ok(_) => {
                    info!(
                        "Successfully sent command through connection manager to {}@{}",
                        command.get_destination_host().unwrap_or_default(),
                        command.get_destination_realm().unwrap_or_default()
                    );
                }
                Err(e) => {
                    error!("Failed to send command through connection manager: {}", e);
                }
            }
        }

        Ok(())
    }

    fn is_my_command(&self, command: &Command) -> bool {
        let destination_host = command.get_destination_host().unwrap_or_default();
        let destination_realm = command.get_destination_realm().unwrap_or_default();
        return destination_host == self.my_host && destination_realm == self.my_realm;
    }

    fn is_my_origin_request(&self, command: &Command) -> bool {
        if command.is_answer() {
            return false;
        }

        let origin_host = command.get_origin_host().unwrap_or_default();
        let origin_realm = command.get_origin_realm().unwrap_or_default();
        return origin_host == self.my_host && origin_realm == self.my_realm;
    }
    async fn process_dpr(&self, command: &Command) -> Result<(), String> {
        info!(
            "Received DPR from server {}, closing connection",
            self.address
        );
        let dwa = Command::new(
            CommandCode::DisconnectPeer as u32,
            CommandFlags::Proxiable as u8,
            0,
            command.hop_by_hop_id,
            command.end_to_end_id,
            vec![
                Avp::from_utf8_string(
                    AvpCode::OriginHost as u32,
                    AvpFlags::Mandatory as u8,
                    None,
                    &self.my_host,
                ),
                Avp::from_utf8_string(
                    AvpCode::OriginRealm as u32,
                    AvpFlags::Mandatory as u8,
                    None,
                    &self.my_realm,
                ),
                Avp::from_unsigned32(
                    AvpCode::DisconnectCause as u32,
                    AvpFlags::Mandatory as u8,
                    None,
                    0,
                ),
            ],
        );
        self.send(&dwa).await?;
        self.close().await
    }
}

#[async_trait::async_trait]
impl Connection for TcpClientConnection {
    fn get_id(&self) -> String {
        self.address.clone()
    }

    async fn send(&self, command: &Command) -> Result<(), String> {
        if command.code != CommandCode::CapabilitiesExchange as u32 && !self.is_connected() {
            return Err("Connection not established, cannot send command".to_string());
        }
        let data = command.encode();
        let mut guard = self.writer.lock().await;
        guard
            .as_mut()
            .ok_or_else(|| "Connection not established".to_string())?
            .write_all(&data)
            .await
            .map_err(|e| format!("Failed to write to connection: {}", e))?;

        Ok(())
    }

    async fn close(&self) -> Result<(), String> {
        // Implement closing the TCP connection
        self.send_dpr_command().await?;

        let mut guard = self.writer.lock().await;
        guard
            .as_mut()
            .ok_or_else(|| "Connection not established".to_string())?
            .shutdown()
            .await
            .map_err(|e| format!("Failed to close connection: {}", e))?;
        Ok(())
    }

    async fn is_closed(&self) -> bool {
        // Implement checking if the connection is closed
        false
    }

    fn get_peer_host(&self) -> Result<String, String> {
        Ok(self.peer_host.clone())
    }

    fn get_peer_realm(&self) -> Result<String, String> {
        Ok(self.peer_realm.clone())
    }
}

#[derive(Clone)]
pub struct TcpServerConnection {
    id: String,
    my_host: String,
    my_realm: String,
    peer_host: String,
    peer_realm: String,
    avp_map: AvpMap,
    command_map: CommandMap,
    writer: Arc<Mutex<Option<BoxedWriter>>>,
    closed: Arc<std::sync::atomic::AtomicBool>,
    hop_by_hop_id_mapper: Arc<HopByHopIdMapper>,
    command_handler: Arc<dyn crate::transport::CommandHandler + Send + Sync>,
    alarm_sender: Option<AlarmSender>,
}

impl TcpServerConnection {
    pub fn new(
        peer_addr: String,
        reader: BoxedReader,
        writer: BoxedWriter,
        my_host: String,
        my_realm: String,
        peer_host: String,
        peer_realm: String,
        command_map: CommandMap,
        avp_map: AvpMap,
        connection_manager: Arc<Mutex<ConnectionManager>>,
        hop_by_hop_id_mapper: Arc<HopByHopIdMapper>,
        command_handler: Arc<dyn crate::transport::CommandHandler + Send + Sync>,
        alarm_sender: Option<AlarmSender>,
    ) -> Self {
        let closed = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let conn = TcpServerConnection {
            id: peer_addr.clone(),
            my_host: my_host.clone(),
            my_realm: my_realm.clone(),
            peer_host: peer_host.clone(),
            peer_realm: peer_realm.clone(),
            avp_map: avp_map.clone(),
            command_map: command_map.clone(),
            writer: Arc::new(Mutex::new(Some(writer))),
            closed: closed.clone(),
            hop_by_hop_id_mapper: hop_by_hop_id_mapper.clone(),
            command_handler: command_handler.clone(),
            alarm_sender: alarm_sender.clone(),
        };

        let mut conn_clone = conn.clone();

        tokio::spawn(async move {
            connection_manager
                .lock()
                .await
                .add_connection(Arc::new(Box::new(conn_clone.clone())))
                .await;
            if let Some(alarm_sender) = &conn_clone.alarm_sender {
                alarm_sender
                    .clear_alarm(
                        &conn_clone.id,
                        &conn_clone.peer_host,
                        &conn_clone.peer_realm,
                    )
                    .await;
            }
            conn_clone
                .handle_connection(reader, connection_manager.clone())
                .await
                .ok();
            if let Some(alarm_sender) = &conn_clone.alarm_sender {
                alarm_sender
                    .raise_alarm(
                        &conn_clone.id,
                        &conn_clone.peer_host,
                        &conn_clone.peer_realm,
                        &format!(
                            "Lost connection from diameter peer {}@{} at {}",
                            conn_clone.peer_host, conn_clone.peer_realm, conn_clone.id
                        ),
                    )
                    .await;
            }
            connection_manager
                .lock()
                .await
                .remove_connection_by_id(&conn_clone.get_id())
                .await;
        });

        conn
    }

    async fn handle_connection(
        &mut self,
        mut reader: BoxedReader,
        connection_manager: Arc<Mutex<ConnectionManager>>,
    ) -> Result<(), String> {
        let mut buffer = [0; 1024];
        let mut command_buffer = crate::command::CommandBuffer::new();
        loop {
            match reader.read(&mut buffer).await {
                Ok(0) => {
                    info!("Connection closed by client");
                    return Ok(());
                }
                Ok(n) => {
                    debug!("Received {} bytes: {:?}", n, &buffer[..n]);
                    command_buffer.append(&buffer[..n]);
                    let commands = command_buffer.read_commands();
                    for mut command in commands {
                        match self
                            .process_command(&mut command, &connection_manager)
                            .await
                        {
                            Ok(_) => {}
                            Err(e) => {
                                error!("Failed to process command: {}", e);
                            }
                        }
                    }
                }
                Err(e) => {
                    error!("Failed to read from connection: {}", e);
                    return Err(format!("Failed to read from connection: {}", e));
                }
            }
        }
    }

    async fn process_command(
        &mut self,
        command: &mut Command,
        connection_manager: &Arc<Mutex<ConnectionManager>>,
    ) -> Result<(), String> {
        // Implement command processing logic here
        info!(
            "Received {} command: {} from tcp client: {}",
            if command.is_request() {
                "request"
            } else {
                "answer"
            },
            create_json_from_command_pretty(&command, &self.command_map, &self.avp_map),
            self.id
        );
        if command.code == CommandCode::DeviceWatchdog as u32 && command.is_request() {
            self.process_dwa(command).await?;
        } else if command.code == CommandCode::DisconnectPeer as u32 && command.is_request() {
            self.process_dpr(command).await?;
        } else if self.is_my_command(command) {
            if command.get_result_code() == Some(ResultCode::DiameterLoopDetected as u32) {
                error!(
                    "Diameter loop detected for command with code {} and hop-by-hop ID {}. Ignoring.",
                    command.code, command.hop_by_hop_id
                );
                return Ok(());
            }

            info!(
                "The {} with code {} is for this stack (my_host: {}, my_realm: {}), processing locally",
                if command.is_request() {
                    "request"
                } else {
                    "answer"
                },
                command.code,
                self.my_host,
                self.my_realm
            );
            match self.command_handler.handle_command(command).await {
                Ok(Some(answer)) => {
                    info!(
                        "Generated answer for request with code {} and hop-by-hop ID {}: {}",
                        command.code,
                        command.hop_by_hop_id,
                        create_json_from_command_pretty(&answer, &self.command_map, &self.avp_map)
                    );
                    connection_manager
                        .lock()
                        .await
                        .find_send_command(&answer)
                        .await
                        .map_err(|e| format!("Failed to send answer: {}", e))?;
                }
                Ok(None) => {
                    info!(
                        "No answer generated for {} with code {} and hop-by-hop ID {}",
                        if command.is_request() {
                            "request"
                        } else {
                            "answer"
                        },
                        command.code,
                        command.hop_by_hop_id
                    );
                }
                Err(e) => {
                    error!(
                        "Failed to handle {} with code {} and hop-by-hop ID {}: {}",
                        if command.is_request() {
                            "request"
                        } else {
                            "answer"
                        },
                        command.code,
                        command.hop_by_hop_id,
                        e
                    );
                }
            }
        } else {
            return self.forward_command(command, connection_manager).await;
        }
        Err("Command is not for this stack".to_string())
    }

    async fn forward_command(
        &mut self,
        command: &mut Command,
        connection_manager: &Arc<Mutex<ConnectionManager>>,
    ) -> Result<(), String> {
        info!(
            "The {} with code {} is not for this stack (my_host: {}, my_realm: {}), forwarding to connection manager",
            if command.is_request() {
                "request"
            } else {
                "answer"
            },
            command.code,
            self.my_host,
            self.my_realm
        );

        replace_hop_by_hop_id(command, &self.hop_by_hop_id_mapper);
        let guard = connection_manager.lock().await;

        match guard.find_send_command(command).await {
            Ok(_) => Ok(()),
            Err(e) => {
                if command.is_request() {
                    let mut answer = command.create_response();
                    answer.set_origin_host(&self.my_host);
                    answer.set_origin_realm(&self.my_realm);
                    answer.set_result_code(ResultCode::DiameterUnableToDeliver.as_u32());
                    replace_hop_by_hop_id(&mut answer, &self.hop_by_hop_id_mapper);
                    if let Err(e) = guard.find_send_command(&answer).await {
                        error!("Failed to send error response: {}", e);
                    }
                }
                Err(format!(
                    "Failed to send command through connection manager: {}",
                    e
                ))
            }
        }?;
        Ok(())
    }

    fn is_my_command(&self, command: &Command) -> bool {
        let destination_host = command.get_destination_host().unwrap_or_default();
        let destination_realm = command.get_destination_realm().unwrap_or_default();
        return destination_host == self.my_host && destination_realm == self.my_realm;
    }

    async fn process_dwa(&mut self, command: &Command) -> Result<(), String> {
        let dwa = Command::new(
            CommandCode::DeviceWatchdog as u32,
            CommandFlags::Proxiable as u8,
            0,
            command.hop_by_hop_id,
            command.end_to_end_id,
            vec![
                Avp::from_utf8_string(
                    AvpCode::OriginHost as u32,
                    AvpFlags::Mandatory as u8,
                    None,
                    &self.my_host,
                ),
                Avp::from_utf8_string(
                    AvpCode::OriginRealm as u32,
                    AvpFlags::Mandatory as u8,
                    None,
                    &self.my_realm,
                ),
                Avp::from_unsigned32(
                    AvpCode::ResultCode as u32,
                    AvpFlags::Mandatory as u8,
                    None,
                    2001,
                ),
            ],
        );
        info!(
            "Sending DWA: {} to tcp client: {}",
            create_json_from_command_pretty(&dwa, &self.command_map, &self.avp_map),
            self.id
        );
        self.send(&dwa).await
    }

    async fn process_dpr(&mut self, command: &Command) -> Result<(), String> {
        let dpr = Command::new(
            CommandCode::DisconnectPeer as u32,
            CommandFlags::Proxiable as u8,
            0,
            command.hop_by_hop_id,
            command.end_to_end_id,
            vec![
                Avp::from_utf8_string(
                    AvpCode::OriginHost as u32,
                    AvpFlags::Mandatory as u8,
                    None,
                    &self.my_host,
                ),
                Avp::from_utf8_string(
                    AvpCode::OriginRealm as u32,
                    AvpFlags::Mandatory as u8,
                    None,
                    &self.my_realm,
                ),
                Avp::from_unsigned32(
                    AvpCode::ResultCode as u32,
                    AvpFlags::Mandatory as u8,
                    None,
                    2001,
                ),
            ],
        );
        info!(
            "Sending DPR: {} to tcp client: {}",
            create_json_from_command_pretty(&dpr, &self.command_map, &self.avp_map),
            self.id
        );
        self.send(&dpr).await?;
        self.close().await
    }
}

#[async_trait::async_trait]
impl Connection for TcpServerConnection {
    fn get_id(&self) -> String {
        self.id.clone()
    }

    async fn send(&self, command: &Command) -> Result<(), String> {
        info!(
            "Sending command with code {} and hop-by-hop ID {} to tcp client {}: {}",
            command.code,
            command.hop_by_hop_id,
            format!("{}@{}", self.peer_host, self.peer_realm),
            create_json_from_command_pretty(command, &self.command_map, &self.avp_map)
        );
        let data = command.encode();
        let mut guard = self.writer.lock().await;
        guard
            .as_mut()
            .ok_or_else(|| "Connection already closed".to_string())?
            .write_all(&data)
            .await
            .map_err(|e| format!("Failed to write to connection: {}", e))?;
        Ok(())
    }

    async fn close(&self) -> Result<(), String> {
        let mut guard = self.writer.lock().await;
        if let Some(writer) = guard.as_mut() {
            writer
                .shutdown()
                .await
                .map_err(|e| format!("Failed to close connection: {}", e))?;
        }
        *guard = None;
        self.closed.store(true, Ordering::Relaxed);
        Ok(())
    }

    async fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Relaxed)
    }

    fn get_peer_host(&self) -> Result<String, String> {
        Ok(self.peer_host.clone())
    }

    fn get_peer_realm(&self) -> Result<String, String> {
        Ok(self.peer_realm.clone())
    }
}

pub struct TcpDiameterServer {
    host: String,
    realm: String,
    capability: StackCapability,
    key_file: String,
    cert_file: String,
    ca_cert_file: String,
    address: String,
    manager: Arc<Mutex<ConnectionManager>>,
    command_map: CommandMap,
    avp_map: AvpMap,
    hop_by_hop_id_mapper: Arc<HopByHopIdMapper>,
    command_handler: Arc<dyn crate::transport::CommandHandler + Send + Sync>,
    alarm_sender: Option<AlarmSender>,
}

impl TcpDiameterServer {
    pub fn new(
        host: String,
        realm: String,
        capability: StackCapability,
        key_file: String,
        cert_file: String,
        ca_cert_file: String,
        address: String,
        manager: Arc<Mutex<ConnectionManager>>,
        command_map: CommandMap,
        avp_map: AvpMap,
        hop_by_hop_id_mapper: Arc<HopByHopIdMapper>,
        command_handler: Arc<dyn crate::transport::CommandHandler + Send + Sync>,
        alarm_sender: Option<AlarmSender>,
    ) -> Self {
        TcpDiameterServer {
            host,
            realm,
            capability,
            key_file,
            cert_file,
            ca_cert_file,
            address,
            manager,
            command_map,
            avp_map,
            hop_by_hop_id_mapper,
            command_handler,
            alarm_sender,
        }
    }

    fn build_tls_acceptor(&self) -> Result<Option<tokio_rustls::TlsAcceptor>, String> {
        if self.cert_file.is_empty() || self.key_file.is_empty() {
            return Ok(None);
        }
        if is_empty_file(&self.cert_file) || is_empty_file(&self.key_file) {
            return Ok(None);
        }

        let cert_pem = std::fs::read(&self.cert_file)
            .map_err(|e| format!("Failed to read cert file {}: {}", self.cert_file, e))?;
        let key_pem = std::fs::read(&self.key_file)
            .map_err(|e| format!("Failed to read key file {}: {}", self.key_file, e))?;

        let certs: Vec<rustls::pki_types::CertificateDer<'static>> =
            rustls_pemfile::certs(&mut &cert_pem[..])
                .filter_map(|r| r.ok())
                .collect();
        if certs.is_empty() {
            return Err(format!("No certificates found in {}", self.cert_file));
        }

        let key = rustls_pemfile::private_key(&mut &key_pem[..])
            .map_err(|e| format!("Failed to parse key file {}: {}", self.key_file, e))?
            .ok_or_else(|| format!("No private key found in {}", self.key_file))?;

        let config = if !self.ca_cert_file.is_empty() && !is_empty_file(&self.ca_cert_file) {
            // mTLS: require client certificate verification
            let ca_pem = std::fs::read(&self.ca_cert_file)
                .map_err(|e| format!("Failed to read CA cert file {}: {}", self.ca_cert_file, e))?;
            let ca_certs: Vec<rustls::pki_types::CertificateDer<'static>> =
                rustls_pemfile::certs(&mut &ca_pem[..])
                    .filter_map(|r| r.ok())
                    .collect();

            let mut root_store = rustls::RootCertStore::empty();
            for cert in ca_certs {
                root_store
                    .add(cert)
                    .map_err(|e| format!("Failed to add CA cert: {}", e))?;
            }

            let client_verifier =
                rustls::server::WebPkiClientVerifier::builder(Arc::new(root_store))
                    .build()
                    .map_err(|e| format!("Failed to build client verifier: {}", e))?;

            rustls::ServerConfig::builder()
                .with_client_cert_verifier(client_verifier)
                .with_single_cert(certs, rustls::pki_types::PrivateKeyDer::from(key))
                .map_err(|e| format!("Failed to build TLS config: {}", e))?
        } else {
            // TLS only (no client cert required)
            rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(certs, rustls::pki_types::PrivateKeyDer::from(key))
                .map_err(|e| format!("Failed to build TLS config: {}", e))?
        };

        Ok(Some(tokio_rustls::TlsAcceptor::from(Arc::new(config))))
    }

    pub async fn start(&self) -> Result<(), String> {
        let listener = tokio::net::TcpListener::bind(&self.address)
            .await
            .map_err(|e| format!("Failed to bind to {}: {}", self.address, e))?;

        let tls_acceptor = self.build_tls_acceptor()?;
        if tls_acceptor.is_some() {
            info!(
                "TcpDiameterServer listening on {} with TLS{}",
                self.address,
                if !self.ca_cert_file.is_empty() && !is_empty_file(&self.ca_cert_file) {
                    " (mTLS enabled)"
                } else {
                    ""
                }
            );
        } else {
            info!("TcpDiameterServer listening on {}", self.address);
        }

        loop {
            match listener.accept().await {
                Ok((stream, addr)) => {
                    info!("Accepted connection from {}", addr);
                    let peer_addr = addr.to_string();

                    let command_map = self.command_map.clone();
                    let avp_map = self.avp_map.clone();
                    let capability = self.capability.clone();
                    let hop_by_hop_id_mapper = self.hop_by_hop_id_mapper.clone();
                    let command_handler = self.command_handler.clone();
                    let alarm_sender = self.alarm_sender.clone();

                    if let Some(ref acceptor) = tls_acceptor {
                        let acceptor = acceptor.clone();
                        let manager = self.manager.clone();
                        let host = self.host.clone();
                        let realm = self.realm.clone();

                        tokio::spawn(async move {
                            match acceptor.accept(stream).await {
                                Ok(tls_stream) => {
                                    let (reader, writer) = tokio::io::split(tls_stream);

                                    let mut reader: BoxedReader = Box::new(reader);
                                    let mut writer: BoxedWriter = Box::new(writer);

                                    if let Ok(cer) = Self::handle_connection(
                                        host.clone(),
                                        realm.clone(),
                                        peer_addr.clone(),
                                        &mut reader,
                                        &mut writer,
                                        &avp_map,
                                        &command_map,
                                        &capability,
                                    )
                                    .await
                                    {
                                        _ = Self::create_connection_from_cer(
                                            host.clone(),
                                            realm.clone(),
                                            &cer,
                                            peer_addr.clone(),
                                            reader,
                                            writer,
                                            &command_map,
                                            &avp_map,
                                            manager.clone(),
                                            hop_by_hop_id_mapper.clone(),
                                            command_handler.clone(),
                                            alarm_sender.clone(),
                                        );
                                    } else {
                                        error!(
                                            "Failed to complete CER exchange with {}",
                                            peer_addr
                                        );
                                        _ = writer.shutdown().await;
                                    }
                                }
                                Err(e) => {
                                    error!("TLS handshake failed for {}: {}", peer_addr, e);
                                }
                            }
                        });
                    } else {
                        let (reader, writer) = stream.into_split();
                        let mut reader: BoxedReader = Box::new(reader);
                        let mut writer: BoxedWriter = Box::new(writer);
                        let host = self.host.clone();
                        let realm = self.realm.clone();

                        if let Ok(cer_command) = Self::handle_connection(
                            host.clone(),
                            realm.clone(),
                            peer_addr.clone(),
                            &mut reader,
                            &mut writer,
                            &avp_map,
                            &command_map,
                            &capability,
                        )
                        .await
                        {
                            _ = Self::create_connection_from_cer(
                                host.clone(),
                                realm.clone(),
                                &cer_command,
                                peer_addr.clone(),
                                reader,
                                writer,
                                &self.command_map,
                                &self.avp_map,
                                self.manager.clone(),
                                hop_by_hop_id_mapper.clone(),
                                self.command_handler.clone(),
                                alarm_sender.clone(),
                            );
                        } else {
                            error!("Failed to complete CER exchange with {}", peer_addr);
                            _ = writer.shutdown().await;
                            continue;
                        }
                    }
                }
                Err(e) => {
                    error!("Failed to accept connection: {}", e);
                }
            }
        }
    }

    fn create_connection_from_cer(
        my_host: String,
        my_realm: String,
        cer_command: &Command,
        peer_address: String,
        reader: BoxedReader,
        writer: BoxedWriter,
        command_map: &CommandMap,
        avp_map: &AvpMap,
        manager: Arc<Mutex<ConnectionManager>>,
        hop_by_hop_id_mapper: Arc<HopByHopIdMapper>,
        command_handler: Arc<dyn crate::transport::CommandHandler + Send + Sync>,
        alarm_sender: Option<AlarmSender>,
    ) -> TcpServerConnection {
        // Implement creating a TcpServerConnection from the accepted stream

        TcpServerConnection::new(
            peer_address,
            reader,
            writer,
            my_host,
            my_realm,
            cer_command.get_origin_host().unwrap_or_default(),
            cer_command.get_origin_realm().unwrap_or_default(),
            command_map.clone(),
            avp_map.clone(),
            manager.clone(),
            hop_by_hop_id_mapper.clone(),
            command_handler.clone(),
            alarm_sender,
        )
    }

    async fn handle_connection(
        host: String,
        realm: String,
        peer_address: String,
        reader: &mut BoxedReader,
        writer: &mut BoxedWriter,
        avp_map: &AvpMap,
        command_map: &CommandMap,
        capability: &StackCapability,
    ) -> Result<Command, String> {
        let cer = match read_command(reader).await {
            Ok(cmd) => cmd,
            Err(e) => {
                error!("Failed to read CER from connection {}: {}", peer_address, e);
                return Err(format!(
                    "Failed to read CER from connection {}: {}",
                    peer_address, e
                ));
            }
        };
        info!(
            "Received {} command: {} from tcp client: {}",
            if cer.is_request() {
                "request"
            } else {
                "answer"
            },
            create_json_from_command_pretty(&cer, command_map, avp_map),
            peer_address
        );
        if cer.code != CommandCode::CapabilitiesExchange as u32 || !cer.is_request() {
            error!(
                "Expected CER with command code {}, got {} from connection {}",
                CommandCode::CapabilitiesExchange as u32,
                cer.code,
                peer_address
            );
            return Err(format!(
                "Expected CER with command code {}, got {} from connection {}",
                CommandCode::CapabilitiesExchange as u32,
                cer.code,
                peer_address
            ));
        }

        if cer.get_origin_host().is_none() || cer.get_origin_realm().is_none() {
            error!(
                "CER missing Origin-Host or Origin-Realm AVP from connection {}",
                peer_address
            );
            return Err(format!(
                "CER missing Origin-Host or Origin-Realm AVP from connection {}",
                peer_address
            ));
        }

        let cea = Self::create_cea(host.clone(), realm.clone(), &cer, avp_map, capability);
        writer
            .write_all(&cea.encode())
            .await
            .map_err(|e| format!("Failed to write CEA to connection {}: {}", peer_address, e))?;

        return Ok(cer);
    }

    fn create_cea(
        host: String,
        realm: String,
        cer_command: &Command,
        avp_map: &AvpMap,
        capability: &StackCapability,
    ) -> Command {
        let mut cea = Command::new(
            CommandCode::CapabilitiesExchange as u32,
            CommandFlags::Proxiable as u8,
            0,
            cer_command.hop_by_hop_id,
            cer_command.end_to_end_id,
            vec![
                name_value_to_avp("Origin-Host", &Value::String(host), avp_map).unwrap(),
                name_value_to_avp("Origin-Realm", &Value::String(realm), avp_map).unwrap(),
                name_value_to_avp("Vendor-Id", &Value::Number(0.into()), avp_map).unwrap(),
            ],
        );
        cea.add_avps(creat_capability_avps(capability, avp_map));
        cea.set_result_code(2001); // Success
        cea
    }
}
