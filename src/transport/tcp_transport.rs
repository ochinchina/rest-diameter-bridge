use crate::alarm::AlarmSender;
use crate::avp::{Avp, AvpCode, AvpFlags, AvpMap, ResultCode, name_value_to_avp};
use crate::command::{Command, CommandCode, CommandFlags, CommandMap};
use crate::config::StackCapability;
use crate::transport::{
    AnswerManager, CommandHandler, CommandProcessorContext, Connection, ConnectionManager,
    HopByHopIdMapper, IdGenerator, RedirectHostManager, read_command,
};
use crate::utils::{create_capability_avps, is_empty_file};
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
    cer_timeout: Duration,
    hop_by_hop_id_generator: Arc<Box<IdGenerator>>,
    end_to_end_id_generator: Arc<Box<IdGenerator>>,
    command_map: CommandMap,
    avp_map: AvpMap,
    writer: Arc<Mutex<Option<BoxedWriter>>>,
    connection_manager: Arc<Box<ConnectionManager>>,
    connected: Arc<std::sync::atomic::AtomicBool>,
    hop_by_hop_id_mapper: Arc<Box<HopByHopIdMapper>>,
    answer_manager: Arc<Box<crate::transport::AnswerManager>>,
    command_handler: Arc<dyn crate::transport::CommandHandler + Send + Sync>,
    alarm_sender: Option<AlarmSender>,
    redirect_host_manager: Arc<Box<RedirectHostManager>>,
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
        hop_by_hop_id_generator: Arc<Box<IdGenerator>>,
        end_to_end_id_generator: Arc<Box<IdGenerator>>,
        command_map: CommandMap,
        avp_map: AvpMap,
        cer_timeout: Duration,
        connection_manager: Arc<Box<ConnectionManager>>,
        hop_by_hop_id_mapper: Arc<Box<HopByHopIdMapper>>,
        answer_manager: Arc<Box<AnswerManager>>,
        command_handler: Arc<dyn CommandHandler + Send + Sync>,
        alarm_sender: Option<AlarmSender>,
        redirect_host_manager: Arc<Box<RedirectHostManager>>,
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
            command_map: command_map,
            avp_map: avp_map,
            writer: Arc::new(Mutex::new(None)),
            connection_manager,
            connected: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            hop_by_hop_id_mapper,
            answer_manager,
            command_handler,
            alarm_sender,
            redirect_host_manager,
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
                        _ = tokio::time::sleep(self.cer_timeout) => {
                            error!("CER timeout after {:?}", self.cer_timeout);
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
                    tokio::time::sleep(Duration::from_secs(5)).await;
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

        avps.extend(create_capability_avps(&self.capability, &self.avp_map));

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
            cer_command.to_pretty_json_str(&self.command_map, &self.avp_map),
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
            dwr_command.to_pretty_json_str(&self.command_map, &self.avp_map),
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
            dwa_command.to_pretty_json_str(&self.command_map, &self.avp_map),
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
            dpr_command.to_pretty_json_str(&self.command_map, &self.avp_map),
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
                                    command.to_pretty_json_str(&self.command_map, &self.avp_map),
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
            return Ok(());
        }

        if command.code == CommandCode::DisconnectPeer as u32 && command.is_request() {
            self.process_dpr(command).await?;
            return Ok(());
        }

        let context = CommandProcessorContext {
            connection_id: &self.address,
            my_host: &self.my_host,
            my_realm: &self.my_realm,
            peer_host: &self.peer_host,
            peer_realm: &self.peer_realm,
            command_map: &self.command_map,
            avp_map: &self.avp_map,
            connection_manager: &self.connection_manager,
            hop_by_hop_id_generator: &self.hop_by_hop_id_generator,
            hop_by_hop_id_mapper: &self.hop_by_hop_id_mapper,
            answer_manager: &self.answer_manager,
            command_handler: self.command_handler.as_ref(),
            redirect_host_manager: &self.redirect_host_manager,
        };

        context.process_command(command).await
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

    async fn get_connections(
        &self,
        _connections: &mut Vec<Arc<Box<dyn Connection + Send + Sync>>>,
    ) {
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
    hop_by_hop_id_generator: Arc<Box<IdGenerator>>,
    hop_by_hop_id_mapper: Arc<Box<HopByHopIdMapper>>,
    answer_manager: Arc<Box<AnswerManager>>,
    command_handler: Arc<dyn CommandHandler + Send + Sync>,
    alarm_sender: Option<AlarmSender>,
    redirect_host_manager: Arc<Box<RedirectHostManager>>,
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
        connection_manager: Arc<Box<ConnectionManager>>,
        hop_by_hop_id_generator: Arc<Box<IdGenerator>>,
        hop_by_hop_id_mapper: Arc<Box<HopByHopIdMapper>>,
        answer_manager: Arc<Box<AnswerManager>>,
        command_handler: Arc<dyn CommandHandler + Send + Sync>,
        alarm_sender: Option<AlarmSender>,
        redirect_host_manager: Arc<Box<RedirectHostManager>>,
    ) -> Self {
        let closed = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let conn = TcpServerConnection {
            id: peer_addr,
            my_host: my_host,
            my_realm: my_realm,
            peer_host: peer_host,
            peer_realm: peer_realm,
            avp_map: avp_map,
            command_map: command_map,
            writer: Arc::new(Mutex::new(Some(writer))),
            closed: closed,
            hop_by_hop_id_generator: hop_by_hop_id_generator,
            hop_by_hop_id_mapper: hop_by_hop_id_mapper,
            answer_manager: answer_manager,
            command_handler: command_handler,
            alarm_sender: alarm_sender,
            redirect_host_manager: redirect_host_manager,
        };

        let mut conn_clone = conn.clone();

        tokio::spawn(async move {
            connection_manager
                .add_connection(Arc::new(Box::new(conn_clone.clone())))
                .await;
            conn_clone.clear_alarm().await;

            conn_clone
                .handle_connection(reader, connection_manager.clone())
                .await
                .ok();

            let alarm_raise_message = format!(
                "Lost connection from diameter peer {}@{} at {}",
                conn_clone.peer_host, conn_clone.peer_realm, conn_clone.id
            );
            conn_clone.raise_alarm(&alarm_raise_message).await;

            connection_manager
                .remove_connection_by_id(&conn_clone.get_id())
                .await;
        });

        conn
    }

    async fn raise_alarm(&self, message: &str) {
        if let Some(alarm_sender) = &self.alarm_sender {
            alarm_sender
                .raise_alarm(&self.id, &self.peer_host, &self.peer_realm, message)
                .await;
        }
    }

    async fn clear_alarm(&self) {
        if let Some(alarm_sender) = &self.alarm_sender {
            alarm_sender
                .clear_alarm(&self.id, &self.peer_host, &self.peer_realm)
                .await;
        }
    }
    async fn handle_connection(
        &mut self,
        mut reader: BoxedReader,
        connection_manager: Arc<Box<ConnectionManager>>,
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
        connection_manager: &Arc<Box<ConnectionManager>>,
    ) -> Result<(), String> {
        // Implement command processing logic here
        info!(
            "Received {} command: {} from tcp client: {}",
            if command.is_request() {
                "request"
            } else {
                "answer"
            },
            command.to_pretty_json_str(&self.command_map, &self.avp_map),
            self.id
        );
        if command.code == CommandCode::DeviceWatchdog as u32 && command.is_request() {
            self.process_dwa(command).await?;
            return Ok(());
        }

        if command.code == CommandCode::DisconnectPeer as u32 && command.is_request() {
            self.process_dpr(command).await?;
            return Ok(());
        }

        let context = CommandProcessorContext {
            connection_id: &self.id,
            my_host: &self.my_host,
            my_realm: &self.my_realm,
            peer_host: &self.peer_host,
            peer_realm: &self.peer_realm,
            command_map: &self.command_map,
            avp_map: &self.avp_map,
            connection_manager,
            hop_by_hop_id_generator: &self.hop_by_hop_id_generator,
            hop_by_hop_id_mapper: &self.hop_by_hop_id_mapper,
            answer_manager: &self.answer_manager,
            command_handler: self.command_handler.as_ref(),
            redirect_host_manager: &self.redirect_host_manager,
        };

        context.process_command(command).await
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
            dwa.to_pretty_json_str(&self.command_map, &self.avp_map),
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
            dpr.to_pretty_json_str(&self.command_map, &self.avp_map),
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
            command.to_pretty_json_str(&self.command_map, &self.avp_map),
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

    async fn get_connections(
        &self,
        _connections: &mut Vec<Arc<Box<dyn Connection + Send + Sync>>>,
    ) {
    }

    fn get_peer_host(&self) -> Result<String, String> {
        Ok(self.peer_host.clone())
    }

    fn get_peer_realm(&self) -> Result<String, String> {
        Ok(self.peer_realm.clone())
    }
}

#[derive(Clone)]
pub struct TcpDiameterServer {
    host: String,
    realm: String,
    capability: StackCapability,
    key_file: String,
    cert_file: String,
    ca_cert_file: String,
    address: String,
    manager: Arc<Box<ConnectionManager>>,
    command_map: CommandMap,
    avp_map: AvpMap,
    hop_by_hop_id_generator: Arc<Box<IdGenerator>>,
    hop_by_hop_id_mapper: Arc<Box<HopByHopIdMapper>>,
    answer_manager: Arc<Box<AnswerManager>>,
    command_handler: Arc<dyn CommandHandler + Send + Sync>,
    alarm_sender: Option<AlarmSender>,
    redirect_host_manager: Arc<Box<RedirectHostManager>>,
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
        manager: Arc<Box<ConnectionManager>>,
        command_map: CommandMap,
        avp_map: AvpMap,
        hop_by_hop_id_generator: Arc<Box<IdGenerator>>,
        hop_by_hop_id_mapper: Arc<Box<HopByHopIdMapper>>,
        answer_manager: Arc<Box<AnswerManager>>,
        command_handler: Arc<dyn crate::transport::CommandHandler + Send + Sync>,
        alarm_sender: Option<AlarmSender>,
        redirect_host_manager: Arc<Box<RedirectHostManager>>,
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
            hop_by_hop_id_generator,
            hop_by_hop_id_mapper,
            answer_manager,
            command_handler,
            alarm_sender,
            redirect_host_manager,
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

                    if let Some(ref acceptor) = tls_acceptor {
                        let acceptor = acceptor.clone();
                        let self_clone = self.clone();

                        tokio::spawn(async move {
                            match acceptor.accept(stream).await {
                                Ok(tls_stream) => {
                                    let (reader, writer) = tokio::io::split(tls_stream);

                                    let mut reader: BoxedReader = Box::new(reader);
                                    let mut writer: BoxedWriter = Box::new(writer);

                                    if let Ok(cer) = self_clone
                                        .handle_connection(
                                            peer_addr.clone(),
                                            &mut reader,
                                            &mut writer,
                                        )
                                        .await
                                    {
                                        _ = self_clone.create_connection_from_cer(
                                            &cer,
                                            peer_addr.clone(),
                                            reader,
                                            writer,
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

                        if let Ok(cer_command) = self
                            .handle_connection(peer_addr.clone(), &mut reader, &mut writer)
                            .await
                        {
                            _ = self.create_connection_from_cer(
                                &cer_command,
                                peer_addr.clone(),
                                reader,
                                writer,
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
        &self,
        cer_command: &Command,
        peer_address: String,
        reader: BoxedReader,
        writer: BoxedWriter,
    ) -> TcpServerConnection {
        // Implement creating a TcpServerConnection from the accepted stream

        TcpServerConnection::new(
            peer_address,
            reader,
            writer,
            self.host.clone(),
            self.realm.clone(),
            cer_command.get_origin_host().unwrap_or_default(),
            cer_command.get_origin_realm().unwrap_or_default(),
            self.command_map.clone(),
            self.avp_map.clone(),
            self.manager.clone(),
            self.hop_by_hop_id_generator.clone(),
            self.hop_by_hop_id_mapper.clone(),
            self.answer_manager.clone(),
            self.command_handler.clone(),
            self.alarm_sender.clone(),
            self.redirect_host_manager.clone(),
        )
    }

    async fn handle_connection(
        &self,
        peer_address: String,
        reader: &mut BoxedReader,
        writer: &mut BoxedWriter,
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
            cer.to_pretty_json_str(&self.command_map, &self.avp_map),
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

        let cea = self.create_cea(&cer);
        writer
            .write_all(&cea.encode())
            .await
            .map_err(|e| format!("Failed to write CEA to connection {}: {}", peer_address, e))?;

        return Ok(cer);
    }

    fn create_cea(&self, cer_command: &Command) -> Command {
        let mut cea = Command::new(
            CommandCode::CapabilitiesExchange as u32,
            CommandFlags::Proxiable as u8,
            0,
            cer_command.hop_by_hop_id,
            cer_command.end_to_end_id,
            vec![
                name_value_to_avp(
                    "Origin-Host",
                    &Value::String(self.host.clone()),
                    &self.avp_map,
                )
                .unwrap(),
                name_value_to_avp(
                    "Origin-Realm",
                    &Value::String(self.realm.clone()),
                    &self.avp_map,
                )
                .unwrap(),
                name_value_to_avp("Vendor-Id", &Value::Number(0.into()), &self.avp_map).unwrap(),
            ],
        );
        cea.add_avps(create_capability_avps(&self.capability, &self.avp_map));
        cea.set_result_code(ResultCode::DiameterSuccess.as_u32()); // Success
        cea
    }
}
