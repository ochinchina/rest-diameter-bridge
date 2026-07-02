use axum::Router;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use log::{error, info};
use std::{sync::Arc, time::Duration};
use tokio::sync::Mutex;
use tokio::sync::mpsc::Receiver;

use crate::{
    alarm::AlarmStore,
    avp::AvpMap,
    command::{
        Command, CommandMap, create_command_from_json_value, create_json_from_command,
        create_json_from_command_pretty,
    },
    metrics::{RESTFUL_REQUESTS, gather_metrics},
    transport::{ConnectionManager, DefaultCommandHandler, IdGenerator},
    utils::load_rustls_config,
};

#[derive(Clone)]
pub struct HttpRestListener {
    address: String,
    host: String,
    realm: String,
    path: String,
    command_handler: Arc<DefaultCommandHandler>,
    cert_file: String,
    key_file: String,
    ca_cert_file: String,
    connection_manager: Arc<Mutex<ConnectionManager>>,
    avp_map: AvpMap,
    command_map: CommandMap,
    hop_by_hop_id_generator: Arc<IdGenerator>,
    end_to_end_id_generator: Arc<IdGenerator>,
    alarm_store: Option<AlarmStore>,
    alarm_rest_path: Option<String>,
}

#[derive(Clone)]
struct HttpRestListenerState {
    host: String,
    realm: String,
    command_handler: Arc<DefaultCommandHandler>,
    connection_manager: Arc<Mutex<ConnectionManager>>,
    avp_map: AvpMap,
    command_map: CommandMap,
    hop_by_hop_id_generator: Arc<IdGenerator>,
    end_to_end_id_generator: Arc<IdGenerator>,
    alarm_store: Option<AlarmStore>,
}

impl HttpRestListener {
    // Methods for managing an HTTP server connection
    pub fn new(
        address: String,
        host: String,
        realm: String,
        path: String,
        command_handler: Arc<DefaultCommandHandler>,
        cert_file: String,
        key_file: String,
        ca_cert_file: String,
        connection_manager: Arc<Mutex<ConnectionManager>>,
        avp_map: AvpMap,
        command_map: CommandMap,
        hop_by_hop_id_generator: Arc<IdGenerator>,
        end_to_end_id_generator: Arc<IdGenerator>,
        alarm_store: Option<AlarmStore>,
        alarm_rest_path: Option<String>,
    ) -> Self {
        info!(
            "Creating HttpRestListener with address: {}, host: {}, realm: {}, path: {}, cert_file: {}, key_file: {}, ca_cert_file: {}",
            address, host, realm, path, cert_file, key_file, ca_cert_file
        );
        HttpRestListener {
            address,
            host,
            realm,
            path,
            command_handler,
            cert_file,
            key_file,
            ca_cert_file,
            connection_manager: connection_manager.clone(),
            avp_map,
            command_map,
            hop_by_hop_id_generator,
            end_to_end_id_generator,
            alarm_store,
            alarm_rest_path,
        }
    }

    async fn handle_diameter_request(
        State(state): State<Arc<HttpRestListenerState>>,
        body: String,
    ) -> Result<(StatusCode, String), (StatusCode, String)> {
        let v = serde_json::from_str::<serde_json::Value>(&body).map_err(|e| {
            error!("Failed to parse incoming JSON: {}", e);
            (StatusCode::BAD_REQUEST, "Invalid JSON body".to_string())
        })?;

        info!("Received HTTP request with body: {}", body);
        RESTFUL_REQUESTS.inc();

        let mut command = create_command_from_json_value(&v, &state.command_map, &state.avp_map)
            .map_err(|e| {
                error!("Failed to parse incoming JSON command: {}", e);
                (
                    StatusCode::BAD_REQUEST,
                    format!("Invalid diameter message: {}", e),
                )
            })?;

        // Validate that the command has the required Destination-Host and Destination-Realm AVPs for routing

        if command.get_destination_host().is_none() || command.get_destination_realm().is_none() {
            error!("Diameter message missing Destination-Host or Destination-Realm");
            return Err((
                StatusCode::BAD_REQUEST,
                "Diameter message must include Destination-Host and Destination-Realm".to_string(),
            ));
        }

        info!(
            "set origin host and realm to {}, {} for the command",
            state.host, state.realm,
        );
        command.set_origin_host(&state.host);
        command.set_origin_realm(&state.realm);
        command.hop_by_hop_id = state.hop_by_hop_id_generator.next_id();
        command.end_to_end_id = state.end_to_end_id_generator.next_id();

        if !command.is_request() {
            error!("Received Diameter message is not a request");
            return Err((
                StatusCode::BAD_REQUEST,
                "Received Diameter message is not a request".to_string(),
            ));
        }

        info!(
            "Received HTTP request to send Diameter command with code: {}, app_id: {}, destination host: {}, destination realm: {}",
            command.code,
            command.application_id,
            command.get_destination_host().unwrap_or_default(),
            command.get_destination_realm().unwrap_or_default()
        );

        let callback_url = v
            .as_object()
            .ok_or_else(|| {
                error!("Incoming JSON is not an object");
                (
                    StatusCode::BAD_REQUEST,
                    "JSON body must be an object".to_string(),
                )
            })?
            .get("callback-url")
            .and_then(|v| v.as_str())
            .unwrap_or_default();

        if callback_url == "" {
            info!("No callback URL provided, using channel callback for response");
            let (sender, mut receiver) = tokio::sync::mpsc::channel::<Command>(1);

            state.command_handler.add_answer_sender_with_request(
                command.hop_by_hop_id,
                sender,
                &command,
            );

            match Self::send_command(
                &state.connection_manager,
                &command,
                &state.command_map,
                &state.avp_map,
            )
            .await
            {
                Ok(_) => {
                    info!(
                        "Diameter {} with code {}: {} is sent successfully, waiting for response through channel callback",
                        if command.is_request() {
                            "request"
                        } else {
                            "answer"
                        },
                        command.code,
                        create_json_from_command_pretty(
                            &command,
                            &state.command_map,
                            &state.avp_map
                        )
                    );
                    Self::receive_response(
                        &mut receiver,
                        Duration::from_secs(30),
                        &state.command_map,
                        &state.avp_map,
                    )
                    .await
                }
                Err(e) => {
                    error!("Failed to route diameter message: {}", e);
                    return Err((
                        StatusCode::SERVICE_UNAVAILABLE,
                        format!("Failed to route diameter message: {}", e),
                    ));
                }
            }
        } else {
            info!("Callback URL provided: {}", callback_url);
            state.command_handler.add_answer_url_with_request(
                command.hop_by_hop_id,
                callback_url,
                &command,
            );

            match Self::send_command(
                &state.connection_manager,
                &command,
                &state.command_map,
                &state.avp_map,
            )
            .await
            {
                Ok(_) => {
                    info!(
                        "Diameter {} with code {}: {} is sent successfully, response will be sent to callback URL: {}",
                        if command.is_request() {
                            "request"
                        } else {
                            "answer"
                        },
                        command.code,
                        create_json_from_command_pretty(
                            &command,
                            &state.command_map,
                            &state.avp_map
                        ),
                        callback_url
                    );
                    Ok((StatusCode::OK, "Message sent".to_string()))
                }
                Err(e) => {
                    error!("Failed to route diameter message: {}", e);
                    Err((
                        StatusCode::SERVICE_UNAVAILABLE,
                        format!("Failed to route diameter message: {}", e),
                    ))
                }
            }
        }
    }

    async fn send_command(
        connection_manager: &Arc<Mutex<ConnectionManager>>,
        command: &Command,
        command_map: &CommandMap,
        avp_map: &AvpMap,
    ) -> Result<(), String> {
        info!(
            "Try to send command: {} through connection manager",
            create_json_from_command_pretty(command, command_map, avp_map)
        );
        connection_manager
            .lock()
            .await
            .find_send_command(command)
            .await
    }

    async fn receive_response(
        rx: &mut Receiver<Command>,
        timeout: Duration,
        command_map: &CommandMap,
        avp_map: &AvpMap,
    ) -> Result<(StatusCode, String), (StatusCode, String)> {
        match tokio::time::timeout(timeout, rx.recv()).await {
            Ok(result) => match result {
                Some(response_command) => {
                    let json_response = serde_json::to_string(&create_json_from_command(
                        &response_command,
                        command_map,
                        avp_map,
                    ))
                    .map_err(|e| {
                        error!("Failed to serialize response command to JSON: {}", e);
                        (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            format!("Failed to serialize response command to JSON: {}", e),
                        )
                    })?;
                    Ok((StatusCode::OK, json_response))
                }
                None => Err((
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Failed to receive response command through channel callback".to_string(),
                )),
            },
            Err(_) => Err((
                StatusCode::SERVICE_UNAVAILABLE,
                "Timeout waiting for response command".to_string(),
            )),
        }
    }

    pub async fn start(&self) -> Result<(), String> {
        let address = self.address.clone();
        let cert_file = self.cert_file.clone();
        let key_file = self.key_file.clone();
        let ca_cert_file = self.ca_cert_file.clone();
        let cm = self.connection_manager.clone();
        let cmd_map = self.command_map.clone();
        let avp_map_clone = self.avp_map.clone();
        let hop_by_hop_id_generator = self.hop_by_hop_id_generator.clone();
        let end_to_end_id_generator = self.end_to_end_id_generator.clone();
        let host = self.host.clone();
        let realm = self.realm.clone();

        info!(
            "Starting HTTP server on {} with host: {}, realm: {}, cert_file: {}, key_file: {}, ca_cert_file: {}",
            address, host, realm, cert_file, key_file, ca_cert_file
        );
        let app_state = HttpRestListenerState {
            host,
            realm,
            command_handler: self.command_handler.clone(),
            connection_manager: cm,
            command_map: cmd_map,
            avp_map: avp_map_clone,
            hop_by_hop_id_generator,
            end_to_end_id_generator,
            alarm_store: self.alarm_store.clone(),
        };

        let shared_state = Arc::new(app_state);
        let mut app = Router::new().route(&self.path, post(Self::handle_diameter_request));

        if let Some(alarm_path) = &self.alarm_rest_path {
            info!("Registering alarm REST API at {}", alarm_path);
            app = app.route(alarm_path, get(Self::handle_get_alarms)).route(
                &format!("{}/{{alarm_id}}", alarm_path),
                get(Self::handle_get_alarm_by_id),
            );
        }

        let app = app.route("/metrics", get(Self::handle_metrics));

        let app = app.with_state(shared_state);

        let addr: std::net::SocketAddr = match address.parse() {
            Ok(a) => a,
            Err(e) => {
                error!("Invalid REST listen address '{}': {}", address, e);
                return Err(format!("Invalid REST listen address '{}': {}", address, e));
            }
        };

        if let Ok(config) = load_rustls_config(&cert_file, &key_file, &ca_cert_file) {
            info!("Starting HTTPS REST server on {}", address);
            let handle = axum_server::tls_rustls::RustlsConfig::from_config(config);
            if let Err(e) = axum_server::bind_rustls(addr, handle)
                .serve(app.into_make_service())
                .await
            {
                error!("HTTPS REST server error on {}: {}", address, e);
                return Err(format!("HTTPS REST server error on {}: {}", address, e));
            }
        } else {
            info!("Starting HTTP REST server on {}", address);
            let listener = match tokio::net::TcpListener::bind(addr).await {
                Ok(l) => l,
                Err(e) => {
                    error!("Failed to bind REST listener on {}: {}", address, e);
                    return Err(format!(
                        "Failed to bind REST listener on {}: {}",
                        address, e
                    ));
                }
            };
            if let Err(e) = axum::serve(listener, app).await {
                error!("HTTP REST server error on {}: {}", address, e);
                return Err(format!("HTTP REST server error on {}: {}", address, e));
            }
        }
        Ok(())
    }

    async fn handle_get_alarms(
        State(state): State<Arc<HttpRestListenerState>>,
    ) -> Result<(StatusCode, String), (StatusCode, String)> {
        let store = state.alarm_store.as_ref().ok_or_else(|| {
            (
                StatusCode::SERVICE_UNAVAILABLE,
                "Alarm store not configured".to_string(),
            )
        })?;

        let alarms = store.get_active_alarms();
        let json = serde_json::to_string(&alarms).map_err(|e| {
            error!("Failed to serialize alarms: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to serialize alarms: {}", e),
            )
        })?;
        Ok((StatusCode::OK, json))
    }

    async fn handle_get_alarm_by_id(
        State(state): State<Arc<HttpRestListenerState>>,
        Path(alarm_id): Path<String>,
    ) -> Result<(StatusCode, String), (StatusCode, String)> {
        let store = state.alarm_store.as_ref().ok_or_else(|| {
            (
                StatusCode::SERVICE_UNAVAILABLE,
                "Alarm store not configured".to_string(),
            )
        })?;

        match store.get_alarm(&alarm_id) {
            Some(alarm) => {
                let json = serde_json::to_string(&alarm).map_err(|e| {
                    error!("Failed to serialize alarm: {}", e);
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        format!("Failed to serialize alarm: {}", e),
                    )
                })?;
                Ok((StatusCode::OK, json))
            }
            None => Err((
                StatusCode::NOT_FOUND,
                format!("Alarm '{}' not found", alarm_id),
            )),
        }
    }

    async fn handle_metrics(
        State(_state): State<Arc<HttpRestListenerState>>,
    ) -> (StatusCode, String) {
        (StatusCode::OK, gather_metrics())
    }
}
