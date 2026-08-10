use crate::transport::AnswerManager;
use axum::Router;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use log::{error, info};
use std::sync::Arc;

use crate::avp::ResultCode;
use crate::{
    alarm::AlarmStore,
    avp::AvpMap,
    command::{Command, CommandMap},
    metrics::{RESTFUL_REQUESTS, gather_metrics},
    transport::{ConnectionManager, IdGenerator},
    utils::load_rustls_config,
};

#[derive(Clone)]
pub struct HttpRestListener {
    address: String,
    host: String,
    realm: String,
    path: String,
    cert_file: String,
    key_file: String,
    ca_cert_file: String,
    connection_manager: Arc<Box<ConnectionManager>>,
    avp_map: AvpMap,
    command_map: CommandMap,
    hop_by_hop_id_generator: Arc<Box<IdGenerator>>,
    end_to_end_id_generator: Arc<Box<IdGenerator>>,
    alarm_store: Option<AlarmStore>,
    alarm_rest_path: Option<String>,
    answer_manager: Arc<Box<AnswerManager>>,
}

#[derive(Clone)]
struct HttpRestListenerState {
    host: String,
    realm: String,
    connection_manager: Arc<Box<ConnectionManager>>,
    avp_map: AvpMap,
    command_map: CommandMap,
    hop_by_hop_id_generator: Arc<Box<IdGenerator>>,
    end_to_end_id_generator: Arc<Box<IdGenerator>>,
    alarm_store: Option<AlarmStore>,
    answer_manager: Arc<Box<AnswerManager>>,
}

impl HttpRestListener {
    // Methods for managing an HTTP server connection
    pub fn new(
        address: String,
        host: String,
        realm: String,
        path: String,
        cert_file: String,
        key_file: String,
        ca_cert_file: String,
        connection_manager: Arc<Box<ConnectionManager>>,
        avp_map: AvpMap,
        command_map: CommandMap,
        hop_by_hop_id_generator: Arc<Box<IdGenerator>>,
        end_to_end_id_generator: Arc<Box<IdGenerator>>,
        alarm_store: Option<AlarmStore>,
        alarm_rest_path: Option<String>,
        answer_manager: Arc<Box<AnswerManager>>,
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
            answer_manager,
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

        let mut command = Command::from_json_value(&v, &state.command_map, &state.avp_map)
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

        state
            .answer_manager
            .prepare_for_answer(
                command.hop_by_hop_id,
                "".to_string(),
                state.host.clone(),
                state.realm.clone(),
            )
            .await;
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
            .unwrap_or_default()
            .to_string();

        if callback_url != "" {
            tokio::spawn(async move {
                info!(
                    "Callback URL provided: {}, will send response to this URL",
                    callback_url
                );
                let (_status_code, content_type, message) = match Self::send_request(
                    &state.connection_manager,
                    &command,
                    &state.command_map,
                    &state.avp_map,
                )
                .await
                {
                    Ok((status_code, message)) => {
                        info!(
                            "Successfully routed diameter message: HTTP {}, Content-Type: {}",
                            status_code, "application/json"
                        );
                        (status_code, "application/json".to_string(), message)
                    }
                    Err((status_code, message)) => {
                        error!("Failed to route diameter message: {}", message);
                        (
                            status_code,
                            "text/plain".to_string(),
                            format!("Failed to route diameter message: {}", message),
                        )
                    }
                };
                if let Err(e) = send_message_to_url(&callback_url, &content_type, &message).await {
                    error!(
                        "Failed to send response to callback URL {}: {}",
                        callback_url, e
                    );
                } else {
                    info!(
                        "Successfully sent response to callback URL {}",
                        callback_url
                    );
                }
            });
            return Ok((
                StatusCode::OK,
                "Message sent, response will be sent to callback URL".to_string(),
            ));
        } else {
            Self::send_request(
                &state.connection_manager,
                &command,
                &state.command_map,
                &state.avp_map,
            )
            .await
        }
    }

    async fn send_request(
        connection_manager: &Arc<Box<ConnectionManager>>,
        command: &Command,
        command_map: &CommandMap,
        avp_map: &AvpMap,
    ) -> Result<(StatusCode, String), (StatusCode, String)> {
        info!(
            "Try to send command: {} through connection manager",
            command.to_pretty_json_str(command_map, avp_map)
        );
        match connection_manager.send_request(command).await {
            Ok(answer) => {
                let result_code = answer
                    .get_result_code()
                    .unwrap_or(ResultCode::DiameterSuccess as u32);
                info!(
                    "Diameter command sent successfully, received answer with result code: {}",
                    result_code
                );
                let json_response = answer.to_json(command_map, avp_map);
                let json_response = serde_json::to_string(&json_response).map_err(|e| {
                    error!("Failed to serialize response command to JSON: {}", e);
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        format!("Failed to serialize response command to JSON: {}", e),
                    )
                })?;
                return Ok((StatusCode::OK, json_response));
            }
            Err(e) => {
                error!("Failed to send Diameter command: {}", e);
                return Err((
                    StatusCode::SERVICE_UNAVAILABLE,
                    format!("Failed to send Diameter command: {}", e),
                ));
            }
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
            connection_manager: cm,
            command_map: cmd_map,
            avp_map: avp_map_clone,
            hop_by_hop_id_generator,
            end_to_end_id_generator,
            alarm_store: self.alarm_store.clone(),
            answer_manager: self.answer_manager.clone(),
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

        let alarms = store.get_active_alarms().await;
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

        match store.get_alarm(&alarm_id).await {
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

async fn send_message_to_url(url: &str, content_type: &str, message: &str) -> Result<(), String> {
    match reqwest::Client::new()
        .post(url)
        .header("Content-Type", content_type)
        .body(message.to_string())
        .send()
        .await
    {
        Ok(response) => {
            let status_code = response.status().as_u16();
            if status_code >= 200 && status_code < 400 {
                info!("Successfully sent message to {}: HTTP {}", url, status_code);
                Ok(())
            } else {
                Err(format!(
                    "Failed to send message to {}: HTTP {}",
                    url, status_code
                ))
            }
        }
        Err(e) => Err(format!("Failed to send message to {}: {}", url, e)),
    }
}
