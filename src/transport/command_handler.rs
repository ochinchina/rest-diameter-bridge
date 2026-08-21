use log::{error, info};

use tokio::io::{AsyncRead, AsyncReadExt};

use crate::avp::AvpMap;
use crate::command::{Command, CommandBuffer, CommandFlags, CommandMap};
use crate::metrics::{PROCESSED_REQUESTS, REQUESTS_RECEIVED, RESPONSES_RECEIVED};

#[async_trait::async_trait]
pub trait CommandHandler: Send + Sync {
    /// Handles an incoming Diameter command. If the command is a request, it processes it and returns an optional answer. If the command is a response, it handles it accordingly.
    /// Returns an error string if processing fails.
    /// # Arguments
    /// * `command` - A reference to the incoming Diameter command to be handled.
    /// # Returns
    /// * `Result<Option<Command>, String>` - Returns an optional answer command if the incoming command is a request, or None if it's a response. Returns an error string if processing fails.
    async fn handle_command(&self, command: &Command) -> Result<Option<Command>, String>;
}

pub struct RequestProcessor {
    command_codes: Vec<u32>,
    application_ids: Vec<u32>,
    urls: Vec<String>,
    timeout: std::time::Duration,
}

impl RequestProcessor {
    pub fn new(
        command_codes: Vec<u32>,
        application_ids: Vec<u32>,
        urls: Vec<String>,
        timeout: std::time::Duration,
    ) -> Self {
        RequestProcessor {
            command_codes,
            application_ids,
            urls,
            timeout,
        }
    }

    pub fn matches(&self, command: &Command) -> bool {
        if (self.command_codes.is_empty() || self.command_codes.contains(&command.code))
            && (self.application_ids.is_empty()
                || self.application_ids.contains(&command.get_application_id()))
        {
            true
        } else {
            false
        }
    }

    pub async fn send_request(
        &self,
        request: &Command,
        command_map: &CommandMap,
        avp_map: &AvpMap,
    ) -> Result<Command, String> {
        for url in &self.urls {
            info!(
                "Sending request with code {} and hop-by-hop ID {} to URL: {}",
                request.code, request.hop_by_hop_id, url
            );
            // Implement the logic to send the command to the specified URL
            // This is a placeholder implementation
            match reqwest::Client::new()
                .post(url)
                .timeout(self.timeout)
                .header("Content-Type", "application/json")
                .json(&request.to_json(command_map, avp_map))
                .send()
                .await
            {
                Ok(response) => {
                    let status_code = response.status().as_u16();
                    if status_code >= 200 && status_code < 400 {
                        info!(
                            "Successfully sent request with command code {} to {}: HTTP status code {}",
                            request.code, url, status_code
                        );
                        if let Ok(body) = response.text().await {
                            return self.create_answer(&body, request, command_map, avp_map);
                        } else {
                            error!(
                                "Failed to read response body for request with command code {} from {}",
                                request.code, url
                            );
                        }
                    } else {
                        error!(
                            "Failed to send request with command code {} to {}: HTTP status code {}",
                            request.code, url, status_code
                        );
                    }
                }
                Err(e) => {
                    error!(
                        "Failed to send request with command code {} to {}: {}",
                        request.code, url, e
                    );
                }
            }
        }
        let mut response = request.create_response();
        response.set_result_code(3002);
        Ok(response)
    }

    fn create_answer(
        &self,
        response: &String,
        request: &Command,
        command_map: &CommandMap,
        avp_map: &AvpMap,
    ) -> Result<Command, String> {
        let mut v = serde_json::from_str::<serde_json::Value>(response).map_err(|e| {
            format!(
                "Failed to parse response JSON for request with code {} and hop-by-hop ID {}: {}",
                request.code, request.hop_by_hop_id, e
            )
        })?;

        if !v.is_object() {
            return Err(format!(
                "Response is not a valid JSON object for request with code {} and hop-by-hop ID {}: {}",
                request.code, request.hop_by_hop_id, response
            ));
        }

        if v.get("code").is_none() && v.get("name").is_none() {
            v.as_object_mut()
                .unwrap()
                .insert("code".to_string(), serde_json::json!(request.code));
        }

        let flags = v
            .get("flags")
            .and_then(|f| f.as_str())
            .and_then(|s| CommandFlags::u8_from_str(s))
            .unwrap_or(request.flags);

        match Command::from_json_value(&v, command_map, avp_map) {
            Ok(mut answer) => {
                answer.hop_by_hop_id = request.hop_by_hop_id; // Ensure the hop-by-hop ID matches the request
                answer.end_to_end_id = request.end_to_end_id; // Ensure the end-to-end ID matches the request
                answer.flags = flags & !(CommandFlags::Request as u8); // Ensure the flags match the request
                if request.get_application_id() != 0 {
                    answer.application_id = request.get_application_id();
                }
                if request.get_destination_realm().is_some() {
                    answer.set_origin_realm(&request.get_destination_realm().unwrap_or_default());
                }
                if request.get_destination_host().is_some() {
                    answer.set_origin_host(&request.get_destination_host().unwrap_or_default());
                }
                
                info!(
                    "Received answer for request with code {} and hop-by-hop ID {}: {}",
                    answer.code,
                    answer.hop_by_hop_id,
                    answer.to_pretty_json_str(command_map, avp_map)
                );

                Ok(answer)
            }
            Err(e) => {
                error!(
                    "Failed to create answer for request with code {} and hop-by-hop ID {} from: {}. Error: {}",
                    request.code, request.hop_by_hop_id, response, e
                );
                Err("Failed to create answer from response".to_string())
            }
        }
    }
}
pub struct DefaultCommandHandler {
    request_processors: Vec<RequestProcessor>,
    command_map: CommandMap,
    avp_map: AvpMap,
}

impl DefaultCommandHandler {
    pub fn new(
        request_processors: Vec<RequestProcessor>,
        command_map: &CommandMap,
        avp_map: &AvpMap,
    ) -> Self {
        DefaultCommandHandler {
            request_processors,
            command_map: command_map.clone(),
            avp_map: avp_map.clone(),
        }
    }
}

#[async_trait::async_trait]
impl CommandHandler for DefaultCommandHandler {
    async fn handle_command(&self, command: &Command) -> Result<Option<Command>, String> {
        if command.is_request() {
            REQUESTS_RECEIVED.inc();
            for processor in &self.request_processors {
                if processor.matches(command) {
                    PROCESSED_REQUESTS.inc();
                    if let Ok(answer) = processor
                        .send_request(command, &self.command_map, &self.avp_map)
                        .await
                    {
                        return Ok(Some(answer));
                    }
                }
            }
            Err(format!(
                "No processor found for command with hop-by-hop ID: {}",
                command.hop_by_hop_id
            ))
        } else {
            RESPONSES_RECEIVED.inc();
            return Ok(None); // For responses, we don't return an answer, just handle it
        }
    }
}

/**
 * Helper function to read a Diameter command from a TCP stream. This function reads the Diameter message length first, then reads the full message, and finally parses it into a Command struct.
 * This is used in both the TcpClientConnection and TcpServerConnection to read incoming Diameter messages after the initial CER/CEA exchange.
 */
pub async fn read_command(reader: &mut (impl AsyncRead + Unpin)) -> Result<Command, String> {
    let mut length_buffer = [0; 4];

    reader
        .read_exact(&mut length_buffer)
        .await
        .map_err(|e| format!("Failed to read message length: {}", e))?;

    let message_length = u32::from_be_bytes(length_buffer) & 0x00FFFFFF; // Diameter message length is in the last 3 bytes
    let mut buffer = vec![0; message_length as usize - 4];

    reader
        .read_exact(&mut buffer)
        .await
        .map_err(|e| format!("Failed to read message body: {}", e))?;
    let mut command_buffer = CommandBuffer::from_bytes(&length_buffer);
    command_buffer.append(&buffer);
    let command = command_buffer
        .read_command()
        .ok_or_else(|| "Failed to parse CEA command".to_string())?;
    Ok(command)
}
