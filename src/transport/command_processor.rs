use std::sync::Arc;

use crate::avp::{AvpMap, ResultCode};
use crate::command::{Command, CommandMap};
use crate::transport::{
    AnswerManager, CommandHandler, ConnectionManager, HopByHopIdMapper, IdGenerator,
    RedirectHostManager,
};
use log::{error, info};

pub struct CommandProcessorContext<'a> {
    pub connection_id: &'a str,
    pub my_host: &'a String,
    pub my_realm: &'a String,
    pub peer_host: &'a String,
    pub peer_realm: &'a String,
    pub command_map: &'a CommandMap,
    pub avp_map: &'a AvpMap,
    pub connection_manager: &'a ConnectionManager,
    pub hop_by_hop_id_generator: &'a Arc<Box<IdGenerator>>,
    pub hop_by_hop_id_mapper: &'a Arc<Box<HopByHopIdMapper>>,
    pub answer_manager: &'a Arc<Box<AnswerManager>>,
    pub command_handler: &'a (dyn CommandHandler + Send + Sync),
    pub redirect_host_manager: &'a Arc<Box<RedirectHostManager>>,
}

impl CommandProcessorContext<'_> {
    pub fn new<'a>(
        connection_id: &'a str,
        my_host: &'a String,
        my_realm: &'a String,
        peer_host: &'a String,
        peer_realm: &'a String,
        command_map: &'a CommandMap,
        avp_map: &'a AvpMap,
        connection_manager: &'a ConnectionManager,
        hop_by_hop_id_generator: &'a Arc<Box<IdGenerator>>,
        hop_by_hop_id_mapper: &'a Arc<Box<HopByHopIdMapper>>,
        answer_manager: &'a Arc<Box<AnswerManager>>,
        command_handler: &'a (dyn CommandHandler + Send + Sync),
        redirect_host_manager: &'a Arc<Box<RedirectHostManager>>,
    ) -> CommandProcessorContext<'a> {
        CommandProcessorContext {
            connection_id,
            my_host,
            my_realm,
            peer_host,
            peer_realm,
            command_map,
            avp_map,
            connection_manager,
            hop_by_hop_id_generator,
            hop_by_hop_id_mapper,
            answer_manager,
            command_handler,
            redirect_host_manager,
        }
    }

    /// Processes an application command received from a Diameter peer.
    ///
    /// Connection-control commands such as CER/CEA, DWR/DWA, and DPR/DPA must be
    /// handled by the transport before calling this function because they can
    /// require connection-specific state changes.
    ///
    /// # Arguments
    /// * `context` - The context for processing the command.
    /// * `command` - The command to be processed.
    /// # Returns
    /// * `Result<(), String>` - Returns Ok(()) if the command was processed successfully, or an Err(String) with an error message if processing failed.
    pub async fn process_command(&self, command: &mut Command) -> Result<(), String> {
        if self.is_looped_request(command) {
            return self.reject_looped_request(command).await;
        }

        if command.is_request() {
            if self.is_my_command(command) {
                return self.process_local_command(command).await;
            } else {
                return self.forward_request(command).await;
            }
        } else {
            return self.process_answer(command).await;
        }
    }

    /// Checks if the command is a looped request by verifying if it is a request and if it has the local host in its Record-Route AVP.
    /// # Arguments
    /// * `context` - The context for processing the command.
    /// * `command` - The command to be checked.
    /// # Returns
    /// * `bool` - Returns true if the command is a looped request, false otherwise
    fn is_looped_request(&self, command: &Command) -> bool {
        command.is_request() && command.has_record_route(self.my_host)
    }

    fn is_my_command(&self, command: &Command) -> bool {
        command.get_destination_host().unwrap_or_default() == *self.my_host
            && command.get_destination_realm().unwrap_or_default() == *self.my_realm
    }

    async fn reject_looped_request(&self, command: &Command) -> Result<(), String> {
        error!(
            "Diameter loop detected for command with code {} and hop-by-hop ID {}. Sending error response.",
            command.code, command.hop_by_hop_id
        );

        let mut response = command.create_response();
        response.set_origin_host(self.my_host);
        response.set_origin_realm(self.my_realm);
        response.set_result_code(ResultCode::DiameterLoopDetected.as_u32());

        self.connection_manager
            .send_response(
                self.connection_id,
                &command.get_origin_host().unwrap_or_default(),
                &command.get_origin_realm().unwrap_or_default(),
                &response,
            )
            .await
            .map_err(|error| format!("Failed to send response: {}", error))
    }

    async fn process_local_command(&self, command: &Command) -> Result<(), String> {
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
                    answer.to_pretty_json_str(self.command_map, self.avp_map)
                );
                self.connection_manager
                    .send_response(
                        self.connection_id,
                        &answer.get_destination_host().unwrap_or_default(),
                        &answer.get_destination_realm().unwrap_or_default(),
                        &answer,
                    )
                    .await
                    .map_err(|error| format!("Failed to send answer: {}", error))?;
            }
            Ok(None) => {
                if command.is_request() {
                    info!(
                        "No answer generated for {} with code {} and hop-by-hop ID {}",
                        if command.is_request() {
                            "request"
                        } else {
                            "answer"
                        },
                        command.code,
                        command.hop_by_hop_id
                    )
                };
            }
            Err(error) => {
                error!(
                    "Failed to handle {} with code {} and hop-by-hop ID {}: {}",
                    if command.is_request() {
                        "request"
                    } else {
                        "answer"
                    },
                    command.code,
                    command.hop_by_hop_id,
                    error
                );
            }
        }

        Ok(())
    }

    /// Forwards a request command to the connection manager for further processing.
    /// This method is called when a request command is received that is not intended for this stack
    /// and needs to be forwarded to the appropriate connection.
    /// # Arguments
    /// * `request` - The request command to be forwarded.
    /// # Returns
    /// * `Result<(), String>` - Returns Ok(()) if the command was forwarded successfully, or an Err(String) with an error message if forwarding failed.
    async fn forward_request(&self, request: &mut Command) -> Result<(), String> {
        info!(
            "The request with code {} is not for this stack (my_host: {}, my_realm: {}), forwarding to connection manager",
            request.code, self.my_host, self.my_realm
        );
        // RFC 6733 Section 6.1.9: append Route-Record with this node's identity
        request.add_record_route(self.my_host);
        let original_hop_by_hop_id = request.hop_by_hop_id;
        let new_hop_by_hop_id = self.hop_by_hop_id_generator.next_id();
        request.hop_by_hop_id = new_hop_by_hop_id;

        // Store the mapping of new hop-by-hop ID to original hop-by-hop ID for future reference when the answer is received
        self.hop_by_hop_id_mapper
            .add_mapping(new_hop_by_hop_id, original_hop_by_hop_id)
            .await;

        // RFC 6733 Section 6.1.9: prepare for answer with the new hop-by-hop ID
        self.answer_manager
            .prepare_for_answer(
                new_hop_by_hop_id,
                self.connection_id.to_string(),
                self.peer_host.to_string(),
                self.peer_realm.to_string(),
            )
            .await;
        match self.connection_manager.send_request(request).await {
            Ok(_answer) => info!(
                "Successfully sent command {} through connection manager to {}@{}",
                request.code,
                request.get_destination_host().unwrap_or_default(),
                request.get_destination_realm().unwrap_or_default()
            ),
            Err(error) => {
                error!(
                    "Failed to send request through connection manager: {}",
                    error
                );
                let mut answer = request.create_response();
                answer.set_origin_host(self.my_host);
                answer.set_origin_realm(self.my_realm);
                answer.hop_by_hop_id = original_hop_by_hop_id; // Restore the original hop-by-hop ID for the error response
                answer.set_result_code(ResultCode::DiameterUnableToDeliver.as_u32());
                self.connection_manager
                    .send_response(
                        self.connection_id,
                        &request.get_origin_host().unwrap_or_default(),
                        &request.get_origin_realm().unwrap_or_default(),
                        &answer,
                    )
                    .await
                    .map_err(|error| format!("Failed to send response: {}", error))?;
            }
        }
        return Ok(());
    }

    async fn process_answer(&self, answer: &mut Command) -> Result<(), String> {
        // RFC 6733 Section 6.1.9: remove the Route-Record with this node's identity
        answer.remove_record_route(self.my_host);
        let orignal_hop_by_hop_id = self
            .hop_by_hop_id_mapper
            .remove_mapping(answer.hop_by_hop_id)
            .await;

        if let Some((connection_id, answer_host, answer_realm)) =
            self.answer_manager.answer_received(answer.clone()).await
        {
            if answer_host == self.my_host.to_string() && answer_realm == self.my_realm.to_string()
            {
                info!(
                    "The answer with code {} and hop-by-hop ID {} is for this stack (my_host: {}, my_realm: {})",
                    answer.code, answer.hop_by_hop_id, self.my_host, self.my_realm
                );
                return Ok(());
            }

            // RFC 6733 Section 6.1.9: restore the original hop-by-hop ID before forwarding the answer
            if let Some(original_hop_by_hop_id) = orignal_hop_by_hop_id {
                answer.hop_by_hop_id = original_hop_by_hop_id;
            }

            info!(
                "The answer with code {} is not for this stack (my_host: {}, my_realm: {}), forwarding to connection manager",
                answer.code, self.my_host, self.my_realm
            );
            match self
                .connection_manager
                .send_response(&connection_id, &answer_host, &answer_realm, answer)
                .await
            {
                Ok(()) => info!(
                    "Successfully sent command through connection manager to {}@{}",
                    answer.get_destination_host().unwrap_or_default(),
                    answer.get_destination_realm().unwrap_or_default()
                ),
                Err(error) => error!(
                    "Failed to send answer through connection manager: {}",
                    error
                ),
            }
            return Ok(());
        }

        error!(
            "No mapping found for answer with hop-by-hop ID {} and code {}. Cannot forward.",
            answer.hop_by_hop_id, answer.code
        );
        Err(format!(
            "No mapping found for answer with hop-by-hop ID {} and code {}",
            answer.hop_by_hop_id, answer.code
        ))
    }
}
