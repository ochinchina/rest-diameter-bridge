use crate::{
    avp::{
        Avp, AvpCode, AvpFlags, AvpMap, RedirectHostUsage, avp_to_name_value, name_value_to_avp,
    },
    utils::is_empty_file,
};
use bytes::{BufMut, BytesMut};
use log::{error, info};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use serde_yaml;
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Bit-flag constants for the Diameter command flags octet (RFC 6733 §3).
pub enum CommandFlags {
    Request = 0x80,
    Proxiable = 0x40,
    Error = 0x20,
    PotentiallyRetransmitted = 0x10,
}

impl CommandFlags {
    fn from_str(value: &str) -> Option<Vec<CommandFlags>> {
        let flags = value.to_lowercase();
        let flags = flags
            .chars()
            .map(|flag| match flag {
                'r' => Some(CommandFlags::Request),
                'p' => Some(CommandFlags::Proxiable),
                'e' => Some(CommandFlags::Error),
                't' => Some(CommandFlags::PotentiallyRetransmitted),
                _ => None,
            })
            .filter(|f| f.is_some())
            .map(|f| f.unwrap())
            .collect::<Vec<CommandFlags>>();

        return if flags.is_empty() {
            None
        } else {
            return Some(flags);
        };
    }

    fn str_from_u8(value: u8) -> String {
        let mut result = vec![];

        if value & 0x80 != 0 {
            result.push("R");
        }
        if value & 0x40 != 0 {
            result.push("P");
        }
        if value & 0x20 != 0 {
            result.push("E");
        }
        if value & 0x10 != 0 {
            result.push("T");
        }
        if result.is_empty() {
            String::new()
        } else {
            result.join("")
        }
    }

    pub fn u8_from_str(value: &str) -> Option<u8> {
        let flags = value.to_lowercase();
        let mut result: u8 = 0;

        for flag in flags.chars() {
            match flag {
                'r' => result |= CommandFlags::Request as u8,
                'p' => result |= CommandFlags::Proxiable as u8,
                'e' => result |= CommandFlags::Error as u8,
                't' => result |= CommandFlags::PotentiallyRetransmitted as u8,
                _ => {}
            }
        }

        if result == 0 { None } else { Some(result) }
    }

    fn as_u8(&self) -> u8 {
        *self as u8
    }
}

/// Standard Diameter command codes as defined in RFC 6733 and related specifications.
pub enum CommandCode {
    CapabilitiesExchange = 257,
    ReAuth = 258,
    SessionTermination = 275,
    AbortSession = 274,
    Accounting = 271,
    DeviceWatchdog = 280,
    DisconnectPeer = 282,
}
/// An incremental byte buffer that accumulates raw TCP/SCTP data and yields complete
/// [`Command`] frames as they arrive.
pub struct CommandBuffer {
    buffer: BytesMut,
}

impl CommandBuffer {
    /// Creates an empty `CommandBuffer`.
    pub fn new() -> Self {
        CommandBuffer {
            buffer: BytesMut::new(),
        }
    }

    /// Creates a `CommandBuffer` pre-loaded with the given bytes.
    pub fn from_bytes(bytes: &[u8]) -> Self {
        CommandBuffer {
            buffer: BytesMut::from(bytes),
        }
    }

    /// Appends `data` to the internal buffer.
    pub fn append(&mut self, data: &[u8]) {
        self.buffer.extend_from_slice(data);
    }

    /// Clears all data from the buffer.
    pub fn clear(&mut self) {
        self.buffer.clear();
    }

    /// Returns a slice of the raw buffered bytes.
    pub fn get(&self) -> &[u8] {
        &self.buffer
    }

    /// Attempts to read and decode one complete Diameter command from the buffer.
    /// The consumed bytes are removed from the buffer.
    /// Returns `None` if there is insufficient data for a full command.
    pub fn read_command(&mut self) -> Option<Command> {
        if self.buffer.len() < 20 {
            return None; // Not enough data for Diameter header
        }

        let length = u32::from_be_bytes([
            self.buffer[0],
            self.buffer[1],
            self.buffer[2],
            self.buffer[3],
        ]) & 0x00FFFFFF;
        if self.buffer.len() < length as usize {
            return None; // Not enough data for complete command
        }

        let command_data = self.buffer.split_to(length as usize).to_vec();
        match Command::decode(&command_data) {
            Ok(cmd) => Some(cmd),
            Err(e) => {
                error!("Failed to decode command: {}", e);
                None
            }
        }
    }

    /// Reads and decodes all complete Diameter commands currently held in the buffer.
    /// Each successfully decoded command is removed from the buffer.
    pub fn read_commands(&mut self) -> Vec<Command> {
        let mut commands = Vec::new();
        while let Some(cmd) = self.read_command() {
            commands.push(cmd);
        }
        commands
    }
}

/// A decoded Diameter command (request or answer) as defined in RFC 6733 §3.
#[derive(Debug, Clone)]
pub struct Command {
    pub code: u32,
    pub flags: u8,
    pub application_id: u32,
    pub hop_by_hop_id: u32,
    pub end_to_end_id: u32,
    pub avps: Vec<Avp>,
}

impl Command {
    /// Creates a new `Command` with the specified header fields and AVP list.
    ///
    /// # Arguments
    /// * `code` - The Diameter command code.
    /// * `flags` - The command flags byte (use [`CommandFlags`] constants).
    /// * `application_id` - The Diameter application identifier.
    /// * `hop_by_hop_id` - Hop-by-Hop identifier used to match requests with answers.
    /// * `end_to_end_id` - End-to-End identifier used for duplicate detection.
    /// * `avps` - The list of AVPs carried by the command.
    pub fn new(
        code: u32,
        flags: u8,
        application_id: u32,
        hop_by_hop_id: u32,
        end_to_end_id: u32,
        avps: Vec<Avp>,
    ) -> Self {
        Command {
            code,
            flags,
            application_id,
            hop_by_hop_id,
            end_to_end_id,
            avps,
        }
    }

    // create diameter command from json, using command map and avp map to get names and values
    pub fn from_json_str(
        json: &str,
        command_map: &CommandMap,
        avp_map: &AvpMap,
    ) -> Result<Command, String> {
        let v: Value = serde_json::from_str(json).map_err(|e| e.to_string())?;
        Self::from_json_value(&v, command_map, avp_map)
    }

    pub fn from_json_value(
        v: &Value,
        command_map: &CommandMap,
        avp_map: &AvpMap,
    ) -> Result<Command, String> {
        match v.as_object() {
            Some(obj) => {
                let command_define = Self::get_command_define(obj, command_map);
                if command_define.is_none() {
                    return Err("Command not found in command map".to_string());
                }
                let command_define = command_define.unwrap();

                let mut avps = Vec::new();
                let mut application_id = command_define.application_id;
                let mut hop_by_hop_id = 0;
                let mut end_to_end_id = 0;
                let mut flags = 0;

                obj.iter().for_each(|(k, v)| match k.as_str() {
                    "code" | "name" => {}
                    "application_id" => {
                        if let Some(app_id) = v.as_u64() {
                            application_id = app_id as u32;
                        }
                    }
                    "hop_by_hop_id" => {
                        hop_by_hop_id = v.as_u64().unwrap_or(0) as u32;
                    }
                    "end_to_end_id" => {
                        end_to_end_id = v.as_u64().unwrap_or(0) as u32;
                    }
                    "callback-url" => {}
                    "flags" => {
                        CommandFlags::from_str(v.as_str().unwrap_or_default())
                            .unwrap_or_default()
                            .iter()
                            .for_each(|flag| {
                                flags |= flag.as_u8();
                            });
                    }
                    avp_name => {
                        // If the value is an array, we need to create multiple AVPs with the same name
                        if v.is_array() {
                            v.as_array().unwrap().iter().for_each(|item| {
                                if let Ok(avp) = name_value_to_avp(avp_name, item, avp_map) {
                                    avps.push(avp);
                                } else {
                                    error!("Unknown AVP: {} with value {:?}", avp_name, item);
                                }
                            });
                        } else {
                            if let Ok(avp) = name_value_to_avp(avp_name, v, avp_map) {
                                avps.push(avp);
                            } else {
                                error!("Unknown AVP: {} with value {:?}", avp_name, v);
                            }
                        }
                    }
                });

                command_define.sort_avps(&mut avps, avp_map);

                Ok(Command::new(
                    command_define.code,
                    command_define.flags() | flags,
                    application_id,
                    hop_by_hop_id,
                    end_to_end_id,
                    avps,
                ))
            }
            None => return Err("Invalid JSON format".to_string()),
        }
    }

    fn get_command_define(
        obj: &Map<String, Value>,
        command_map: &CommandMap,
    ) -> Option<CommandJson> {
        if let Some(code) = obj.get("code").and_then(|v| v.as_u64()) {
            let request = obj.get("request").and_then(|v| v.as_bool()).unwrap_or(true);
            command_map.get_by_code(code as u32, request)
        } else if let Some(name) = obj.get("name").and_then(|v| v.as_str()) {
            command_map.get_by_name(name)
        } else {
            None
        }
    }

    // create json from diameter command, using command map and avp map to get names and values
    pub fn to_json(&self, command_map: &CommandMap, avp_map: &AvpMap) -> Value {
        let avps_json: Vec<(String, Value)> = self
            .avps
            .iter()
            .map(|avp| {
                let (name, value) = avp_to_name_value(avp, avp_map).unwrap_or_else(|_| {
                    (
                        format!("Unknown-AVP-{}", avp.code),
                        Value::String("Unknown".to_string()),
                    )
                });
                (name, value)
            })
            .collect();

        let mut r = serde_json::json!({});

        if let Some(command_define) = command_map.get_by_code(self.code, self.is_request()) {
            r.as_object_mut().unwrap().insert(
                "name".to_string(),
                Value::String(command_define.long_name.clone()),
            );
        }

        r.as_object_mut().unwrap().insert(
            "code".to_string(),
            Value::Number(serde_json::Number::from(self.code)),
        );

        r.as_object_mut().unwrap().insert(
            "application_id".to_string(),
            Value::Number(serde_json::Number::from(self.application_id)),
        );

        r.as_object_mut().unwrap().insert(
            "hop_by_hop_id".to_string(),
            Value::Number(serde_json::Number::from(self.hop_by_hop_id)),
        );

        r.as_object_mut().unwrap().insert(
            "end_to_end_id".to_string(),
            Value::Number(serde_json::Number::from(self.end_to_end_id)),
        );

        r.as_object_mut().unwrap().insert(
            "flags".to_string(),
            Value::String(CommandFlags::str_from_u8(self.flags)),
        );

        for (name, value) in avps_json {
            if let Some(old_value) = r.as_object_mut().unwrap().get_mut(&name) {
                if old_value.is_array() {
                    old_value.as_array_mut().unwrap().push(value);
                } else {
                    *old_value = serde_json::json!([old_value.clone(), value]);
                }
            } else {
                r.as_object_mut().unwrap().insert(name, value);
            }
        }
        r
    }

    pub fn to_pretty_json_str(&self, command_map: &CommandMap, avp_map: &AvpMap) -> String {
        let json_value = self.to_json(command_map, avp_map);
        serde_json::to_string_pretty(&json_value).unwrap_or_else(|_| "{}".to_string())
    }

    /// Creates an answer command from this request, copying the header identifiers and
    /// swapping Destination-Host/Realm into Origin-Host/Realm.
    pub fn create_response(&self) -> Command {
        let mut command = Command {
            code: self.code,
            flags: (self.flags & 0x7F) | 0x00, // Clear the Request bit to indicate this is a response
            application_id: self.application_id,
            hop_by_hop_id: self.hop_by_hop_id,
            end_to_end_id: self.end_to_end_id,
            avps: Vec::new(),
        };

        if self.get_destination_host().is_some() {
            command.set_origin_host(&self.get_destination_host().unwrap());
        }
        if self.get_destination_realm().is_some() {
            command.set_origin_realm(&self.get_destination_realm().unwrap());
        }

        command
    }

    /// Returns `true` if the Request bit is set in the command flags.
    pub fn is_request(&self) -> bool {
        self.flags & 0x80 != 0
    }

    /// Returns `true` if this command is an answer (Request bit not set).
    pub fn is_answer(&self) -> bool {
        !self.is_request()
    }

    /// Returns `true` if the Proxiable bit is set in the command flags.
    pub fn is_proxiable(&self) -> bool {
        self.flags & 0x40 != 0
    }

    /// Returns `true` if the Error bit is set in the command flags.
    pub fn is_error(&self) -> bool {
        self.flags & 0x20 != 0
    }

    /// Returns `true` if the Potentially Retransmitted bit is set in the command flags.
    pub fn is_retransmission(&self) -> bool {
        self.flags & 0x10 != 0
    }

    /// Returns the command code.
    pub fn get_command_id(&self) -> u32 {
        self.code
    }

    /// Returns the application identifier.
    pub fn get_application_id(&self) -> u32 {
        self.application_id
    }

    /// Appends a single AVP to the end of the AVP list.
    pub fn add_avp(&mut self, avp: Avp) {
        self.avps.push(avp);
    }

    /// Appends multiple AVPs to the end of the AVP list.
    pub fn add_avps(&mut self, avps: Vec<Avp>) {
        self.avps.extend(avps);
    }

    /// Returns the first AVP whose code matches `code`, or `None` if not found.
    pub fn get_avp(&self, code: u32) -> Option<&Avp> {
        self.avps.iter().find(|avp| avp.code == code)
    }

    /// Returns a vector of references to all AVPs whose code matches `code`.
    /// # Arguments
    /// * `code` - The AVP code to search for.
    /// # Returns
    /// * `Vec<&Avp>` - A vector of references to matching AVPs. Empty if none found.
    pub fn get_avps(&self, code: u32) -> Vec<&Avp> {
        self.avps.iter().filter(|avp| avp.code == code).collect()
    }

    /**
     * Convenience method to get the Result-Code AVP value as u32, if present
     */
    pub fn get_result_code(&self) -> Option<u32> {
        self.get_avp(268).and_then(|avp| avp.as_unsigned32())
    }

    /// Sets the Result-Code AVP (code 268). If one already exists it is updated in-place;
    /// otherwise a new Mandatory AVP is appended.
    pub fn set_result_code(&mut self, result_code: u32) {
        if let Some(avp) = self.avps.iter_mut().find(|avp| avp.code == 268) {
            avp.set_unsigned32(result_code);
        } else {
            self.avps.push(Avp::from_unsigned32(
                268,
                AvpFlags::Mandatory as u8,
                None,
                result_code,
            ));
        }
    }
    /**
     * Convenience method to get the Error-Message AVP value as String, if present
     */
    pub fn get_error_message(&self) -> Option<String> {
        self.get_avp(281).and_then(|avp| avp.as_utf8_string())
    }

    /**
     * Convenience method to get the Origin-Host AVP value as String, if present
     */
    pub fn get_origin_host(&self) -> Option<String> {
        self.get_avp(264).and_then(|avp| avp.as_utf8_string())
    }

    /// Sets the Origin-Host AVP (code 264). Updates an existing one or appends a new one.
    pub fn set_origin_host(&mut self, origin_host: &String) {
        if let Some(avp) = self.avps.iter_mut().find(|avp| avp.code == 264) {
            avp.set_utf8_string(origin_host);
        } else {
            self.avps.push(Avp::from_utf8_string(
                264,
                AvpFlags::Mandatory as u8,
                None,
                origin_host,
            ));
        }
    }
    /**
     * Convenience method to get the Origin-Realm AVP value as String, if present
     */
    pub fn get_origin_realm(&self) -> Option<String> {
        self.get_avp(296).and_then(|avp| avp.as_utf8_string())
    }

    /// Sets the Origin-Realm AVP (code 296). Updates an existing one or appends a new one.
    pub fn set_origin_realm(&mut self, origin_realm: &String) {
        if let Some(avp) = self.avps.iter_mut().find(|avp| avp.code == 296) {
            avp.set_utf8_string(origin_realm);
        } else {
            self.avps.push(Avp::from_utf8_string(
                296,
                AvpFlags::Mandatory as u8,
                None,
                origin_realm,
            ));
        }
    }

    /**
     * Convenience method to get the Destination-Host AVP value as String, if present
     */
    pub fn get_destination_host(&self) -> Option<String> {
        self.get_avp(293).and_then(|avp| avp.as_utf8_string())
    }

    /// Sets the Destination-Host AVP (code 293). Updates an existing one or appends a new one.
    pub fn set_destination_host(&mut self, destination_host: &String) {
        if let Some(avp) = self.avps.iter_mut().find(|avp| avp.code == 293) {
            avp.set_utf8_string(destination_host);
        } else {
            self.avps.push(Avp::from_utf8_string(
                AvpCode::DestinationHost as u32,
                AvpFlags::Mandatory as u8,
                None,
                destination_host,
            ));
        }
    }
    /**
     * Convenience method to get the Destination-Realm AVP value as String, if present
     */
    pub fn get_destination_realm(&self) -> Option<String> {
        self.get_avp(283).and_then(|avp| avp.as_utf8_string())
    }

    /// Sets the Destination-Realm AVP (code 283). Updates an existing one or appends a new one.
    pub fn set_destination_realm(&mut self, destination_realm: &String) {
        if let Some(avp) = self.avps.iter_mut().find(|avp| avp.code == 283) {
            avp.set_utf8_string(destination_realm);
        } else {
            self.avps.push(Avp::from_utf8_string(
                AvpCode::DestinationRealm as u32,
                AvpFlags::Mandatory as u8,
                None,
                destination_realm,
            ));
        }
    }

    pub fn add_record_route(&mut self, host: &str) {
        self.avps.push(Avp::from_utf8_string(
            AvpCode::RouteRecord as u32,
            AvpFlags::Mandatory as u8,
            None,
            host,
        ));
    }

    pub fn remove_record_route(&mut self, host: &str) {
        self.avps.retain(|avp| {
            !(avp.code == AvpCode::RouteRecord as u32
                && avp.as_utf8_string().map_or(false, |s| s == host))
        });
    }

    /// Returns `true` if any Route-Record AVP (code 282) matches `host`.
    pub fn has_record_route(&self, host: &str) -> bool {
        self.avps.iter().any(|avp| {
            avp.code == AvpCode::RouteRecord as u32
                && avp.as_utf8_string().map_or(false, |s| s == host)
        })
    }

    pub fn get_redirect_hosts(&self) -> Option<Vec<String>> {
        self.get_avps(AvpCode::RedirectHost as u32)
            .iter()
            .filter_map(|avp| avp.as_utf8_string())
            .collect::<Vec<String>>()
            .into()
    }
    pub fn get_redirect_host_usage(&self) -> Option<RedirectHostUsage> {
        self.get_avp(AvpCode::RedirectHostUsage as u32)
            .and_then(|avp| avp.as_unsigned32())
            .and_then(RedirectHostUsage::from_u32)
    }

    /// Encodes this command to its on-wire byte representation.
    pub fn encode(&self) -> Vec<u8> {
        let length = 20
            + self
                .avps
                .iter()
                .map(|avp| avp.total_length_including_padding() as usize)
                .sum::<usize>();
        let mut buffer = BytesMut::new();

        buffer.put_u32(0x01000000 | (length as u32 & 0x00FFFFFF));
        buffer.put_u32((self.flags as u32) << 24 | (self.code & 0x00FFFFFF));
        buffer.put_u32(self.application_id);
        buffer.put_u32(self.hop_by_hop_id);
        buffer.put_u32(self.end_to_end_id);
        buffer.extend(self.avps.iter().flat_map(|avp| avp.encode()));
        buffer.to_vec()
    }

    /// Decodes a Diameter command from the given byte slice.
    ///
    /// # Returns
    /// * `Ok(Command)` on success.
    /// * `Err(String)` if the data is too short or malformed.
    pub fn decode(data: &[u8]) -> Result<Self, String> {
        if data.len() < 20 {
            return Err("Data too short for Diameter header".to_string());
        }

        let length = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) & 0x00FFFFFF;
        if data.len() < length as usize {
            return Err("Data length mismatch".to_string());
        }

        let flags = data[4];
        let code = u32::from_be_bytes([data[4], data[5], data[6], data[7]]) & 0x00FFFFFF;
        let application_id = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
        let hop_by_hop_id = u32::from_be_bytes([data[12], data[13], data[14], data[15]]);
        let end_to_end_id = u32::from_be_bytes([data[16], data[17], data[18], data[19]]);

        let mut avps = Vec::new();
        let mut offset = 20;
        while offset + 8 <= length as usize {
            match Avp::decode(&data[offset..]) {
                Ok(avp) => {
                    offset += avp.total_length_including_padding() as usize;
                    avps.push(avp);
                }
                Err(e) => return Err(format!("Failed to decode AVP at offset {}: {}", offset, e)),
            }
        }

        Ok(Command {
            code,
            flags,
            application_id,
            hop_by_hop_id,
            end_to_end_id,
            avps,
        })
    }
}

impl std::fmt::Display for Command {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let avps = self
            .avps
            .iter()
            .map(|avp| format!("{}", avp))
            .collect::<Vec<String>>()
            .join(", ");
        write!(
            f,
            "Command {{ code: {}, flags: {:02x}, application_id: {}, hop_by_hop_id: {}, end_to_end_id: {}, avps: [{}] }}",
            self.code,
            self.flags,
            self.application_id,
            self.hop_by_hop_id,
            self.end_to_end_id,
            avps
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandJson {
    #[serde(rename = "long-name")]
    pub long_name: String,
    #[serde(rename = "short-name")]
    pub short_name: String,
    #[serde(rename = "code")]
    pub code: u32,
    #[serde(rename = "application-id")]
    pub application_id: u32,
    pub request: bool,
    pub proxiable: bool,
    pub error: bool,
    pub avps: Vec<String>,
}

impl CommandJson {
    pub fn new(
        long_name: String,
        short_name: String,
        code: u32,
        application_id: u32,
        request: bool,
        proxiable: bool,
        error: bool,
        avps: Vec<String>,
    ) -> Self {
        CommandJson {
            long_name,
            short_name,
            code,
            application_id,
            request,
            proxiable,
            error,
            avps,
        }
    }

    pub fn flags(&self) -> u8 {
        (if self.request { 0x80 } else { 0 })
            | (if self.proxiable { 0x40 } else { 0 })
            | (if self.error { 0x20 } else { 0 })
    }

    /**
     * Sort the AVPs in the command according to the order defined in the CommandJson, using the avp_map to get the AVP names from codes. AVPs that are not in the CommandJson will be placed at the end in their original order.
     */
    pub fn sort_avps(&self, avps: &mut Vec<Avp>, avp_map: &AvpMap) {
        avps.sort_by_key(|avp| {
            self.avps
                .iter()
                .position(|name| {
                    if let Some(avp_info) = avp_map.get_by_code(avp.code) {
                        avp_info.name == *name
                    } else {
                        false
                    }
                })
                .unwrap_or(usize::MAX)
        });
    }
}

lazy_static::lazy_static! {
    static ref STANDARD_COMMANDS: Vec<CommandJson> = vec![
        CommandJson::new(
            "Abort-Session-Request".to_string(),
            "ASR".to_string(),
            CommandCode::AbortSession as u32,
            0,
            true,
            true,
            false,
            vec!["Session-Id".to_string(),
            "Origin-Host".to_string(),
            "Origin-Realm".to_string(),
            "Destination-Realm".to_string(),
            "Destination-Host".to_string(),
            "Auth-Application-Id".to_string(),
            "User-Name".to_string(),
            "Origin-State-Id".to_string(),
            "Proxy-Info".to_string(),
            "Route-Record".to_string(),]),
        CommandJson::new(
            "Abort-Session-Answer".to_string(),
            "ASA".to_string(),
            CommandCode::AbortSession as u32,
            0,
            false,
            true,
            false,
            vec!["Session-Id".to_string(),
            "Result-Code".to_string(),
            "Origin-Host".to_string(),
            "Origin-Realm".to_string(),
            "User-Name".to_string(),
            "Origin-State-Id".to_string(),
            "Error-Message".to_string(),
            "Error-Reporting-Host".to_string(),
            "Failed-AVP".to_string(),
            "Redirect-Host".to_string(),
            "Redirect-Host-Usage".to_string(),
            "Redirect-Max-Cache-Time".to_string(),
            "Proxy-Info".to_string(),]),

        CommandJson::new(
            "Accounting-Request".to_string(),
            "ACR".to_string(),
            CommandCode::Accounting as u32,
            0,
            true,
            true,
            false,
            vec!["Session-Id".to_string(),
            "Origin-Host".to_string(),
            "Origin-Realm".to_string(),
            "Destination-Realm".to_string(),
            "Accounting-Record-Type".to_string(),
            "Accounting-Record-Number".to_string(),
            "Acct-Application-Id".to_string(),
            "Vendor-Specific-Application-Id".to_string(),
            "User-Name".to_string(),
            "Destination-Host".to_string(),
            "Accounting-Sub-Session-Id".to_string(),
            "Accounting-Session-Id".to_string(),
            "Acct-Multi-Session-Id".to_string(),
            "Acct-Interim-Interval".to_string(),
            "Accounting-Realtime-Required".to_string(),
            "Origin-State-Id".to_string(),
            "Event-Timestamp".to_string(),
            "Proxy-Info".to_string(),
            "Route-Record".to_string(),]),
        CommandJson::new(
            "Accounting-Answer".to_string(),
            "ACA".to_string(),
            CommandCode::Accounting as u32,
            0,
            false,
            true,
            false,
            vec!["Session-Id".to_string(),
            "Result-Code".to_string(),
            "Origin-Host".to_string(),
            "Origin-Realm".to_string(),
            "Accounting-Record-Type".to_string(),
            "Accounting-Record-Number".to_string(),
            "Acct-Application-Id".to_string(),
            "Vendor-Specific-Application-Id".to_string(),
            "User-Name".to_string(),
            "Accounting-Sub-Session-Id".to_string(),
            "Acct-Session-Id".to_string(),
            "Acct-Multi-Session-Id".to_string(),
            "Error-Message".to_string(),
            "Error-Reporting-Host".to_string(),
            "Failed-AVP".to_string(),
            "Acct-Interim-Interval".to_string(),
            "Accounting-Realtime-Required".to_string(),
            "Origin-State-Id".to_string(),
            "Event-Timestamp".to_string(),
            "Proxy-Info".to_string(),]),
        CommandJson::new(
            "Capabilities-Exchange-Request".to_string(),
            "CER".to_string(),
            CommandCode::CapabilitiesExchange as u32,
            0,
            true,
            true,
            false,
            vec!["Origin-Host".to_string(),
            "Origin-Realm".to_string(),
            "Host-IP-Address".to_string(),
            "Vendor-Id".to_string(),
            "Product-Name".to_string(),
            "Origin-State-Id".to_string(),
            "Supported-Vendor-Id".to_string(),
            "Auth-Application-Id".to_string(),
            "Inband-Security-Id".to_string(),
            "Acct-Application-Id".to_string(),
            "Vendor-Specific-Application-Id".to_string(),
            "Firmware-Revision".to_string()],
        ),
        CommandJson::new(
            "Capabilities-Exchange-Answer".to_string(),
            "CEA".to_string(),
            CommandCode::CapabilitiesExchange as u32,
            0,
            false,
            true,
            false,
            vec!["Result-Code".to_string(),
            "Origin-Host".to_string(),
            "Origin-Realm".to_string(),
            "Host-IP-Address".to_string(),
            "Vendor-Id".to_string(),
            "Product-Name".to_string(),
            "Origin-State-Id".to_string(),
            "Error-Message".to_string(),
            "Failed-AVP".to_string(),
            "Supported-Vendor-Id".to_string(),
            "Auth-Application-Id".to_string(),
            "Inband-Security-Id".to_string(),
            "Acct-Application-Id".to_string(),
            "Vendor-Specific-Application-Id".to_string(),
            "Firmware-Revision".to_string()],
        ),
        CommandJson::new(
            "Device-Watchdog-Request".to_string(),
            "DWR".to_string(),
            CommandCode::DeviceWatchdog as u32,
            0,
            true,
            true,
            false,
            vec!["Origin-Host".to_string(), "Origin-Realm".to_string(), "Origin-State-Id".to_string()],
        ),
        CommandJson::new(
            "Device-Watchdog-Answer".to_string(),
            "DWA".to_string(),
            CommandCode::DeviceWatchdog as u32,
            0,
            false,
            true,
            false,
            vec!["Result-Code".to_string(),
            "Origin-Host".to_string(),
            "Origin-Realm".to_string(),
            "Error-Message".to_string(),
            "Failed-AVP".to_string(),
            "Origin-State-Id".to_string()],
        ),
        CommandJson::new(
            "Disconnect-Peer-Request".to_string(),
            "DPR".to_string(),
            CommandCode::DisconnectPeer as u32,
            0,
            true,
            true,
            false,
            vec!["Origin-Host".to_string(), "Origin-Realm".to_string(), "Disconnect-Cause".to_string()],
        ),
        CommandJson::new(
            "Disconnect-Peer-Answer".to_string(),
            "DPA".to_string(),
            CommandCode::DisconnectPeer as u32,
            0,
            false,
            true,
            false,
            vec!["Result-Code".to_string(),
            "Origin-Host".to_string(),
            "Origin-Realm".to_string(),
            "Error-Message".to_string(),
            "Failed-AVP".to_string()],
        ),
        CommandJson::new(
            "Re-Auth-Request".to_string(),
            "RAR".to_string(),
            CommandCode::ReAuth as u32,
            0,
            true,
            true,
            false,
            vec!["Session-Id".to_string(),
            "Origin-Host".to_string(),
            "Origin-Realm".to_string(),
            "Destination-Realm".to_string(),
            "Destination-Host".to_string(),
            "Auth-Application-Id".to_string(),
            "Re-Auth-Request-Type".to_string(),
            "User-Name".to_string(),
            "Origin-State-Id".to_string(),
            "Proxy-Info".to_string(),
            "Route-Record".to_string(),],
        ),
        CommandJson::new(
            "Re-Auth-Answer".to_string(),
            "RAA".to_string(),
            CommandCode::ReAuth as u32,
            0,
            false,
            true,
            false,
            vec!["Session-Id".to_string(),
            "Result-Code".to_string(),
            "Origin-Host".to_string(),
            "Origin-Realm".to_string(),
            "User-Name".to_string(),
            "Origin-State-Id".to_string(),
            "Error-Message".to_string(),
            "Error-Reporting-Host".to_string(),
            "Failed-AVP".to_string(),
            "Redirect-Host".to_string(),
            "Redirect-Host-Usage".to_string(),
            "Redirect-Max-Cache-Time".to_string(),
            "Proxy-Info".to_string(),],
        ),
        CommandJson::new(
            "Session-Termination-Request".to_string(),
            "STR".to_string(),
            CommandCode::SessionTermination as u32,
            0,
            true,
            true,
            false,
            vec!["Session-Id".to_string(),
            "Origin-Host".to_string(),
            "Origin-Realm".to_string(),
            "Destination-Realm".to_string(),
            "Auth-Application-Id".to_string(),
            "Termination-Cause".to_string(),
            "User-Name".to_string(),
            "Destination-Host".to_string(),
            "Class".to_string(),
            "Origin-State-Id".to_string(),
            "Proxy-Info".to_string(),
            "Route-Record".to_string(),],
        ),
        CommandJson::new(
            "Session-Termination-Answer".to_string(),
            "STA".to_string(),
            CommandCode::SessionTermination as u32,
            0,
            false,
            true,
            false,
            vec!["Session-Id".to_string(),
            "Result-Code".to_string(),
            "Origin-Host".to_string(),
            "Origin-Realm".to_string(),
            "User-Name".to_string(),
            "Class".to_string(),
            "Error-Message".to_string(),
            "Error-Reporting-Host".to_string(),
            "Failed-AVP".to_string(),
            "Origin-State-Id".to_string(),
            "Redirect-Host".to_string(),
            "Redirect-Host-Usage".to_string(),
            "Redirect-Max-Cache-Time".to_string(),
            "Proxy-Info".to_string(),],
        ),
    ];
    static ref STANDARD_COMMAND_MAP: CommandMap = CommandMap::new(STANDARD_COMMANDS.clone());
}

#[derive(Debug, Clone)]
pub struct CommandMap {
    code_to_command: HashMap<u32, Vec<CommandJson>>,
    name_to_command: HashMap<String, CommandJson>,
}

impl CommandMap {
    pub fn new(commands: Vec<CommandJson>) -> Self {
        let mut command_map = CommandMap {
            code_to_command: HashMap::new(),
            name_to_command: HashMap::new(),
        };

        for cmd in STANDARD_COMMANDS.iter() {
            command_map.add_command(cmd.clone());
        }

        for cmd in commands {
            command_map.add_command(cmd);
        }

        command_map
    }

    fn add_command(&mut self, cmd: CommandJson) {
        let entry = self
            .code_to_command
            .entry(cmd.code)
            .or_insert_with(Vec::new);
        entry.push(cmd.clone());

        self.name_to_command
            .insert(cmd.long_name.clone().to_lowercase(), cmd.clone());
        self.name_to_command
            .insert(cmd.short_name.clone().to_lowercase(), cmd);
    }

    pub fn get_by_code(&self, code: u32, request: bool) -> Option<CommandJson> {
        self.code_to_command
            .get(&code)
            .and_then(|m| m.iter().find(|cmd| cmd.request == request))
            .cloned()
    }

    pub fn get_by_name(&self, name: &str) -> Option<CommandJson> {
        let name = name.to_lowercase();
        self.name_to_command.get(&name).cloned()
        //.or_else(|| STANDARD_COMMAND_MAP.get_by_name(&name))
    }
}

pub fn load_command_definition_from_yaml_files(
    filenames: Vec<String>,
) -> Result<Vec<CommandJson>, String> {
    let mut commands = Vec::new();
    for filename in filenames {
        let mut file_commands = load_command_definition_from_yaml_file(&filename)?;
        commands.append(&mut file_commands);
    }
    Ok(commands)
}

pub fn load_command_definition_from_yaml_file(path: &str) -> Result<Vec<CommandJson>, String> {
    if is_empty_file(path) {
        error!("File {} is empty", path);
        return Err(format!("File {} is empty", path));
    }
    let contents = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
    let yaml: serde_yaml::Value = serde_yaml::from_str(&contents).map_err(|e| {
        error!("Failed to parse YAML: {}", e);
        format!("Failed to parse YAML: {}", e)
    })?;
    return load_command_definition_from_yaml(&yaml);
}

pub fn load_command_definition_from_yaml(
    yaml: &serde_yaml::Value,
) -> Result<Vec<CommandJson>, String> {
    if yaml.is_mapping() {
        return yaml
            .as_mapping()
            .unwrap()
            .get(&serde_yaml::Value::String("commands".to_string()))
            .ok_or("Missing 'commands' key in YAML".to_string())
            .and_then(|v| {
                if v.is_sequence() {
                    let r = v
                        .as_sequence()
                        .unwrap()
                        .iter()
                        .map(|item| {
                            serde_yaml::from_value::<CommandJson>(item.clone())
                                .map_err(|e| e.to_string())
                        })
                        .collect::<Result<Vec<CommandJson>, String>>();
                    info!(
                        "Loaded {} commands from YAML",
                        r.as_ref().map(|v| v.len()).unwrap_or(0)
                    );
                    r
                } else {
                    error!("Expected 'commands' to be a sequence");
                    Err("Expected 'commands' to be a sequence".to_string())
                }
            });
    } else {
        error!("Invalid YAML format: expected a mapping at the top level");
        Err("Invalid YAML format: expected a mapping at the top level".to_string())
    }
}
