use base64::prelude::*;
use log::info;
use serde_json::{Map, Value};
use serde_yaml;
use std::{
    collections::HashMap,
    net::{Ipv4Addr, Ipv6Addr},
};

pub enum AvpFlags {
    VendorSpecific = 0x80,
    Mandatory = 0x40,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AvpCode {
    AcctInterimInterval = 85,
    AccountingRealtimeRequired = 483,
    AcctMultiSessionId = 50,
    AccountingRecordNumber = 485,
    AccountingRecordType = 480,
    AcctSessionId = 44,
    AccountingSubSessionId = 287,
    AcctApplicationId = 259,
    AuthApplicationId = 258,
    AuthRequestType = 274,
    AuthorizationLifetime = 291,
    AuthGracePeriod = 276,
    AuthSessionState = 277,
    ReAuthRequestType = 285,
    Class = 25,
    DestinationHost = 293,
    DestinationRealm = 283,
    DisconnectCause = 273,
    ErrorMessage = 281,
    ErrorReportingHost = 294,
    EventTimestamp = 55,
    ExperimentalResult = 297,
    ExperimentalResultCode = 298,
    FailedAvp = 279,
    FirmwareRevision = 267,
    HostIpAddress = 257,
    InbandSecurityId = 299,
    MultiRoundTimeOut = 272,
    OriginHost = 264,
    OriginRealm = 296,
    OriginStateId = 278,
    ProductName = 269,
    ProxyHost = 280,
    ProxyInfo = 284,
    ProxyState = 33,
    RedirectHost = 292,
    RedirectHostUsage = 261,
    RedirectMaxCacheTime = 262,
    ResultCode = 268,
    RouteRecord = 282,
    SessionId = 263,
    SessionTimeout = 27,
    SessionBinding = 270,
    SessionServerFailover = 271,
    SupportedVendorId = 265,
    TerminationCause = 295,
    UserName = 1,
    VendorId = 266,
    VendorSpecificApplicationId = 260,
}

impl AvpCode {
    pub fn as_u32(&self) -> u32 {
        *self as u32
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResultCode {
    DiameterMultiRoundAuth = 1001,
    DiameterSuccess = 2001,
    DiameterLimitedSuccess = 2002,
    DiameterCommandUnsupported = 3001,
    DiameterUnableToDeliver = 3002,
    DiameterRealmNotServed = 3003,
    DiameterTooBusy = 3004,
    DiameterLoopDetected = 3005,
    DiameterRedirectIndication = 3006,
    DiameterApplicationUnsupported = 3007,
    DiameterInvalidHdrBits = 3008,
    DiameterInvalidAvpBits = 3009,
    DiameterUnknownPeer = 3010,
    DiameterAuthenticationRejected = 4001,
    DiameterOutOfSpace = 4002,
    ElectionLost = 4003,
    DiameterAvpUnsupported = 5001,
    DiameterUnknownSessionId = 5002,
    DiameterAuthorizationRejected = 5003,
    DiameterInvalidAvpValue = 5004,
    DiameterMissingAvp = 5005,
    DiameterResourcesExceeded = 5006,
    DiameterContradictingAvps = 5007,
    DiameterAvpNotAllowed = 5008,
    DiameterAvpOccursTooManyTimes = 5009,
    DiameterNoCommonApplication = 5010,
    DiameterUnsupportedVersion = 5011,
    DiameterUnableToComply = 5012,
    DiameterInvalidBitInHeader = 5013,
    DiameterInvalidAvpLength = 5014,
    DiameterInvalidMessageLength = 5015,
    DiameterInvalidAvpBitCombo = 5016,
    DiameterNoCommonSecurity = 5017,
}

impl ResultCode {
    pub fn as_u32(&self) -> u32 {
        *self as u32
    }
    pub fn is_informational(&self) -> bool {
        let code = self.as_u32();
        code >= 1000 && code < 2000
    }

    pub fn is_success(&self) -> bool {
        let code = self.as_u32();
        code >= 2000 && code < 3000
    }

    pub fn is_protocol_errors(&self) -> bool {
        let code = self.as_u32();
        code >= 3000 && code < 4000
    }

    pub fn is_transient_failure(&self) -> bool {
        let code = self.as_u32();
        code >= 4000 && code < 5000
    }

    pub fn is_permanent_failure(&self) -> bool {
        let code = self.as_u32();
        code >= 5000 && code < 6000
    }
}
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum AvpType {
    Address,
    Enumerated,
    OctetString,
    Time,
    UTF8String,
    DiameterIdentity,
    DiameterURI,
    IPFilterRule,
    Integer32,
    Unsigned32,
    Integer64,
    Unsigned64,
    Float32,
    Float64,
    Grouped,
}

impl From<String> for AvpType {
    fn from(s: String) -> Self {
        match s.to_lowercase().as_str() {
            "address" => AvpType::Address,
            "enumerated" => AvpType::Enumerated,
            "octetstring" => AvpType::OctetString,
            "time" => AvpType::Time,
            "utf8string" => AvpType::UTF8String,
            "diameteridentity" => AvpType::DiameterIdentity,
            "diameteruri" => AvpType::DiameterURI,
            "ipfilterrule" => AvpType::IPFilterRule,
            "integer32" => AvpType::Integer32,
            "unsigned32" => AvpType::Unsigned32,
            "integer64" => AvpType::Integer64,
            "unsigned64" => AvpType::Unsigned64,
            "float32" => AvpType::Float32,
            "float64" => AvpType::Float64,
            "grouped" => AvpType::Grouped,
            _ => AvpType::OctetString,
        }
    }
}

impl From<AvpType> for String {
    fn from(avp_type: AvpType) -> Self {
        match avp_type {
            AvpType::Address => "Address".to_string(),
            AvpType::Enumerated => "Enumerated".to_string(),
            AvpType::OctetString => "OctetString".to_string(),
            AvpType::Time => "Time".to_string(),
            AvpType::UTF8String => "UTF8String".to_string(),
            AvpType::DiameterIdentity => "DiameterIdentity".to_string(),
            AvpType::DiameterURI => "DiameterURI".to_string(),
            AvpType::IPFilterRule => "IPFilterRule".to_string(),
            AvpType::Integer32 => "Integer32".to_string(),
            AvpType::Unsigned32 => "Unsigned32".to_string(),
            AvpType::Integer64 => "Integer64".to_string(),
            AvpType::Unsigned64 => "Unsigned64".to_string(),
            AvpType::Float32 => "Float32".to_string(),
            AvpType::Float64 => "Float64".to_string(),
            AvpType::Grouped => "Grouped".to_string(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Avp {
    pub code: u32,
    pub flags: u8,
    pub vendor_id: Option<u32>,
    pub data: Option<Vec<u8>>,
    pub sub_avps: Vec<Self>, // For grouped AVPs, this will be empty for base type AVPs
}

impl Avp {
    pub fn new(code: u32, flags: u8, vendor_id: Option<u32>, data: Vec<u8>) -> Self {
        Avp {
            code,
            flags: flags & 0x7F, // Ensure the vendor-specific flag is not set in the flags field
            vendor_id,
            data: Some(data),
            sub_avps: Vec::new(),
        }
    }

    pub fn from_octet_string(code: u32, flags: u8, vendor_id: Option<u32>, value: &str) -> Self {
        let data = value.as_bytes().to_vec();
        Avp::new(code, flags, vendor_id, data)
    }

    pub fn from_utf8_string(code: u32, flags: u8, vendor_id: Option<u32>, value: &str) -> Self {
        let data = value.as_bytes().to_vec();
        Avp::new(code, flags, vendor_id, data)
    }

    pub fn from_integer32(code: u32, flags: u8, vendor_id: Option<u32>, value: i32) -> Self {
        let data = value.to_be_bytes().to_vec();
        Avp::new(code, flags, vendor_id, data)
    }

    pub fn from_unsigned32(code: u32, flags: u8, vendor_id: Option<u32>, value: u32) -> Self {
        let data = value.to_be_bytes().to_vec();
        Avp::new(code, flags, vendor_id, data)
    }

    pub fn from_float32(code: u32, flags: u8, vendor_id: Option<u32>, value: f32) -> Self {
        let data = value.to_be_bytes().to_vec();
        Avp::new(code, flags, vendor_id, data)
    }

    pub fn from_float64(code: u32, flags: u8, vendor_id: Option<u32>, value: f64) -> Self {
        let data = value.to_be_bytes().to_vec();
        Avp::new(code, flags, vendor_id, data)
    }

    pub fn from_address(code: u32, flags: u8, vendor_id: Option<u32>, address: String) -> Self {
        let mut data = Vec::new();
        if let Ok(ip) = address.parse::<std::net::Ipv4Addr>() {
            data.extend_from_slice(&1u16.to_be_bytes()); // Address type 1 for IPv4
            data.extend_from_slice(&ip.octets());
        } else if let Ok(ip) = address.parse::<std::net::Ipv6Addr>() {
            data.extend_from_slice(&2u16.to_be_bytes()); // Address type 2 for IPv6
            data.extend_from_slice(&ip.octets());
        }
        Avp::new(code, flags, vendor_id, data)
    }

    /**
     * Create an AVP from a time value. The time value is expected to be the number of seconds since the epoch (January 1, 1970). The AVP data will be the big-endian binary representation of this time value. Note that in a real implementation, you might want to handle time values that are larger than what can fit in a 32-bit unsigned integer, but for simplicity we will just use a 32-bit representation here.
     */
    pub fn from_time(code: u32, flags: u8, vendor_id: Option<u32>, time: u32) -> Self {
        let v = 2208988800 as u32 + time; // Convert Unix time to NTP time (seconds since 1900)

        return Avp::from_unsigned32(code, flags, vendor_id, v);
    }

    pub fn from_grouped(code: u32, flags: u8, vendor_id: Option<u32>, sub_avps: Vec<Avp>) -> Self {
        Avp {
            code,
            flags: flags | 0x40, // Set the grouped flag
            vendor_id,
            data: None,
            sub_avps,
        }
    }

    pub fn is_vendor_specific(&self) -> bool {
        self.flags & 0x80 != 0
    }

    pub fn is_grouped(&self) -> bool {
        self.data.is_none() && !self.sub_avps.is_empty()
    }

    pub fn as_integer32(&self) -> Option<i32> {
        if let Some(data) = self.data.as_ref() {
            if data.len() == 4 {
                return Some(i32::from_be_bytes([data[0], data[1], data[2], data[3]]));
            }
        }
        None
    }

    pub fn set_integer32(&mut self, value: i32) {
        self.data = Some(value.to_be_bytes().to_vec());
    }

    pub fn as_unsigned32(&self) -> Option<u32> {
        if let Some(data) = self.data.as_ref() {
            if data.len() == 4 {
                return Some(u32::from_be_bytes([data[0], data[1], data[2], data[3]]));
            }
        }
        None
    }

    pub fn set_unsigned32(&mut self, value: u32) {
        self.data = Some(value.to_be_bytes().to_vec());
    }

    pub fn as_integer64(&self) -> Option<i64> {
        if let Some(data) = self.data.as_ref() {
            if data.len() == 8 {
                return Some(i64::from_be_bytes([
                    data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
                ]));
            }
        }
        None
    }

    pub fn set_integer64(&mut self, value: i64) {
        self.data = Some(value.to_be_bytes().to_vec());
    }
    pub fn as_unsigned64(&self) -> Option<u64> {
        if let Some(data) = self.data.as_ref() {
            if data.len() == 8 {
                return Some(u64::from_be_bytes([
                    data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
                ]));
            }
        }
        None
    }

    pub fn set_unsigned64(&mut self, value: u64) {
        self.data = Some(value.to_be_bytes().to_vec());
    }

    pub fn set_float32(&mut self, value: f32) {
        self.data = Some(value.to_be_bytes().to_vec());
    }

    pub fn set_float64(&mut self, value: f64) {
        self.data = Some(value.to_be_bytes().to_vec());
    }

    pub fn as_float32(&self) -> Option<f32> {
        if let Some(data) = self.data.as_ref() {
            if data.len() == 4 {
                return Some(f32::from_be_bytes([data[0], data[1], data[2], data[3]]));
            }
        }
        None
    }

    pub fn as_float64(&self) -> Option<f64> {
        if let Some(data) = self.data.as_ref() {
            if data.len() == 8 {
                return Some(f64::from_be_bytes([
                    data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
                ]));
            }
        }
        None
    }

    pub fn set_octet_string(&mut self, value: Vec<u8>) {
        self.data = Some(value);
    }

    pub fn as_octet_string(&self) -> Vec<u8> {
        self.data.clone().unwrap_or_else(Vec::new)
    }

    pub fn as_utf8_string(&self) -> Option<String> {
        if let Some(data) = self.data.as_ref() {
            if let Ok(s) = String::from_utf8(data.clone()) {
                return Some(s);
            }
        }
        None
    }

    pub fn as_address(&self) -> Option<String> {
        if let Some(data) = self.data.as_ref() {
            let n = data.len();
            if n < 2 {
                return None; // Not enough data for address
            }
            let address_type = u16::from_be_bytes([data[0], data[1]]) as u16;
            if address_type == 1 && n == 6 {
                // IPv4
                return Some(Ipv4Addr::from([data[2], data[3], data[4], data[5]]).to_string());
            } else if address_type == 2 && n == 18 {
                // IPv6
                return Some(Ipv6Addr::from(<[u8; 16]>::try_from(&data[2..18]).ok()?).to_string());
            }
        }
        None
    }

    /**
     * Convert the AVP data to a time value. The AVP data is expected to be a 4-byte big-endian representation of the number of seconds since the epoch (January 1, 1970). The returned time value will be the number of seconds since the epoch. Note that in a real implementation, you might want to handle time values that are larger than what can fit in a 32-bit unsigned integer, but for simplicity we will just use a 32-bit representation here.
     */
    pub fn as_time(&self) -> Option<u32> {
        if let Some(data) = self.data.as_ref() {
            if data.len() == 4 {
                let ntp_time = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
                return Some(ntp_time - 2208988800); // Convert NTP time back to Unix time
            }
        }
        None
    }
    /**
     * Set the AVP data as a UTF-8 string. This will overwrite any existing data and clear sub AVPs if it's a grouped AVP. The flags will be updated to indicate it's not grouped.
     */
    pub fn set_utf8_string(&mut self, value: &str) {
        self.data = Some(value.as_bytes().to_vec());
    }

    pub fn as_grouped(&self) -> Option<Vec<Avp>> {
        if let Some(data) = self.data.as_ref() {
            if data.len() >= 8 {
                let mut sub_avps = Vec::new();
                let mut offset = 0;
                while offset + 8 <= data.len() {
                    match Avp::decode(&data[offset..]) {
                        Ok(avp) => {
                            let padding = (4 - (avp.total_length() % 4)) % 4; // Calculate padding needed to align to 4 bytes
                            offset += avp.total_length() as usize + padding as usize; // Move offset by AVP length plus padding
                            sub_avps.push(avp);
                        }
                        Err(_e) => return None, // Failed to decode sub AVP
                    }
                }
                return Some(sub_avps);
            }
        }
        if self.is_grouped() {
            return Some(self.sub_avps.clone());
        }
        None
    }

    pub fn set_grouped(&mut self, sub_avps: Vec<Avp>) {
        self.data = None; // Clear data for grouped AVP
        self.sub_avps = sub_avps;
        self.flags |= 0x40; // Set the grouped flag
    }

    // Calculate the total length of the AVP including header and data, accounting for vendor-specific AVPs
    pub fn total_length(&self) -> u32 {
        match self.data.as_ref() {
            Some(data) => 8 + data.len() as u32 + if self.is_vendor_specific() { 4 } else { 0 },
            None => {
                self.sub_avps
                    .iter()
                    .map(|sub_avp| sub_avp.total_length_including_padding())
                    .sum::<u32>()
                    + 8
                    + if self.is_vendor_specific() { 4 } else { 0 }
            }
        }
    }

    fn total_length_including_padding(&self) -> u32 {
        let length = self.total_length();
        let remain = length % 4;
        if remain == 0 {
            length
        } else {
            length + (4 - remain)
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut buffer = Vec::new();
        let length = self.total_length();
        buffer.extend_from_slice(&self.code.to_be_bytes());
        buffer.push(self.flags);
        buffer.extend_from_slice(&length.to_be_bytes()[1..]); // Use only the last 3 bytes for length
        if self.is_vendor_specific() {
            if let Some(vendor_id) = self.vendor_id {
                buffer.extend_from_slice(&vendor_id.to_be_bytes());
            }
        }
        if let Some(data) = self.data.as_ref() {
            buffer.extend_from_slice(data);
        } else {
            for sub_avp in &self.sub_avps {
                let data = sub_avp.encode();
                buffer.extend_from_slice(&data);
                if data.len() % 4 != 0 {
                    buffer.extend_from_slice(&vec![0; 4 - (data.len() % 4)]); // Add padding
                }
            }
        }
        buffer
    }

    fn decode_header(buffer: &[u8]) -> Option<(u32, u8, u32, Option<u32>)> {
        if buffer.len() < 8 {
            return None; // Not enough data for code, flags, and length
        }
        let code = u32::from_be_bytes([buffer[0], buffer[1], buffer[2], buffer[3]]);
        let flags = buffer[4];
        let length = u32::from_be_bytes([0, buffer[5], buffer[6], buffer[7]]); // Length is 3 bytes
        let vendor_id: Option<u32> = if flags & 0x80 != 0 {
            if buffer.len() < 12 {
                return None; // Not enough data for vendor_id
            }
            Some(u32::from_be_bytes([
                buffer[8], buffer[9], buffer[10], buffer[11],
            ]))
        } else {
            None
        };

        let header_length = 8 + if flags & 0x80 != 0 { 4 } else { 0 };
        if length < header_length as u32 {
            return None; // Length is too short to include header
        }
        Some((code, flags, length, vendor_id))
    }

    pub fn decode(data: &[u8]) -> Result<Avp, String> {
        if let Some((code, flags, length, vendor_id)) = Self::decode_header(data) {
            if data.len() < length as usize {
                return Err("Data length mismatch".to_string());
            }
            let header_length = 8 + if flags & 0x80 != 0 { 4 } else { 0 };
            let data_start = header_length as usize;
            let data_end = length as usize;
            let avp_data = data[data_start..data_end].to_vec();
            Ok(Avp::new(code, flags, vendor_id, avp_data))
        } else {
            Err("Failed to decode AVP header".to_string())
        }
    }
}

impl std::fmt::Display for Avp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(data) = self.data.as_ref() {
            write!(
                f,
                "AVP(code: {}, flags: {:02x}, vendor_id: {:?}, data: {:?})",
                self.code, self.flags, self.vendor_id, data
            )
        } else {
            write!(
                f,
                "AVP(code: {}, flags: {:02x}, vendor_id: {:?}, sub_avps: {:?})",
                self.code, self.flags, self.vendor_id, self.sub_avps
            )
        }
    }
}

#[derive(Debug, Clone)]
pub struct AvpJson {
    pub name: String,
    pub code: u32,
    pub avp_type: AvpType,
    pub mandatory: bool,
    pub vendor_id: Option<u32>,
}

impl AvpJson {
    pub fn new(
        name: String,
        code: u32,
        avp_type: AvpType,
        mandatory: bool,
        vendor_id: Option<u32>,
    ) -> Self {
        AvpJson {
            name,
            code,
            avp_type,
            mandatory,
            vendor_id: vendor_id,
        }
    }
}

lazy_static::lazy_static! {
    pub static ref STANDARD_AVP_JSON: Vec<AvpJson> = vec![
        AvpJson::new("Acct-Interim-Interval".to_string(), AvpCode::AcctInterimInterval as u32, AvpType::Unsigned32, true, None),
        AvpJson::new("Accounting-Realtime-Required".to_string(), AvpCode::AccountingRealtimeRequired as u32, AvpType::Enumerated, true, None),
        AvpJson::new("Acct-Multi-Session-Id".to_string(), AvpCode::AcctMultiSessionId as u32, AvpType::UTF8String, true, None),
        AvpJson::new("Accounting-Record-Number".to_string(), AvpCode::AccountingRecordNumber as u32, AvpType::Unsigned32, true, None),
        AvpJson::new("Accounting-Record-Type".to_string(), AvpCode::AccountingRecordType as u32, AvpType::Enumerated, true, None),
        AvpJson::new("Acct-Session-Id".to_string(), AvpCode::AcctSessionId as u32, AvpType::UTF8String, true, None),
        AvpJson::new("Accounting-Sub-Session-Id".to_string(), AvpCode::AccountingSubSessionId as u32, AvpType::Unsigned64, true, None),
        AvpJson::new("Acct-Application-Id".to_string(), AvpCode::AcctApplicationId as u32, AvpType::Unsigned32, true, None),
        AvpJson::new("Auth-Application-Id".to_string(), AvpCode::AuthApplicationId as u32, AvpType::Unsigned32, true, None),
        AvpJson::new("Auth-Request-Type".to_string(), AvpCode::AuthRequestType as u32, AvpType::Enumerated, true, None),
        AvpJson::new("Authorization-Lifetime".to_string(), AvpCode::AuthorizationLifetime as u32, AvpType::Unsigned32, true, None),
        AvpJson::new("Auth-Grace-Period".to_string(), AvpCode::AuthGracePeriod as u32, AvpType::Unsigned32, true, None),
        AvpJson::new("Auth-Session-State".to_string(), AvpCode::AuthSessionState as u32, AvpType::Enumerated, true, None),
        AvpJson::new("Re-Auth-Request-Type".to_string(), AvpCode::ReAuthRequestType as u32, AvpType::Enumerated, true, None),
        AvpJson::new("Class".to_string(), AvpCode::Class as u32, AvpType::OctetString, false, None),
        AvpJson::new("Destination-Host".to_string(), AvpCode::DestinationHost as u32, AvpType::DiameterIdentity, true, None),
        AvpJson::new("Destination-Realm".to_string(), AvpCode::DestinationRealm as u32, AvpType::DiameterIdentity, true, None),
        AvpJson::new("Disconnect-Cause".to_string(), AvpCode::DisconnectCause as u32, AvpType::Enumerated, true, None),
        AvpJson::new("Error-Message".to_string(), AvpCode::ErrorMessage as u32, AvpType::UTF8String, false, None),
        AvpJson::new("Error-Reporting-Host".to_string(), AvpCode::ErrorReportingHost as u32, AvpType::DiameterIdentity, false, None),
        AvpJson::new("Event-Timestamp".to_string(), AvpCode::EventTimestamp as u32, AvpType::Time, true, None),
        AvpJson::new("Experimental-Result".to_string(), AvpCode::ExperimentalResult as u32, AvpType::Grouped, true, None),
        AvpJson::new("Experimental-Result-Code".to_string(), AvpCode::ExperimentalResultCode as u32, AvpType::Unsigned32, true, None),
        AvpJson::new("Failed-AVP".to_string(), AvpCode::FailedAvp as u32, AvpType::Grouped, true, None),
        AvpJson::new("Firmware-Revision".to_string(), AvpCode::FirmwareRevision as u32, AvpType::Unsigned32, false, None),
        AvpJson::new("Host-IP-Address".to_string(), AvpCode::HostIpAddress as u32, AvpType::Address, true, None),
        AvpJson::new("Inband-Security-Id".to_string(), AvpCode::InbandSecurityId as u32, AvpType::Unsigned32, true, None),
        AvpJson::new("Multi-Round-Time-Out".to_string(), AvpCode::MultiRoundTimeOut as u32, AvpType::Unsigned32, true, None),
        AvpJson::new("Origin-Host".to_string(), AvpCode::OriginHost as u32, AvpType::DiameterIdentity, true, None),
        AvpJson::new("Origin-Realm".to_string(), AvpCode::OriginRealm as u32, AvpType::DiameterIdentity, true, None),
        AvpJson::new("Origin-State-Id".to_string(), AvpCode::OriginStateId as u32, AvpType::Unsigned32, true, None),
        AvpJson::new("Product-Name".to_string(), AvpCode::ProductName as u32, AvpType::UTF8String, false, None),
        AvpJson::new("Proxy-Host".to_string(), AvpCode::ProxyHost as u32, AvpType::DiameterIdentity, true, None),
        AvpJson::new("Proxy-Info".to_string(), AvpCode::ProxyInfo as u32, AvpType::Grouped, true, None),
        AvpJson::new("Proxy-State".to_string(), AvpCode::ProxyState as u32, AvpType::OctetString, true, None),
        AvpJson::new("Redirect-Host".to_string(), AvpCode::RedirectHost as u32, AvpType::DiameterIdentity, true, None),
        AvpJson::new("Redirect-Host-Usage".to_string(), AvpCode::RedirectHostUsage as u32, AvpType::Enumerated, true, None),
        AvpJson::new("Redirect-Max-Cache-Time".to_string(), AvpCode::RedirectMaxCacheTime as u32, AvpType::Unsigned32, true, None),
        AvpJson::new("Result-Code".to_string(), AvpCode::ResultCode as u32, AvpType::Unsigned32, true, None),
        AvpJson::new("Route-Record".to_string(), AvpCode::RouteRecord as u32, AvpType::DiameterIdentity, true, None),
        AvpJson::new("Session-Id".to_string(), AvpCode::SessionId as u32, AvpType::UTF8String, true, None),
        AvpJson::new("Session-Timeout".to_string(), AvpCode::SessionTimeout as u32, AvpType::Unsigned32, true, None),
        AvpJson::new("Session-Binding".to_string(), AvpCode::SessionBinding as u32, AvpType::Unsigned32, true, None),
        AvpJson::new("Session-Server-Failover".to_string(), AvpCode::SessionServerFailover as u32, AvpType::Enumerated, true, None),
        AvpJson::new("Supported-Vendor-Id".to_string(), AvpCode::SupportedVendorId as u32, AvpType::Unsigned32, true, None),
        AvpJson::new("Termination-Cause".to_string(), AvpCode::TerminationCause as u32, AvpType::Enumerated, true, None),
        AvpJson::new("User-Name".to_string(), AvpCode::UserName as u32, AvpType::UTF8String, true, None),
        AvpJson::new("Vendor-Id".to_string(), AvpCode::VendorId as u32, AvpType::Unsigned32, true, None),
        AvpJson::new("Vendor-Specific-Application-Id".to_string(), AvpCode::VendorSpecificApplicationId as u32, AvpType::Grouped, true, None),
    ];

    pub static ref STANDARD_AVP_MAP: AvpMap = AvpMap::new(STANDARD_AVP_JSON.clone());
}

#[derive(Debug, Clone)]
pub struct AvpMap {
    code_to_avp: HashMap<u32, AvpJson>,
    name_to_avp: HashMap<String, AvpJson>,
}

impl AvpMap {
    pub fn new(avps: Vec<AvpJson>) -> Self {
        let mut code_to_avp = HashMap::new();
        let mut name_to_avp = HashMap::new();

        for avp in STANDARD_AVP_JSON.iter() {
            code_to_avp.insert(avp.code, avp.clone());
            name_to_avp.insert(avp.name.clone(), avp.clone());
        }
        for avp in avps {
            code_to_avp.insert(avp.code, avp.clone());
            name_to_avp.insert(avp.name.clone(), avp);
        }
        AvpMap {
            code_to_avp,
            name_to_avp,
        }
    }

    pub fn get_by_code(&self, code: u32) -> Option<&AvpJson> {
        self.code_to_avp.get(&code)
    }

    pub fn get_by_name(&self, name: &str) -> Option<&AvpJson> {
        self.name_to_avp.get(name)
    }
}

pub fn load_avp_definition_from_yaml_files(filenames: Vec<String>) -> Result<Vec<AvpJson>, String> {
    let mut avps = Vec::new();
    for filename in filenames {
        let mut file_avps = load_avp_definition_from_yaml_file(&filename)?;
        avps.append(&mut file_avps);
    }
    Ok(avps)
}

pub fn load_avp_definition_from_yaml_file(filename: &str) -> Result<Vec<AvpJson>, String> {
    let md = std::fs::metadata(filename);
    if md.is_err() || !md.unwrap().is_file() {
        return Err(format!("File not found: {}", filename));
    }
    let contents =
        std::fs::read_to_string(filename).map_err(|e| format!("Failed to read file: {}", e))?;
    let yaml: serde_yaml::Value =
        serde_yaml::from_str(&contents).map_err(|e| format!("Failed to parse YAML: {}", e))?;

    return load_avp_definition_from_yaml(&yaml);
}

pub fn load_avp_definition_from_yaml(yaml: &serde_yaml::Value) -> Result<Vec<AvpJson>, String> {
    if !yaml.is_mapping() {
        return Err("Invalid YAML structure".to_string());
    }
    let Some(yaml) = yaml.as_mapping().unwrap().get("avps") else {
        return Err("Missing 'avps' key in YAML".to_string());
    };

    if !yaml.is_sequence() {
        return Err("Invalid YAML structure: 'avps' should be a sequence".to_string());
    }

    let mut avps = Vec::new();

    if let Some(avp_list) = yaml.as_sequence() {
        for avp in avp_list {
            if let (Some(name), Some(code), Some(avp_type), Some(mandatory)) = (
                avp.get("name").and_then(|v| v.as_str()),
                avp.get("code").and_then(|v| v.as_u64()),
                avp.get("type").and_then(|v| v.as_str()),
                avp.get("mandatory").and_then(|v| v.as_bool()),
            ) {
                let vendor_id = avp
                    .get("vendor_id")
                    .and_then(|v| v.as_u64())
                    .map(|v| v as u32);
                avps.push(AvpJson::new(
                    name.to_string(),
                    code as u32,
                    AvpType::from(avp_type.to_string()),
                    mandatory,
                    vendor_id,
                ));
            }
        }
    }
    Ok(avps)
}

pub fn avp_to_name_value(avp: &Avp, avp_map: &AvpMap) -> Result<(String, Value), ()> {
    if let Some(named_avp) = avp_map.get_by_code(avp.code) {
        match named_avp.avp_type {
            AvpType::OctetString => {
                if let Ok(value) = String::from_utf8(avp.data.clone().unwrap()) {
                    return Ok((named_avp.name.clone(), value.into()));
                }
            }
            AvpType::Address => {
                if let Some(value) = avp.as_address() {
                    return Ok((named_avp.name.clone(), value.into()));
                }
            }

            AvpType::Time => {
                if let Some(value) = avp.as_time() {
                    return Ok((named_avp.name.clone(), value.into()));
                }
            }
            AvpType::UTF8String
            | AvpType::DiameterIdentity
            | AvpType::DiameterURI
            | AvpType::IPFilterRule => {
                if let Ok(value) = String::from_utf8(avp.data.clone().unwrap()) {
                    return Ok((named_avp.name.clone(), value.into()));
                }
            }
            AvpType::Integer32 | AvpType::Enumerated => {
                return Ok((named_avp.name.clone(), avp.as_integer32().into()));
            }
            AvpType::Unsigned32 => {
                return Ok((named_avp.name.clone(), avp.as_unsigned32().into()));
            }
            AvpType::Integer64 => {
                return Ok((named_avp.name.clone(), avp.as_integer64().into()));
            }
            AvpType::Unsigned64 => {
                return Ok((named_avp.name.clone(), avp.as_unsigned64().into()));
            }
            AvpType::Float32 => {
                return Ok((named_avp.name.clone(), avp.as_float32().into()));
            }
            AvpType::Float64 => {
                return Ok((named_avp.name.clone(), avp.as_float64().into()));
            }
            AvpType::Grouped => {
                match avp.as_grouped() {
                    Some(grouped_avp) => {
                        let mut sub_avps_json = Map::new();
                        for sub_avp in &grouped_avp {
                            if let Ok((sub_name, sub_value)) = avp_to_name_value(sub_avp, avp_map) {
                                sub_avps_json.insert(sub_name, sub_value);
                            }
                        }
                        return Ok((named_avp.name.clone(), Value::Object(sub_avps_json)));
                    }
                    None => return Err(()), // Invalid Grouped AVP
                };
            }
        }
    } else {
        info!(
            "Unknown AVP code: {}, using generic name and base64-encoded value",
            avp.code
        );
        return Ok((
            format!("AVP-{}", avp.code),
            Value::String(BASE64_STANDARD.encode(avp.data.clone().unwrap())),
        ));
    }
    Err(())
}

// Convert a name-value pair to an AVP using the AVP map for lookup
pub fn name_value_to_avp(name: &str, value: &Value, avp_map: &AvpMap) -> Result<Avp, ()> {
    if let Some(named_avp) = avp_map.get_by_name(name) {
        let flags = if named_avp.mandatory { 0x40 } else { 0x00 };
        match named_avp.avp_type {
            AvpType::OctetString => {
                if let Value::String(s) = value {
                    return Ok(Avp::new(
                        named_avp.code,
                        flags, // Set mandatory flag
                        named_avp.vendor_id,
                        BASE64_STANDARD
                            .decode(s)
                            .unwrap_or_else(|_| s.as_bytes().to_vec()),
                    ));
                }
                return Err(()); // Value type mismatch
            }
            AvpType::Address => {
                if let Value::String(s) = value {
                    return Ok(Avp::from_address(
                        named_avp.code,
                        flags,
                        named_avp.vendor_id,
                        s.clone(),
                    ));
                }
                return Err(()); // Value type mismatch
            }
            AvpType::Time => {
                if let Value::Number(num) = value {
                    if let Some(u) = num.as_u64() {
                        return Ok(Avp::from_time(
                            named_avp.code,
                            flags,
                            named_avp.vendor_id,
                            u as u32,
                        ));
                    }
                }
                return Err(()); // Value type mismatch
            }
            AvpType::Integer32 | AvpType::Enumerated => {
                if let Value::Number(num) = value {
                    if let Some(i) = num.as_i64() {
                        return Ok(Avp::new(
                            named_avp.code,
                            flags, // Set mandatory flag
                            named_avp.vendor_id,
                            (i as i32).to_be_bytes().to_vec(),
                        ));
                    }
                }
                return Err(()); // Value type mismatch
            }
            AvpType::Unsigned32 => {
                if let Value::Number(num) = value {
                    if let Some(u) = num.as_u64() {
                        return Ok(Avp::new(
                            named_avp.code,
                            flags, // Set mandatory flag
                            named_avp.vendor_id,
                            (u as u32).to_be_bytes().to_vec(),
                        ));
                    }
                }
                return Err(()); // Value type mismatch
            }
            AvpType::Integer64 => {
                if let Value::Number(num) = value {
                    if let Some(i) = num.as_i64() {
                        return Ok(Avp::new(
                            named_avp.code,
                            flags, // Set mandatory flag
                            named_avp.vendor_id,
                            i.to_be_bytes().to_vec(),
                        ));
                    }
                }
                return Err(()); // Value type mismatch
            }

            AvpType::Unsigned64 => {
                if let Value::Number(num) = value {
                    if let Some(u) = num.as_u64() {
                        return Ok(Avp::new(
                            named_avp.code,
                            flags, // Set mandatory flag
                            named_avp.vendor_id,
                            u.to_be_bytes().to_vec(),
                        ));
                    }
                }
                return Err(()); // Value type mismatch
            }
            AvpType::Float32 => {
                if let Value::Number(num) = value {
                    if let Some(f) = num.as_f64() {
                        return Ok(Avp::new(
                            named_avp.code,
                            flags, // Set mandatory flag
                            named_avp.vendor_id,
                            (f as f32).to_be_bytes().to_vec(),
                        ));
                    }
                }
                return Err(()); // Value type mismatch
            }

            AvpType::Float64 => {
                if let Value::Number(num) = value {
                    if let Some(f) = num.as_f64() {
                        return Ok(Avp::new(
                            named_avp.code,
                            flags, // Set mandatory flag
                            named_avp.vendor_id,
                            f.to_be_bytes().to_vec(),
                        ));
                    }
                }
                return Err(()); // Value type mismatch
            }

            AvpType::UTF8String
            | AvpType::DiameterIdentity
            | AvpType::DiameterURI
            | AvpType::IPFilterRule => {
                if let Value::String(s) = value {
                    return Ok(Avp::new(
                        named_avp.code,
                        flags, // Set mandatory flag
                        named_avp.vendor_id,
                        s.as_bytes().to_vec(),
                    ));
                }
                return Err(()); // Value type mismatch
            }
            AvpType::Grouped => {
                match value.as_object() {
                    Some(obj) => {
                        let mut sub_avps = Vec::new();
                        for (sub_name, sub_value) in obj {
                            match name_value_to_avp(sub_name, sub_value, avp_map) {
                                Ok(avp) => sub_avps.push(avp),
                                Err(_) => return Err(()), // Failed to convert sub AVP
                            }
                        }
                        return Ok(Avp::from_grouped(
                            named_avp.code,
                            flags, // Set mandatory flag
                            named_avp.vendor_id,
                            sub_avps,
                        ));
                    }
                    None => return Err(()), // Value type mismatch
                }
            }
        }
    } else if name.starts_with("AVP-") {
        if let Some(code_str) = name.strip_prefix("AVP-") {
            if let Ok(code) = code_str.parse::<u32>() {
                if let Value::String(s) = value {
                    return Ok(Avp::new(
                        code,
                        0x00, // No flags set for unknown AVP
                        None, // No vendor ID for unknown AVP
                        BASE64_STANDARD
                            .decode(s)
                            .unwrap_or_else(|_| s.as_bytes().to_vec())
                            .to_vec(),
                    ));
                }
            }
        }
    }
    Err(())
}
