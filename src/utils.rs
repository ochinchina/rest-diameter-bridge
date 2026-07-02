use std::sync::Arc;

use crate::avp::{Avp, AvpCode, AvpFlags, AvpMap, name_value_to_avp};
use crate::config::StackCapability;

use serde_json::Value;

pub fn is_empty_file(path: &str) -> bool {
    std::fs::metadata(path)
        .map(|m| m.len() == 0)
        .unwrap_or(true)
}

pub fn is_non_empty_file(path: &str) -> bool {
    std::fs::metadata(path)
        .map(|m| m.len() > 0)
        .unwrap_or(false)
}

pub fn creat_capability_avps(capability: &StackCapability, avp_map: &AvpMap) -> Vec<Avp> {
    let mut avps = Vec::new();
    for host_ip in capability.host_ips.clone().unwrap_or_default() {
        let avp = Avp::from_utf8_string(
            avp_map.get_by_name("Host-IP-Address").unwrap().code,
            0,
            None,
            &host_ip,
        );
        avps.push(avp);
    }

    avps.extend(vec![
        Avp::from_unsigned32(
            AvpCode::VendorId as u32,
            AvpFlags::Mandatory as u8,
            None,
            capability.vendor_id,
        ),
        name_value_to_avp(
            "Vendor-Id",
            &Value::Number(capability.vendor_id.into()),
            avp_map,
        )
        .unwrap(),
        name_value_to_avp(
            "Product-Name",
            &Value::String(capability.product_name.clone()),
            avp_map,
        )
        .unwrap(),
    ]);
    if capability.supported_vendor_ids.is_some() {
        capability
            .supported_vendor_ids
            .clone()
            .unwrap_or_default()
            .into_iter()
            .for_each(|id| {
                avps.push(
                    name_value_to_avp("Supported-Vendor-Id", &Value::Number(id.into()), avp_map)
                        .unwrap(),
                );
            });
    }
    if capability.auth_application_ids.is_some() {
        capability
            .auth_application_ids
            .clone()
            .unwrap_or_default()
            .into_iter()
            .for_each(|id| {
                avps.push(
                    name_value_to_avp("Auth-Application-Id", &Value::Number(id.into()), avp_map)
                        .unwrap(),
                );
            });
    }

    if capability.inband_security_ids.is_some() {
        capability
            .inband_security_ids
            .clone()
            .unwrap_or_default()
            .into_iter()
            .for_each(|id| {
                avps.push(
                    name_value_to_avp("Inband-Security-Id", &Value::Number(id.into()), avp_map)
                        .unwrap(),
                );
            });
    }
    if capability.acct_application_ids.is_some() {
        capability
            .acct_application_ids
            .clone()
            .unwrap_or_default()
            .into_iter()
            .for_each(|id| {
                avps.push(
                    name_value_to_avp("Acct-Application-Id", &Value::Number(id.into()), avp_map)
                        .unwrap(),
                );
            });
    }
    if capability.vendor_specific_application_ids.is_some() {
        capability
            .vendor_specific_application_ids
            .clone()
            .unwrap_or_default()
            .into_iter()
            .for_each(|vsa| {
                let mut sub_avps = vec![
                    name_value_to_avp("Vendor-Id", &Value::Number(vsa.vendor_id.into()), avp_map)
                        .unwrap(),
                ];
                if let Some(auth_app_id) = vsa.auth_application_id {
                    sub_avps.push(
                        name_value_to_avp(
                            "Auth-Application-Id",
                            &Value::Number(auth_app_id.into()),
                            avp_map,
                        )
                        .unwrap(),
                    );
                }
                if let Some(acct_app_id) = vsa.acct_application_id {
                    sub_avps.push(
                        name_value_to_avp(
                            "Acct-Application-Id",
                            &Value::Number(acct_app_id.into()),
                            avp_map,
                        )
                        .unwrap(),
                    );
                }
                avps.push(Avp::from_grouped(
                    avp_map
                        .get_by_name("Vendor-Specific-Application-Id")
                        .unwrap()
                        .code,
                    0,
                    None,
                    sub_avps,
                ));
            });
    }
    if capability.firmware_revision.is_some() {
        avps.push(
            name_value_to_avp(
                "Firmware-Revision",
                &Value::Number(capability.firmware_revision.unwrap().into()),
                avp_map,
            )
            .unwrap(),
        );
    }
    avps
}

pub fn load_rustls_config(
    cert_path: &str,
    key_path: &str,
    ca_cert_path: &str,
) -> Result<Arc<rustls::ServerConfig>, String> {
    use std::fs::File;
    use std::io::BufReader;

    if is_empty_file(cert_path) || is_empty_file(key_path) {
        return Err("Certificate file and key file must be provided for HTTPS".to_string());
    }
    let cert_file = File::open(cert_path)
        .map_err(|e| format!("Failed to open cert file '{}': {}", cert_path, e))?;
    let key_file = File::open(key_path)
        .map_err(|e| format!("Failed to open key file '{}': {}", key_path, e))?;

    let certs: Vec<_> = rustls_pemfile::certs(&mut BufReader::new(cert_file))
        .filter_map(|r| r.ok())
        .collect();
    let key = rustls_pemfile::private_key(&mut BufReader::new(key_file))
        .map_err(|e| format!("Failed to read private key: {}", e))?
        .ok_or_else(|| "No private key found in key file".to_string())?;

    let config = if !is_empty_file(ca_cert_path) {
        // mTLS: require client certificates verified against the CA
        let ca_file = File::open(ca_cert_path)
            .map_err(|e| format!("Failed to open CA cert file '{}': {}", ca_cert_path, e))?;
        let ca_certs: Vec<_> = rustls_pemfile::certs(&mut BufReader::new(ca_file))
            .filter_map(|r| r.ok())
            .collect();

        let mut root_store = rustls::RootCertStore::empty();
        for cert in ca_certs {
            root_store
                .add(cert)
                .map_err(|e| format!("Failed to add CA cert to root store: {}", e))?;
        }

        let client_verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(root_store))
            .build()
            .map_err(|e| format!("Failed to build client verifier: {}", e))?;

        rustls::ServerConfig::builder()
            .with_client_cert_verifier(client_verifier)
            .with_single_cert(certs, key)
            .map_err(|e| format!("Failed to build mTLS config: {}", e))?
    } else {
        // Standard TLS without client authentication
        rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(|e| format!("Failed to build TLS config: {}", e))?
    };

    Ok(Arc::new(config))
}
