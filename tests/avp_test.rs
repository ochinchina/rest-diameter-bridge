use rest_diameter_bridge::avp::{
    Avp, AvpJson, AvpMap, AvpType, avp_to_name_value, load_avp_definition_from_yaml_file,
};
use serde_json::Value;

#[test]
fn test_avp_encoding_decoding() {
    let avp = Avp::new(1, 0x40, None, vec![0x00, 0x00, 0x00, 0x01]);
    let encoded = avp.encode();
    let decoded = Avp::decode(&encoded).unwrap();
    assert_eq!(avp.code, decoded.code);
    assert_eq!(avp.flags, decoded.flags);
    assert_eq!(avp.total_length(), decoded.total_length());
}
#[test]
fn test_avp_to_name_value() {
    let mut avp_map = Vec::new();
    avp_map.push(AvpJson::new(
        "Test-AVP".to_string(),
        1,
        AvpType::Integer32,
        true,
        None,
    ));

    let avp_map = AvpMap::new(avp_map);

    let avp = Avp::new(1, 0x40, None, vec![0x00, 0x00, 0x00, 0x01]);
    let (name, value) = avp_to_name_value(&avp, &avp_map).unwrap();
    println!("Name: {}, Value: {}", name, value);
    assert_eq!(name, "Test-AVP");
    assert_eq!(value, Value::Number(1.into()));
}

#[test]
fn test_avp_to_name_value_unknown() {
    let avp = Avp::new(999, 0x00, None, vec![0x00, 0x00, 0x00, 0x01]);
    let (name, value) = avp_to_name_value(&avp, &AvpMap::new(vec![])).unwrap();
    println!("Name: {}, Value: {}", name, value);
    assert_eq!(name, "AVP-999");
    //assert_eq!(value, Value::String("AQAAAA==".to_string())); // Base64 encoding of the data
}

#[test]
fn test_name_value_to_avp() {
    let mut avp_map = Vec::new();
    avp_map.push(AvpJson::new(
        "Test-AVP".to_string(),
        1,
        AvpType::Integer32,
        true,
        None,
    ));

    let avp_map = AvpMap::new(avp_map);

    let name = "Test-AVP";
    let value = Value::Number(1.into());
    let avp = rest_diameter_bridge::avp::name_value_to_avp(name, &value, &avp_map).unwrap();
    assert_eq!(avp.code, 1);
    assert_eq!(avp.flags, 0x40);
    assert_eq!(avp.total_length(), 8 + 4);
}

#[test]
fn test_load_avp_definition_from_yaml() {
    use std::io::Write;

    let yaml_content = r#"
avps:
  - name: "Origin-Host"
    code: 264
    type: "DiameterIdentity"
    mandatory: true
  - name: "Origin-Realm"
    code: 296
    type: "DiameterIdentity"
    mandatory: true
    vendor_id: 10415
  - name: "Session-Id"
    code: 263
    type: "UTF8String"
    mandatory: false
"#;

    let mut tmp_file = tempfile::NamedTempFile::new().unwrap();
    tmp_file.write_all(yaml_content.as_bytes()).unwrap();
    let path = tmp_file.path().to_str().unwrap().to_string();

    let avps = load_avp_definition_from_yaml_file(&path).unwrap();
    assert_eq!(avps.len(), 3);

    assert_eq!(avps[0].name, "Origin-Host");
    assert_eq!(avps[0].code, 264);
    assert_eq!(avps[0].avp_type, AvpType::DiameterIdentity);
    assert!(avps[0].mandatory);
    assert_eq!(avps[0].vendor_id, None);

    assert_eq!(avps[1].name, "Origin-Realm");
    assert_eq!(avps[1].code, 296);
    assert_eq!(avps[1].avp_type, AvpType::DiameterIdentity);
    assert!(avps[1].mandatory);
    assert_eq!(avps[1].vendor_id, Some(10415));

    assert_eq!(avps[2].name, "Session-Id");
    assert_eq!(avps[2].code, 263);
    assert_eq!(avps[2].avp_type, AvpType::UTF8String);
    assert!(!avps[2].mandatory);
    assert_eq!(avps[2].vendor_id, None);
}

#[test]
fn test_load_avp_definition_from_yaml_invalid_structure() {
    use std::io::Write;

    let yaml_content = r#"
not_avps:
  - name: "Test"
"#;

    let mut tmp_file = tempfile::NamedTempFile::new().unwrap();
    tmp_file.write_all(yaml_content.as_bytes()).unwrap();
    let path = tmp_file.path().to_str().unwrap().to_string();

    let result = load_avp_definition_from_yaml_file(&path);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("Missing 'avps' key"));
}
