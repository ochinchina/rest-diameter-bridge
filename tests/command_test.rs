use rest_diameter_bridge::avp::{Avp, AvpFlags, AvpJson, AvpMap, AvpType};
use rest_diameter_bridge::command::{
    Command, CommandJson, CommandMap, create_command_from_json_str, create_json_from_command,
    load_command_definition_from_yaml_file,
};
use std::collections::HashMap;

#[test]
fn test_create_command_from_json() {
    let mut avp_map = Vec::new();
    avp_map.push(AvpJson::new(
        "Test-AVP".to_string(),
        1,
        AvpType::Integer32,
        true,
        None,
    ));

    let json = r#"
    {
        "name": "Test-Command-Request",
        "request": true,
        "proxiable": false,
        "error": false,
        "application_id": 456,
        "Test-AVP": 1
    }
    "#;

    let mut commands: Vec<CommandJson> = vec![]; // Empty command list for this test
    commands.push(CommandJson::new(
        "Test-Command-Request".to_string(),
        "TCR".to_string(),
        123,
        456,
        true,
        false,
        false,
        vec!["Test-AVP".to_string()],
    ));

    let avp_map = AvpMap::new(avp_map);
    let command_map = CommandMap::new(commands); // Use the commands vector for this test
    let command = create_command_from_json_str(json, &command_map, &avp_map).unwrap();
    print!("Created Command: {}\n", command);
    assert_eq!(command.code, 123);
    assert_eq!(command.flags, 0x80); // Request flag set
    assert_eq!(command.application_id, 456);
    assert_eq!(command.avps.len(), 1);
}

#[test]
fn test_create_json_from_command() {
    let mut avp_map = Vec::new();
    avp_map.push(AvpJson::new(
        "Test-AVP".to_string(),
        1,
        AvpType::Integer32,
        true,
        None,
    ));

    let avp_map = AvpMap::new(avp_map);

    let avp = rest_diameter_bridge::avp::name_value_to_avp(
        "Test-AVP",
        &serde_json::Value::Number(1.into()),
        &avp_map,
    )
    .unwrap();
    let avp2 = rest_diameter_bridge::avp::name_value_to_avp(
        "Test-AVP",
        &serde_json::Value::Number(2.into()),
        &avp_map,
    )
    .unwrap();

    let avp3 = Avp::new(
        10,
        AvpFlags::Mandatory as u8,
        None,
        vec![0x00, 0x00, 0x00, 0x03],
    ); // Another AVP with same code but different value

    let mut code_avp_map = HashMap::new();
    code_avp_map.insert(
        1,
        AvpJson::new("Test-AVP".to_string(), 1, AvpType::Integer32, true, None),
    );

    let mut commands = Vec::new(); // You can populate this if you want to test command name mapping
    commands.push(CommandJson::new(
        "Test-Command-Request".to_string(),
        "TCR".to_string(),
        123,
        456,
        true,
        true,
        false,
        vec!["Test-AVP".to_string()],
    ));

    let command_map = CommandMap::new(commands);
    let command = Command::new(123, 0x80, 456, 1, 1, vec![avp, avp2, avp3]);
    println!("command: {}", command);
    let json = create_json_from_command(&command, &command_map, &avp_map);
    println!("Generated JSON: {}", json);
}

#[test]
fn test_load_command_definition_from_yaml() {
    use std::io::Write;

    let yaml_content = r#"
commands:
  - long-name: "Test-Request"
    short-name: "TR"
    code: 100
    request: true
    proxiable: true
    error: false
    application-id: 1000
    avps:
      - "Origin-Host"
      - "Origin-Realm"
  - long-name: "Test-Answer"
    short-name: "TA"
    code: 100
    request: false
    proxiable: true
    error: false
    application-id: 1000
    avps:
      - "Result-Code"
      - "Origin-Host"
      - "Origin-Realm"
"#;

    let mut tmp_file = tempfile::NamedTempFile::new().unwrap();
    tmp_file.write_all(yaml_content.as_bytes()).unwrap();
    let path = tmp_file.path().to_str().unwrap().to_string();

    let commands = load_command_definition_from_yaml_file(&path).unwrap();
    assert_eq!(commands.len(), 2);

    assert_eq!(commands[0].long_name, "Test-Request");
    assert_eq!(commands[0].short_name, "TR");
    assert_eq!(commands[0].code, 100);
    assert!(commands[0].request);
    assert!(commands[0].proxiable);
    assert!(!commands[0].error);
    assert_eq!(commands[0].application_id, 1000);
    assert_eq!(commands[0].avps, vec!["Origin-Host", "Origin-Realm"]);

    assert_eq!(commands[1].long_name, "Test-Answer");
    assert_eq!(commands[1].short_name, "TA");
    assert_eq!(commands[1].code, 100);
    assert!(!commands[1].request);
    assert!(commands[1].proxiable);
    assert!(!commands[1].error);
    assert_eq!(commands[1].application_id, 1000);
    assert_eq!(
        commands[1].avps,
        vec!["Result-Code", "Origin-Host", "Origin-Realm"]
    );
}

#[test]
fn test_load_command_definition_from_yaml_missing_file() {
    let result = load_command_definition_from_yaml_file("/nonexistent/path.yaml");
    assert!(result.is_err());
}

#[test]
fn test_load_command_definition_from_yaml_invalid_format() {
    use std::io::Write;

    let yaml_content = r#"
not_commands:
  - name: "Test"
"#;

    let mut tmp_file = tempfile::NamedTempFile::new().unwrap();
    tmp_file.write_all(yaml_content.as_bytes()).unwrap();
    let path = tmp_file.path().to_str().unwrap().to_string();

    let result = load_command_definition_from_yaml_file(&path);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("Missing 'commands' key"));
}
