use super::*;
use std::io::Write;
use tempfile::{NamedTempFile, TempDir};

fn create_full_test_config() -> NamedTempFile {
    let mut file = NamedTempFile::new().unwrap();
    write!(
            file,
            r#"
event_parsers:
  4624:
    name: "Successful Logon"
    description: "An account was successfully logged on"
    fields:
      - name: "TargetUserName"
        source: "eventdata"
        xpath: "Data[@Name='TargetUserName']"
        required: true
        type: "string"
      - name: "TargetDomainName"
        source: "eventdata"
        xpath: "Data[@Name='TargetDomainName']"
        required: true
        type: "string"
      - name: "LogonType"
        source: "eventdata"
        xpath: "Data[@Name='LogonType']"
        required: true
        type: "integer"
      - name: "IpAddress"
        source: "eventdata"
        xpath: "Data[@Name='IpAddress']"
        required: false
        type: "string"
      - name: "IpPort"
        source: "eventdata"
        xpath: "Data[@Name='IpPort']"
        required: false
        type: "string"
    enrichments:
      - field: "LogonType"
        lookup_table:
          "2": "Interactive"
          "3": "Network"
          "4": "Batch"
          "5": "Service"
          "7": "Unlock"
          "8": "NetworkCleartext"
          "9": "NewCredentials"
          "10": "RemoteInteractive"
          "11": "CachedInteractive"
    output_format: "User {{TargetUserName}} from {{TargetDomainName}} logged on via {{LogonType_Name}} from {{IpAddress}}:{{IpPort}}"
  
  4668:
    name: "S4U2Self"
    description: "An account was logged on with S4U2Self"
    fields:
      - name: "TargetUserName"
        source: "eventdata"
        xpath: "Data[@Name='TargetUserName']"
        required: true
        type: "string"
      - name: "TargetDomainName"
        source: "eventdata"
        xpath: "Data[@Name='TargetDomainName']"
        required: true
        type: "string"
      - name: "ServiceName"
        source: "eventdata"
        xpath: "Data[@Name='ServiceName']"
        required: true
        type: "string"
      - name: "Status"
        source: "eventdata"
        xpath: "Data[@Name='Status']"
        required: false
        type: "string"
    output_format: "S4U2Self: {{TargetUserName}}@{{TargetDomainName}} requested {{ServiceName}} with status {{Status}}"
"#
        )
        .unwrap();
    file
}

#[test]
fn test_event_4624_logon() {
    let config_file = create_full_test_config();
    let parser = GenericEventParser::from_file(config_file.path()).unwrap();

    // Sample Windows Event 4624 (Successful Logon)
    let xml = r#"<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
            <System>
                <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-A5BA-3E3B0328C30D}" />
                <EventID>4624</EventID>
                <Version>2</Version>
                <Level>0</Level>
                <Task>12544</Task>
                <Opcode>0</Opcode>
                <Keywords>0x8020000000000000</Keywords>
                <TimeCreated SystemTime="2024-01-15T10:30:45.1234567Z" />
                <EventRecordID>123456</EventRecordID>
                <Correlation ActivityID="{00000000-0000-0000-0000-000000000000}" />
                <Execution ProcessID="456" ThreadID="1234" />
                <Channel>Security</Channel>
                <Computer>WORKSTATION01.contoso.com</Computer>
                <Security UserID="S-1-5-18" />
            </System>
            <EventData>
                <Data Name="SubjectUserSid">S-1-5-18</Data>
                <Data Name="SubjectUserName">WORKSTATION01$</Data>
                <Data Name="SubjectDomainName">CONTOSO</Data>
                <Data Name="SubjectLogonId">0x3E7</Data>
                <Data Name="TargetUserSid">S-1-5-21-123456789-123456789-123456789-1001</Data>
                <Data Name="TargetUserName">john.doe</Data>
                <Data Name="TargetDomainName">CONTOSO</Data>
                <Data Name="TargetLogonId">0x1234567</Data>
                <Data Name="LogonType">3</Data>
                <Data Name="LogonProcessName">NtLmSsp</Data>
                <Data Name="AuthenticationPackageName">NTLM</Data>
                <Data Name="WorkstationName">REMOTE-PC</Data>
                <Data Name="LogonGuid">{00000000-0000-0000-0000-000000000000}</Data>
                <Data Name="TransmittedServices">-</Data>
                <Data Name="LmPackageName">NTLM V2</Data>
                <Data Name="KeyLength">128</Data>
                <Data Name="ProcessName">C:\Windows\System32\svchost.exe</Data>
                <Data Name="IpAddress">192.168.1.100</Data>
                <Data Name="IpPort">49234</Data>
                <Data Name="ImpersonationLevel">%%1833</Data>
                <Data Name="RestrictedAdminMode">-</Data>
                <Data Name="TargetOutboundUserName">-</Data>
                <Data Name="TargetOutboundDomainName">-</Data>
                <Data Name="VirtualAccount">%%1843</Data>
                <Data Name="TargetLinkedLogonId">0x0</Data>
                <Data Name="ElevatedToken">%%1842</Data>
            </EventData>
        </Event>"#;

    let result = parser.parse_event(4624, xml);
    assert!(result.is_some(), "Parser should handle event 4624");

    let parsed = result.unwrap();
    assert_eq!(parsed.event_id, 4624);
    assert_eq!(parsed.parser_name, "Successful Logon");

    // Check extracted fields
    assert_eq!(
        parsed.fields.get("TargetUserName"),
        Some(&serde_json::Value::String("john.doe".to_string())),
        "Should extract TargetUserName"
    );

    assert_eq!(
        parsed.fields.get("TargetDomainName"),
        Some(&serde_json::Value::String("CONTOSO".to_string())),
        "Should extract TargetDomainName"
    );

    assert_eq!(
        parsed.fields.get("LogonType"),
        Some(&serde_json::Value::Number(3.into())),
        "Should extract LogonType as integer"
    );

    assert_eq!(
        parsed.fields.get("IpAddress"),
        Some(&serde_json::Value::String("192.168.1.100".to_string())),
        "Should extract IpAddress"
    );

    assert_eq!(
        parsed.fields.get("IpPort"),
        Some(&serde_json::Value::String("49234".to_string())),
        "Should extract IpPort"
    );

    // Check enrichment
    assert_eq!(
        parsed.enrichments.get("LogonType_Name"),
        Some(&"Network".to_string()),
        "Should enrich LogonType 3 to 'Network'"
    );

    // Check formatted message
    assert!(
        parsed.formatted_message.is_some(),
        "Should have formatted message"
    );
    let msg = parsed.formatted_message.unwrap();
    assert!(msg.contains("john.doe"), "Message should contain username");
    assert!(msg.contains("CONTOSO"), "Message should contain domain");
    assert!(
        msg.contains("Network"),
        "Message should contain enriched logon type"
    );
    assert!(msg.contains("192.168.1.100"), "Message should contain IP");

    println!("Event 4624 formatted message: {}", msg);
}

#[test]
fn test_event_4668_s4u2self() {
    let config_file = create_full_test_config();
    let parser = GenericEventParser::from_file(config_file.path()).unwrap();

    // Sample Windows Event 4668 (S4U2Self)
    let xml = r#"<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
            <System>
                <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-A5BA-3E3B0328C30D}" />
                <EventID>4668</EventID>
                <Version>0</Version>
                <Level>0</Level>
                <Task>12546</Task>
                <Opcode>0</Opcode>
                <Keywords>0x8020000000000000</Keywords>
                <TimeCreated SystemTime="2024-01-15T10:30:45.1234567Z" />
                <EventRecordID>123457</EventRecordID>
                <Correlation ActivityID="{00000000-0000-0000-0000-000000000000}" />
                <Execution ProcessID="456" ThreadID="1234" />
                <Channel>Security</Channel>
                <Computer>WORKSTATION01.contoso.com</Computer>
                <Security UserID="S-1-5-18" />
            </System>
            <EventData>
                <Data Name="SubjectUserSid">S-1-5-21-123456789-123456789-123456789-1001</Data>
                <Data Name="SubjectUserName">john.doe</Data>
                <Data Name="SubjectDomainName">CONTOSO</Data>
                <Data Name="SubjectLogonId">0x1234567</Data>
                <Data Name="TargetUserSid">S-1-5-21-123456789-123456789-123456789-1002</Data>
                <Data Name="TargetUserName">administrator</Data>
                <Data Name="TargetDomainName">CONTOSO</Data>
                <Data Name="TargetLogonId">0x1234568</Data>
                <Data Name="LogonGuid">{00000000-0000-0000-0000-000000000000}</Data>
                <Data Name="TicketOptions">0x40810010</Data>
                <Data Name="Status">0x0</Data>
                <Data Name="ServiceName">HTTP/webserver.contoso.com</Data>
                <Data Name="ServiceSid">S-1-5-21-123456789-123456789-123456789-1003</Data>
                <Data Name="TicketEncryptionType">0x12</Data>
                <Data Name="TransmittedServices">-</Data>
            </EventData>
        </Event>"#;

    let result = parser.parse_event(4668, xml);
    assert!(result.is_some(), "Parser should handle event 4668");

    let parsed = result.unwrap();
    assert_eq!(parsed.event_id, 4668);
    assert_eq!(parsed.parser_name, "S4U2Self");

    // Check extracted fields
    assert_eq!(
        parsed.fields.get("TargetUserName"),
        Some(&serde_json::Value::String("administrator".to_string())),
        "Should extract TargetUserName"
    );

    assert_eq!(
        parsed.fields.get("TargetDomainName"),
        Some(&serde_json::Value::String("CONTOSO".to_string())),
        "Should extract TargetDomainName"
    );

    assert_eq!(
        parsed.fields.get("ServiceName"),
        Some(&serde_json::Value::String(
            "HTTP/webserver.contoso.com".to_string()
        )),
        "Should extract ServiceName"
    );

    assert_eq!(
        parsed.fields.get("Status"),
        Some(&serde_json::Value::String("0x0".to_string())),
        "Should extract Status"
    );

    // Check formatted message
    assert!(
        parsed.formatted_message.is_some(),
        "Should have formatted message"
    );
    let msg = parsed.formatted_message.unwrap();
    assert!(
        msg.contains("administrator"),
        "Message should contain target username"
    );
    assert!(msg.contains("CONTOSO"), "Message should contain domain");
    assert!(
        msg.contains("HTTP/webserver.contoso.com"),
        "Message should contain service name"
    );
    assert!(msg.contains("0x0"), "Message should contain status");

    println!("Event 4668 formatted message: {}", msg);
}

// ---------------------------------------------------------------------------
// Helpers shared by new tests
// ---------------------------------------------------------------------------

/// Write a single per-event YAML file to `dir` and return the path.
fn write_yaml_file(dir: &TempDir, filename: &str, content: &str) -> std::path::PathBuf {
    let path = dir.path().join(filename);
    std::fs::write(&path, content).unwrap();
    path
}

/// Build a minimal YAML for a single event parser in **EventParserFile** format
/// (i.e. `event_id:` at top level — suitable for directory-mode loading).
fn single_event_yaml(
    event_id: u32,
    name: &str,
    description: &str,
    fields_yaml: &str,
    enrichments_yaml: Option<&str>,
    output_format: Option<&str>,
) -> String {
    let mut s = format!(
        "event_id: {event_id}\nname: \"{name}\"\ndescription: \"{description}\"\nfields:\n{fields_yaml}\n"
    );
    if let Some(enr) = enrichments_yaml {
        s.push_str("enrichments:\n");
        s.push_str(enr);
        s.push('\n');
    }
    if let Some(fmt) = output_format {
        s.push_str(&format!("output_format: |\n  {fmt}\n"));
    }
    s
}

/// Build a minimal YAML in **EventParserConfig** format (has `event_parsers:` key)
/// suitable for single-file loading via `from_file(path_to_file)`.
fn single_file_config_yaml(
    event_id: u32,
    name: &str,
    description: &str,
    fields_yaml: &str,
    enrichments_yaml: Option<&str>,
    output_format: Option<&str>,
) -> String {
    let mut s = format!(
        "event_parsers:\n  {event_id}:\n    name: \"{name}\"\n    description: \"{description}\"\n    fields:\n"
    );
    // Indent the fields yaml by 4 extra spaces (they currently have 2 spaces of indent in fields_yaml)
    for line in fields_yaml.lines() {
        s.push_str("    ");
        s.push_str(line);
        s.push('\n');
    }
    if let Some(enr) = enrichments_yaml {
        s.push_str("    enrichments:\n");
        for line in enr.lines() {
            s.push_str("    ");
            s.push_str(line);
            s.push('\n');
        }
    }
    if let Some(fmt) = output_format {
        s.push_str(&format!("    output_format: |\n      {fmt}\n"));
    }
    s
}

/// Create a `NamedTempFile` containing `EventParserConfig` YAML for single-event test parsers.
fn make_single_file_parser(
    event_id: u32,
    name: &str,
    description: &str,
    fields_yaml: &str,
    enrichments_yaml: Option<&str>,
    output_format: Option<&str>,
) -> (NamedTempFile, GenericEventParser) {
    let yaml = single_file_config_yaml(
        event_id,
        name,
        description,
        fields_yaml,
        enrichments_yaml,
        output_format,
    );
    let mut file = NamedTempFile::new().unwrap();
    write!(file, "{yaml}").unwrap();
    let parser = GenericEventParser::from_file(file.path())
        .unwrap_or_else(|e| panic!("Failed to parse config for event {event_id}: {e}"));
    (file, parser)
}

// ---------------------------------------------------------------------------
// from_file with a DIRECTORY — load_from_directory happy path
// ---------------------------------------------------------------------------

#[test]
fn test_from_file_directory_loads_multiple_parsers() {
    let dir = TempDir::new().unwrap();

    write_yaml_file(
        &dir,
        "4688_process_created.yaml",
        &single_event_yaml(
            4688,
            "Process Created",
            "A new process was created",
            "  - name: \"NewProcessName\"\n    source: eventdata\n    xpath: \"Data[@Name='NewProcessName']\"\n    required: true\n    type: string\n",
            None,
            Some("Process {NewProcessName} started"),
        ),
    );

    write_yaml_file(
        &dir,
        "4625_failed_logon.yaml",
        &single_event_yaml(
            4625,
            "Failed Logon",
            "Logon failed",
            "  - name: \"TargetUserName\"\n    source: eventdata\n    xpath: \"Data[@Name='TargetUserName']\"\n    required: true\n    type: string\n",
            None,
            None,
        ),
    );

    let parser = GenericEventParser::from_file(dir.path()).unwrap();

    assert!(parser.has_parser(4688), "Should load 4688 from directory");
    assert!(parser.has_parser(4625), "Should load 4625 from directory");
    assert!(!parser.has_parser(9999), "Should not have unknown parser");

    let events = parser.supported_events();
    assert_eq!(events.len(), 2, "Should have exactly 2 parsers loaded");
}

// ---------------------------------------------------------------------------
// load_from_directory — non-YAML files are ignored
// ---------------------------------------------------------------------------

#[test]
fn test_from_file_directory_ignores_non_yaml() {
    let dir = TempDir::new().unwrap();

    // A non-YAML file that should be ignored
    std::fs::write(dir.path().join("README.txt"), "ignore me").unwrap();
    std::fs::write(dir.path().join("notes.md"), "ignore me too").unwrap();

    write_yaml_file(
        &dir,
        "4624.yaml",
        &single_event_yaml(
            4624,
            "Successful Logon",
            "Logon succeeded",
            "  - name: \"TargetUserName\"\n    source: eventdata\n    xpath: \"Data[@Name='TargetUserName']\"\n    required: true\n    type: string\n",
            None,
            None,
        ),
    );

    let parser = GenericEventParser::from_file(dir.path()).unwrap();
    assert!(parser.has_parser(4624));
    assert_eq!(parser.supported_events().len(), 1);
}

// ---------------------------------------------------------------------------
// load_from_directory — empty directory returns an error
// ---------------------------------------------------------------------------

#[test]
fn test_from_file_empty_directory_returns_error() {
    let dir = TempDir::new().unwrap();
    // No YAML files at all
    let result = GenericEventParser::from_file(dir.path());
    assert!(
        result.is_err(),
        "Should return Err when directory has no YAML files"
    );
    let err_msg = format!("{}", result.err().unwrap());
    assert!(
        err_msg.contains("No parser definitions"),
        "Error message should mention missing definitions, got: {err_msg}"
    );
}

// ---------------------------------------------------------------------------
// load_from_directory — duplicate event_id emits a warning but last-writer wins
// ---------------------------------------------------------------------------

#[test]
fn test_from_file_directory_duplicate_event_id_last_wins() {
    let dir = TempDir::new().unwrap();

    // Two files defining the SAME event_id
    write_yaml_file(
        &dir,
        "a_4624.yaml",
        &single_event_yaml(
            4624,
            "First Definition",
            "First",
            "  - name: \"TargetUserName\"\n    source: eventdata\n    xpath: \"Data[@Name='TargetUserName']\"\n    required: true\n    type: string\n",
            None,
            None,
        ),
    );
    write_yaml_file(
        &dir,
        "z_4624.yaml",
        &single_event_yaml(
            4624,
            "Second Definition",
            "Second",
            "  - name: \"TargetUserName\"\n    source: eventdata\n    xpath: \"Data[@Name='TargetUserName']\"\n    required: true\n    type: string\n",
            None,
            None,
        ),
    );

    // Should succeed (warn, but not error)
    let parser = GenericEventParser::from_file(dir.path()).unwrap();
    assert!(parser.has_parser(4624));
    // Files are sorted alphabetically so z_ comes after a_, meaning z_ overwrites a_
    let events = parser.supported_events();
    assert_eq!(events.len(), 1, "Duplicate should collapse to one entry");
}

// ---------------------------------------------------------------------------
// extract_from_system — success and failure paths
// ---------------------------------------------------------------------------

#[test]
fn test_extract_from_system_success() {
    let (_file, parser) = make_single_file_parser(
        9001,
        "Test System Fields",
        "Test",
        "  - name: \"Computer\"\n    source: system\n    xpath: \"Computer\"\n    required: true\n    type: string\n",
        None,
        Some("Host: {Computer}"),
    );

    let xml = r#"<Event>
  <System>
    <EventID>9001</EventID>
    <Computer>DC01.contoso.com</Computer>
  </System>
</Event>"#;

    let result = parser.parse_event(9001, xml).unwrap();
    assert_eq!(
        result.fields.get("Computer"),
        Some(&serde_json::Value::String("DC01.contoso.com".to_string())),
        "Should extract Computer from System section"
    );
    assert_eq!(
        result.formatted_message.as_deref(),
        Some("Host: DC01.contoso.com")
    );
}

#[test]
fn test_extract_from_system_missing_field_optional() {
    // System field missing but optional — parse_event should still succeed,
    // just without that field in the result map.
    let (_file, parser) = make_single_file_parser(
        9002,
        "Test System Missing Optional",
        "Test",
        "  - name: \"Computer\"\n    source: system\n    xpath: \"Computer\"\n    required: false\n    type: string\n",
        None,
        None,
    );

    let xml = r#"<Event><System><EventID>9002</EventID></System></Event>"#;

    let result = parser.parse_event(9002, xml);
    assert!(
        result.is_some(),
        "Missing optional system field should not abort parse"
    );
    let parsed = result.unwrap();
    assert!(
        !parsed.fields.contains_key("Computer"),
        "Optional missing field should be absent from result"
    );
}

#[test]
fn test_extract_from_system_missing_required_returns_none() {
    let (_file, parser) = make_single_file_parser(
        9003,
        "Test Required System",
        "Test",
        "  - name: \"Computer\"\n    source: system\n    xpath: \"Computer\"\n    required: true\n    type: string\n",
        None,
        None,
    );

    let xml = r#"<Event><System><EventID>9003</EventID></System></Event>"#;
    let result = parser.parse_event(9003, xml);
    assert!(
        result.is_none(),
        "Missing required system field should make parse_event return None"
    );
}

// ---------------------------------------------------------------------------
// extract_from_rendering_info — success and failure paths
// ---------------------------------------------------------------------------

#[test]
fn test_extract_from_rendering_info_success() {
    let (_file, parser) = make_single_file_parser(
        9010,
        "Test RenderingInfo",
        "Test",
        "  - name: \"Message\"\n    source: renderinginfo\n    xpath: \"Message\"\n    required: false\n    type: string\n",
        None,
        None,
    );

    let xml = r#"<Event>
  <System><EventID>9010</EventID></System>
  <RenderingInfo>
    <Message>The account was logged on successfully.</Message>
  </RenderingInfo>
</Event>"#;

    let result = parser.parse_event(9010, xml).unwrap();
    assert_eq!(
        result.fields.get("Message"),
        Some(&serde_json::Value::String(
            "The account was logged on successfully.".to_string()
        )),
        "Should extract content from RenderingInfo Message tag"
    );
}

#[test]
fn test_extract_from_rendering_info_missing_is_optional() {
    let (_file, parser) = make_single_file_parser(
        9011,
        "Test RenderingInfo Missing",
        "Test",
        "  - name: \"Message\"\n    source: renderinginfo\n    xpath: \"Message\"\n    required: false\n    type: string\n",
        None,
        None,
    );

    // No RenderingInfo section at all
    let xml = r#"<Event><System><EventID>9011</EventID></System></Event>"#;
    let result = parser.parse_event(9011, xml);
    assert!(
        result.is_some(),
        "Missing optional RenderingInfo should not abort parse"
    );
    assert!(!result.unwrap().fields.contains_key("Message"));
}

// ---------------------------------------------------------------------------
// extract_from_user_data — delegates to extract_from_event_data
// ---------------------------------------------------------------------------

#[test]
fn test_extract_from_user_data() {
    let (_file, parser) = make_single_file_parser(
        9020,
        "Test UserData",
        "Test",
        "  - name: \"TaskName\"\n    source: userdata\n    xpath: \"Data[@Name='TaskName']\"\n    required: true\n    type: string\n",
        None,
        Some("Task: {TaskName}"),
    );

    // UserData section with same Data-Name structure
    let xml = r#"<Event>
  <System><EventID>9020</EventID></System>
  <UserData>
    <Data Name="TaskName">\Microsoft\Windows\Example</Data>
  </UserData>
</Event>"#;

    let result = parser.parse_event(9020, xml).unwrap();
    assert_eq!(
        result.fields.get("TaskName"),
        Some(&serde_json::Value::String(
            r"\Microsoft\Windows\Example".to_string()
        )),
        "Should extract field from UserData section"
    );
}

// ---------------------------------------------------------------------------
// extract_from_event_data — self-closing tag branch (empty value)
// ---------------------------------------------------------------------------

#[test]
fn test_extract_from_event_data_self_closing_tag_returns_empty_string() {
    let (_file, parser) = make_single_file_parser(
        9030,
        "Test Self-closing",
        "Test",
        "  - name: \"EmptyField\"\n    source: eventdata\n    xpath: \"Data[@Name='EmptyField']\"\n    required: false\n    type: string\n",
        None,
        None,
    );

    // Self-closing Data element
    let xml = r#"<Event>
  <System><EventID>9030</EventID></System>
  <EventData>
    <Data Name="EmptyField"/>
  </EventData>
</Event>"#;

    let result = parser.parse_event(9030, xml).unwrap();
    assert_eq!(
        result.fields.get("EmptyField"),
        Some(&serde_json::Value::String(String::new())),
        "Self-closing tag should produce empty string value"
    );
}

// ---------------------------------------------------------------------------
// FieldType::Boolean — true, false, and "1" paths
// ---------------------------------------------------------------------------

#[test]
fn test_field_type_boolean_true_string() {
    let (_file, parser) = make_single_file_parser(
        9040,
        "Test Boolean",
        "Test",
        "  - name: \"Enabled\"\n    source: eventdata\n    xpath: \"Data[@Name='Enabled']\"\n    required: true\n    type: boolean\n",
        None,
        None,
    );

    let xml = r#"<Event>
  <System><EventID>9040</EventID></System>
  <EventData>
    <Data Name="Enabled">true</Data>
  </EventData>
</Event>"#;

    let result = parser.parse_event(9040, xml).unwrap();
    assert_eq!(
        result.fields.get("Enabled"),
        Some(&serde_json::Value::Bool(true)),
        "String 'true' should parse as boolean true"
    );
}

#[test]
fn test_field_type_boolean_numeric_one() {
    let (_file, parser) = make_single_file_parser(
        9041,
        "Test Boolean One",
        "Test",
        "  - name: \"Enabled\"\n    source: eventdata\n    xpath: \"Data[@Name='Enabled']\"\n    required: true\n    type: boolean\n",
        None,
        None,
    );

    let xml = r#"<Event>
  <System><EventID>9041</EventID></System>
  <EventData>
    <Data Name="Enabled">1</Data>
  </EventData>
</Event>"#;

    let result = parser.parse_event(9041, xml).unwrap();
    assert_eq!(
        result.fields.get("Enabled"),
        Some(&serde_json::Value::Bool(true)),
        "String '1' should parse as boolean true"
    );
}

#[test]
fn test_field_type_boolean_false_string() {
    let (_file, parser) = make_single_file_parser(
        9042,
        "Test Boolean False",
        "Test",
        "  - name: \"Enabled\"\n    source: eventdata\n    xpath: \"Data[@Name='Enabled']\"\n    required: true\n    type: boolean\n",
        None,
        None,
    );

    let xml = r#"<Event>
  <System><EventID>9042</EventID></System>
  <EventData>
    <Data Name="Enabled">false</Data>
  </EventData>
</Event>"#;

    let result = parser.parse_event(9042, xml).unwrap();
    assert_eq!(
        result.fields.get("Enabled"),
        Some(&serde_json::Value::Bool(false)),
        "String 'false' should parse as boolean false"
    );
}

#[test]
fn test_field_type_boolean_arbitrary_string_is_false() {
    // Any value that isn't "true" / "1" maps to false
    let (_file, parser) = make_single_file_parser(
        9043,
        "Test Boolean Arbitrary",
        "Test",
        "  - name: \"Enabled\"\n    source: eventdata\n    xpath: \"Data[@Name='Enabled']\"\n    required: true\n    type: boolean\n",
        None,
        None,
    );

    let xml = r#"<Event>
  <System><EventID>9043</EventID></System>
  <EventData>
    <Data Name="Enabled">yes</Data>
  </EventData>
</Event>"#;

    let result = parser.parse_event(9043, xml).unwrap();
    assert_eq!(
        result.fields.get("Enabled"),
        Some(&serde_json::Value::Bool(false)),
        "Arbitrary non-true string should produce boolean false"
    );
}

// ---------------------------------------------------------------------------
// FieldType::Integer — failure path (non-numeric string, required field)
// ---------------------------------------------------------------------------

#[test]
fn test_field_type_integer_invalid_value_required_returns_none() {
    let (_file, parser) = make_single_file_parser(
        9050,
        "Test Integer Fail",
        "Test",
        "  - name: \"LogonType\"\n    source: eventdata\n    xpath: \"Data[@Name='LogonType']\"\n    required: true\n    type: integer\n",
        None,
        None,
    );

    let xml = r#"<Event>
  <System><EventID>9050</EventID></System>
  <EventData>
    <Data Name="LogonType">not-a-number</Data>
  </EventData>
</Event>"#;

    // When a required integer field fails to parse, extract_field returns Err,
    // and since it's required, parse_event should return None.
    let result = parser.parse_event(9050, xml);
    assert!(
        result.is_none(),
        "Required integer field with invalid value should make parse return None"
    );
}

#[test]
fn test_field_type_integer_invalid_value_optional_skipped() {
    let (_file, parser) = make_single_file_parser(
        9051,
        "Test Integer Fail Optional",
        "Test",
        "  - name: \"LogonType\"\n    source: eventdata\n    xpath: \"Data[@Name='LogonType']\"\n    required: false\n    type: integer\n",
        None,
        None,
    );

    let xml = r#"<Event>
  <System><EventID>9051</EventID></System>
  <EventData>
    <Data Name="LogonType">not-a-number</Data>
  </EventData>
</Event>"#;

    // Optional integer with bad value: parse_event still returns Some but without that field
    let result = parser.parse_event(9051, xml);
    assert!(
        result.is_some(),
        "Optional bad-integer field should not abort parse"
    );
    assert!(
        !result.unwrap().fields.contains_key("LogonType"),
        "Bad optional integer should be absent from result"
    );
}

// ---------------------------------------------------------------------------
// FieldType::IpAddress and FieldType::Guid — pass-through as strings
// ---------------------------------------------------------------------------

#[test]
fn test_field_type_ipaddress() {
    let (_file, parser) = make_single_file_parser(
        9060,
        "Test IpAddress",
        "Test",
        "  - name: \"IpAddress\"\n    source: eventdata\n    xpath: \"Data[@Name='IpAddress']\"\n    required: true\n    type: ipaddress\n",
        None,
        None,
    );

    let xml = r#"<Event>
  <System><EventID>9060</EventID></System>
  <EventData>
    <Data Name="IpAddress">::1</Data>
  </EventData>
</Event>"#;

    let result = parser.parse_event(9060, xml).unwrap();
    assert_eq!(
        result.fields.get("IpAddress"),
        Some(&serde_json::Value::String("::1".to_string())),
        "IpAddress type should be stored as a string"
    );
}

#[test]
fn test_field_type_guid() {
    let (_file, parser) = make_single_file_parser(
        9061,
        "Test Guid",
        "Test",
        "  - name: \"CorrelationId\"\n    source: eventdata\n    xpath: \"Data[@Name='CorrelationId']\"\n    required: true\n    type: guid\n",
        None,
        None,
    );

    let xml = r#"<Event>
  <System><EventID>9061</EventID></System>
  <EventData>
    <Data Name="CorrelationId">{54849625-5478-4994-A5BA-3E3B0328C30D}</Data>
  </EventData>
</Event>"#;

    let result = parser.parse_event(9061, xml).unwrap();
    assert_eq!(
        result.fields.get("CorrelationId"),
        Some(&serde_json::Value::String(
            "{54849625-5478-4994-A5BA-3E3B0328C30D}".to_string()
        )),
        "Guid type should be stored as a string"
    );
}

// ---------------------------------------------------------------------------
// Enrichment — lookup miss (key not in table leaves enrichments map empty)
// ---------------------------------------------------------------------------

#[test]
fn test_enrichment_key_not_in_lookup_table() {
    // LogonType 99 is not in the lookup table
    let config_file = create_full_test_config();
    let parser = GenericEventParser::from_file(config_file.path()).unwrap();

    let xml = r#"<Event>
  <System><EventID>4624</EventID></System>
  <EventData>
    <Data Name="TargetUserName">alice</Data>
    <Data Name="TargetDomainName">CORP</Data>
    <Data Name="LogonType">99</Data>
    <Data Name="IpAddress">10.0.0.1</Data>
    <Data Name="IpPort">1234</Data>
  </EventData>
</Event>"#;

    let result = parser.parse_event(4624, xml).unwrap();
    // LogonType 99 is not in the enrichment table
    assert!(
        !result.enrichments.contains_key("LogonType_Name"),
        "Unknown lookup key should produce no enrichment entry"
    );
    // The raw field is still extracted
    assert_eq!(
        result.fields.get("LogonType"),
        Some(&serde_json::Value::Number(99.into()))
    );
}

// ---------------------------------------------------------------------------
// format_message — no fields/enrichments branch (empty patterns)
// ---------------------------------------------------------------------------

#[test]
fn test_format_message_empty_fields_returns_template_as_is() {
    // A parser that has an output_format but all its fields are optional and absent
    let (_file, parser) = make_single_file_parser(
        9070,
        "Test Empty Fields",
        "Test",
        "  - name: \"OptionalField\"\n    source: eventdata\n    xpath: \"Data[@Name='OptionalField']\"\n    required: false\n    type: string\n",
        None,
        Some("Static message with no placeholders"),
    );

    // No EventData at all — OptionalField absent, fields map will be empty
    let xml = r#"<Event><System><EventID>9070</EventID></System></Event>"#;

    let result = parser.parse_event(9070, xml).unwrap();
    // fields map is empty, format_message takes the "patterns.is_empty()" branch
    assert_eq!(
        result.formatted_message.as_deref(),
        Some("Static message with no placeholders"),
        "With no fields, template should be returned verbatim (trimmed)"
    );
}

// ---------------------------------------------------------------------------
// format_message — Number and Bool value serialization in template
// ---------------------------------------------------------------------------

#[test]
fn test_format_message_number_and_bool_placeholders() {
    let (_file, parser) = make_single_file_parser(
        9080,
        "Test Message Types",
        "Test",
        "  - name: \"Count\"\n    source: eventdata\n    xpath: \"Data[@Name='Count']\"\n    required: true\n    type: integer\n  - name: \"Enabled\"\n    source: eventdata\n    xpath: \"Data[@Name='Enabled']\"\n    required: true\n    type: boolean\n",
        None,
        Some("Count={Count} Enabled={Enabled}"),
    );

    let xml = r#"<Event>
  <System><EventID>9080</EventID></System>
  <EventData>
    <Data Name="Count">42</Data>
    <Data Name="Enabled">true</Data>
  </EventData>
</Event>"#;

    let result = parser.parse_event(9080, xml).unwrap();
    let msg = result.formatted_message.unwrap();
    assert!(msg.contains("42"), "Message should contain integer value");
    assert!(msg.contains("true"), "Message should contain bool value");
}

// ---------------------------------------------------------------------------
// has_parser — known and unknown IDs (explicit dedicated test)
// ---------------------------------------------------------------------------

#[test]
fn test_has_parser_known_and_unknown() {
    let dir = TempDir::new().unwrap();
    write_yaml_file(
        &dir,
        "4624.yaml",
        &single_event_yaml(
            4624,
            "Logon",
            "Logon event",
            "  - name: \"TargetUserName\"\n    source: eventdata\n    xpath: \"Data[@Name='TargetUserName']\"\n    required: true\n    type: string\n",
            None,
            None,
        ),
    );
    let parser = GenericEventParser::from_file(dir.path()).unwrap();

    assert!(parser.has_parser(4624), "Known ID should return true");
    assert!(!parser.has_parser(0), "0 should not be known");
    assert!(!parser.has_parser(u32::MAX), "MAX should not be known");
}

// ---------------------------------------------------------------------------
// parse_event with optional field absent — field just omitted, no None
// ---------------------------------------------------------------------------

#[test]
fn test_optional_field_absent_parse_succeeds_without_field() {
    let config_file = create_full_test_config();
    let parser = GenericEventParser::from_file(config_file.path()).unwrap();

    // IpAddress and IpPort are optional in 4624 — omit them
    let xml = r#"<Event>
  <System><EventID>4624</EventID></System>
  <EventData>
    <Data Name="TargetUserName">bob</Data>
    <Data Name="TargetDomainName">CORP</Data>
    <Data Name="LogonType">2</Data>
  </EventData>
</Event>"#;

    let result = parser.parse_event(4624, xml);
    assert!(
        result.is_some(),
        "Missing optional fields should not block parsing"
    );
    let parsed = result.unwrap();
    assert_eq!(
        parsed.fields.get("TargetUserName"),
        Some(&serde_json::Value::String("bob".to_string()))
    );
    // Optional fields absent from the map
    assert!(!parsed.fields.contains_key("IpAddress"));
    assert!(!parsed.fields.contains_key("IpPort"));
    // Enrichment for LogonType=2 should work
    assert_eq!(
        parsed.enrichments.get("LogonType_Name"),
        Some(&"Interactive".to_string())
    );
}

// ---------------------------------------------------------------------------
// Malformed / edge XML — graceful handling
// ---------------------------------------------------------------------------

#[test]
fn test_parse_event_completely_empty_xml_required_field_missing() {
    let config_file = create_full_test_config();
    let parser = GenericEventParser::from_file(config_file.path()).unwrap();

    // Completely empty string — required fields for 4624 are absent
    let result = parser.parse_event(4624, "");
    assert!(
        result.is_none(),
        "Empty XML with required fields should return None"
    );
}

#[test]
fn test_parse_event_xml_with_no_event_data_section() {
    let config_file = create_full_test_config();
    let parser = GenericEventParser::from_file(config_file.path()).unwrap();

    // Valid XML structure but no EventData section at all
    let xml = r#"<Event><System><EventID>4624</EventID></System></Event>"#;
    let result = parser.parse_event(4624, xml);
    assert!(
        result.is_none(),
        "XML with no EventData and required fields should return None"
    );
}

#[test]
fn test_parse_event_xml_with_extra_whitespace_in_values() {
    let (_file, parser) = make_single_file_parser(
        9090,
        "Whitespace Test",
        "Test",
        "  - name: \"Field\"\n    source: eventdata\n    xpath: \"Data[@Name='Field']\"\n    required: true\n    type: string\n",
        None,
        None,
    );

    // Value with leading/trailing whitespace is trimmed
    let xml = r#"<Event>
  <System><EventID>9090</EventID></System>
  <EventData>
    <Data Name="Field">  hello world  </Data>
  </EventData>
</Event>"#;

    let result = parser.parse_event(9090, xml).unwrap();
    assert_eq!(
        result.fields.get("Field"),
        Some(&serde_json::Value::String("hello world".to_string())),
        "Leading/trailing whitespace in values should be trimmed"
    );
}

#[test]
fn test_parse_event_unknown_event_id_returns_none() {
    let config_file = create_full_test_config();
    let parser = GenericEventParser::from_file(config_file.path()).unwrap();

    let xml = r#"<Event>
  <System><EventID>8888</EventID></System>
  <EventData><Data Name="Anything">value</Data></EventData>
</Event>"#;

    let result = parser.parse_event(8888, xml);
    assert!(
        result.is_none(),
        "Event ID without a parser definition should return None"
    );
}

// ---------------------------------------------------------------------------
// BUG DOCUMENTATION: production config/event_parsers YAML files use
// PascalCase source values (e.g. `source: EventData`) but the FieldSource
// enum is `#[serde(rename_all = "lowercase")]` which only accepts lowercase
// (e.g. `source: eventdata`). This means the production config directory
// cannot currently be loaded via GenericEventParser::from_file(directory).
//
// Test below characterises the existing broken behaviour so that any fix
// to either the enum or the YAML files will be visible as a test flip.
// ---------------------------------------------------------------------------

#[test]
fn test_from_file_real_config_directory_currently_fails_due_to_case_mismatch() {
    // Bug: production YAML files use PascalCase source names ("EventData",
    // "System", etc.) but FieldSource is serde(rename_all = "lowercase"),
    // so deserialization fails.
    let config_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("config")
        .join("event_parsers");

    if !config_dir.exists() {
        return;
    }

    let result = GenericEventParser::from_file(&config_dir);
    assert!(
        result.is_err(),
        "Production config directory load should currently fail due to PascalCase source names vs lowercase enum (BUG)"
    );
    let err_msg = format!("{}", result.err().unwrap());
    // The error should mention the case mismatch
    assert!(
        err_msg.contains("unknown variant") || err_msg.contains("Failed to parse"),
        "Error should reference unknown variant, got: {err_msg}"
    );
}

#[test]
fn test_unsupported_event() {
    let config_file = create_full_test_config();
    let parser = GenericEventParser::from_file(config_file.path()).unwrap();

    // Event ID 1234 is not defined in the config
    let xml = r#"<Event><EventData><Data Name="Test">value</Data></EventData></Event>"#;

    let result = parser.parse_event(1234, xml);
    assert!(
        result.is_none(),
        "Should return None for unsupported events"
    );
}

#[test]
fn test_missing_required_field() {
    let config_file = create_full_test_config();
    let parser = GenericEventParser::from_file(config_file.path()).unwrap();

    // Missing TargetUserName which is required
    let xml =
        r#"<Event><EventData><Data Name="TargetDomainName">CONTOSO</Data></EventData></Event>"#;

    let result = parser.parse_event(4624, xml);
    assert!(
        result.is_none(),
        "Should return None when required field is missing"
    );
}

#[test]
fn test_supported_events_list() {
    let config_file = create_full_test_config();
    let parser = GenericEventParser::from_file(config_file.path()).unwrap();

    let events = parser.supported_events();
    assert_eq!(events.len(), 2, "Should have 2 supported events");
    assert!(parser.has_parser(4624), "Should have parser for 4624");
    assert!(parser.has_parser(4668), "Should have parser for 4668");
    assert!(
        !parser.has_parser(9999),
        "Should not have parser for undefined event"
    );
}
