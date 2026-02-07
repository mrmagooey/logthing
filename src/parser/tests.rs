    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

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
        assert!(parsed.formatted_message.is_some(), "Should have formatted message");
        let msg = parsed.formatted_message.unwrap();
        assert!(msg.contains("john.doe"), "Message should contain username");
        assert!(msg.contains("CONTOSO"), "Message should contain domain");
        assert!(msg.contains("Network"), "Message should contain enriched logon type");
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
            Some(&serde_json::Value::String("HTTP/webserver.contoso.com".to_string())),
            "Should extract ServiceName"
        );
        
        assert_eq!(
            parsed.fields.get("Status"),
            Some(&serde_json::Value::String("0x0".to_string())),
            "Should extract Status"
        );
        
        // Check formatted message
        assert!(parsed.formatted_message.is_some(), "Should have formatted message");
        let msg = parsed.formatted_message.unwrap();
        assert!(msg.contains("administrator"), "Message should contain target username");
        assert!(msg.contains("CONTOSO"), "Message should contain domain");
        assert!(msg.contains("HTTP/webserver.contoso.com"), "Message should contain service name");
        assert!(msg.contains("0x0"), "Message should contain status");
        
        println!("Event 4668 formatted message: {}", msg);
    }

    #[test]
    fn test_unsupported_event() {
        let config_file = create_full_test_config();
        let parser = GenericEventParser::from_file(config_file.path()).unwrap();
        
        // Event ID 1234 is not defined in the config
        let xml = r#"<Event><EventData><Data Name="Test">value</Data></EventData></Event>"#;
        
        let result = parser.parse_event(1234, xml);
        assert!(result.is_none(), "Should return None for unsupported events");
    }

    #[test]
    fn test_missing_required_field() {
        let config_file = create_full_test_config();
        let parser = GenericEventParser::from_file(config_file.path()).unwrap();
        
        // Missing TargetUserName which is required
        let xml = r#"<Event><EventData><Data Name="TargetDomainName">CONTOSO</Data></EventData></Event>"#;
        
        let result = parser.parse_event(4624, xml);
        assert!(result.is_none(), "Should return None when required field is missing");
    }

    #[test]
    fn test_supported_events_list() {
        let config_file = create_full_test_config();
        let parser = GenericEventParser::from_file(config_file.path()).unwrap();
        
        let events = parser.supported_events();
        assert_eq!(events.len(), 2, "Should have 2 supported events");
        assert!(parser.has_parser(4624), "Should have parser for 4624");
        assert!(parser.has_parser(4668), "Should have parser for 4668");
        assert!(!parser.has_parser(9999), "Should not have parser for undefined event");
    }
