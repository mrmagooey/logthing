# Generic Windows Event Parser - Implementation Summary

## Overview

I've implemented a generic framework for parsing specific Windows event codes with externally loaded YAML configuration. The framework supports:
- Event code 4624 (Successful Logon)
- Event code 4668 (S4U2Self)
- Extensible to any other Windows event code

## Files Created/Modified

### 1. Configuration Directory (`config/event_parsers/`)
Each YAML file inside this directory defines one Windows event (e.g., `4624_successful_logon.yaml`):
- Field extraction rules with XPath-like selectors
- Data type conversion (string, integer, boolean)
- Enrichment lookups (e.g., LogonType integer → readable name)
- Custom output message formatting

### 2. Parser Module (`src/parser/mod.rs`)
Generic parsing framework with:
- `GenericEventParser` - Main parser struct
- `EventParserConfig` - YAML configuration structures
- Field extraction from EventData, System, RenderingInfo, UserData sections
- Type conversion (string, integer, boolean, IP, GUID)
- Enrichment lookups
- Message template formatting

### 3. Parser Tests (`src/parser/tests.rs`)
Comprehensive tests for:
- Event 4624 parsing (Successful Logon with network type)
- Event 4668 parsing (S4U2Self)
- Unsupported event handling
- Missing required field handling
- Enrichment validation

### 4. Updated Cargo.toml
Added dependencies:
- `serde_yaml = "0.9"` - YAML parsing
- `tempfile = "3.9"` (dev) - Test file creation

### 5. Updated main.rs
Added `mod parser;` to include the new module

### 6. Updated server/mod.rs
- Added event_parser to AppState
- Load parser config on server startup
- Integration with event handling pipeline

## Configuration Format

```yaml
event_id: 4624
name: "Successful Logon"
description: "An account was successfully logged on"
fields:
  - name: "TargetUserName"
    source: EventData
    xpath: "Data[@Name='TargetUserName']"
    required: true
    type: string
  - name: "LogonType"
    source: EventData
    xpath: "Data[@Name='LogonType']"
    required: true
    type: integer
enrichments:
  - field: "LogonType"
    lookup_table:
      "2": "Interactive"
      "3": "Network"
output_format: |
  User {TargetUserName} logged on via {LogonType_Name}
```

> For backward compatibility the parser still accepts a single aggregated `config/event_parsers.yaml`, but the directory layout makes it easier to version-control individual events.

## Usage Example

```rust
use logthing::parser::GenericEventParser;

// Load configuration directory (or pass a single YAML file for legacy setups)
let parser = GenericEventParser::from_file("config/event_parsers")?;

// Check if parser exists for event
if parser.has_parser(4624) {
    // Parse Windows event XML
    if let Some(parsed) = parser.parse_event(4624, event_xml) {
        println!("Event: {}", parsed.parser_name);
        println!("Fields: {:?}", parsed.fields);
        println!("Message: {:?}", parsed.formatted_message);
    }
}
```

## Test Results

### Event 4624 (Successful Logon)
✅ Extracts TargetUserName, TargetDomainName, LogonType, IpAddress, IpPort
✅ Converts LogonType from "3" to integer 3
✅ Enriches LogonType 3 → "Network"
✅ Formats message: "User john.doe from CONTOSO logged on via Network from 192.168.1.100:49234"

### Event 4668 (S4U2Self)
✅ Extracts TargetUserName, TargetDomainName, ServiceName, Status
✅ Handles HTTP service delegation scenario
✅ Formats message: "S4U2Self: administrator@CONTOSO requested HTTP/webserver.contoso.com with status 0x0"

### Edge Cases
✅ Returns None for unsupported events (e.g., event 1234)
✅ Returns None when required fields are missing
✅ Lists all supported events correctly

## Integration with Logthing

The generic parser integrates into the server pipeline:
1. Server loads `config/event_parsers/` (or the legacy YAML file) on startup
2. When events are received, they're first parsed by the WEF protocol parser
3. If a generic parser exists for the event ID, it's applied for detailed extraction
4. Enriched event data is available for forwarding to destinations

## Future Enhancements

Potential improvements:
- Hot-reload of parser configuration
- Regex-based field extraction
- Custom Lua/Python scripts for complex parsing
- Caching of parsed events
- More enrichment types (GeoIP, threat intel lookups)
- Message templates with conditional logic
