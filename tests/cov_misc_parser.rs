//! Coverage tests for `parser::GenericEventParser` branches (enrichment of string and boolean
//! fields, mixed attribute quote styles, self-closing System elements).

use std::io::Write;

use logthing::parser::GenericEventParser;
use tempfile::NamedTempFile;

const PARSERS: &str = r#"
event_parsers:
  9001:
    name: "Coverage"
    description: "exercise enrichment and extraction edge cases"
    fields:
      - name: "Who"
        source: "eventdata"
        xpath: "Data[@Name='Who']"
        required: true
        type: "string"
      - name: "Flag"
        source: "eventdata"
        xpath: "Data[@Name='Flag']"
        required: true
        type: "boolean"
      - name: "EventID"
        source: "system"
        xpath: "EventID"
        required: true
        type: "integer"
    enrichments:
      - field: "Who"
        lookup_table:
          "admin": "Administrator"
      - field: "Flag"
        lookup_table:
          "true": "Enabled"
    output_format: "{Who} {Flag_Name} {Who_Name}"
  9002:
    name: "OptionalEnriched"
    description: "enrichment on a field that may be absent"
    fields:
      - name: "Who"
        source: "eventdata"
        xpath: "Data[@Name='Who']"
        required: true
        type: "string"
      - name: "Role"
        source: "eventdata"
        xpath: "Data[@Name='Role']"
        required: false
        type: "string"
    enrichments:
      - field: "Role"
        lookup_table:
          "root": "Superuser"
"#;

fn parser() -> GenericEventParser {
    let mut file = NamedTempFile::new().unwrap();
    write!(file, "{PARSERS}").unwrap();
    GenericEventParser::from_file(file.path()).unwrap()
}

fn event(who_data: &str, system: &str) -> String {
    format!(
        "<Event><System>{system}</System><EventData>{who_data}\
         <Data Name=\"Flag\">true</Data></EventData></Event>"
    )
}

#[test]
fn test_enrichment_matches_string_and_boolean_field_values() {
    let xml = event("<Data Name=\"Who\">admin</Data>", "<EventID>4</EventID>");
    let parsed = parser().parse_event(9001, &xml).expect("parses");
    assert_eq!(parsed.enrichments["Who_Name"], "Administrator");
    assert_eq!(parsed.enrichments["Flag_Name"], "Enabled");
    assert_eq!(
        parsed.formatted_message.as_deref(),
        Some("admin Enabled Administrator")
    );
}

#[test]
fn test_enrichment_without_matching_lookup_entry_is_omitted() {
    let xml = event("<Data Name=\"Who\">bob</Data>", "<EventID>4</EventID>");
    let parsed = parser().parse_event(9001, &xml).expect("parses");
    assert!(!parsed.enrichments.contains_key("Who_Name"));
    assert_eq!(parsed.enrichments["Flag_Name"], "Enabled");
}

#[test]
fn test_extract_prefers_earliest_attribute_when_both_quote_styles_present() {
    let xml = event(
        "<Data Name='Who'>single</Data><Data Name=\"Who\">double</Data>",
        "<EventID>4</EventID>",
    );
    let parsed = parser().parse_event(9001, &xml).expect("parses");
    assert_eq!(parsed.fields["Who"], "single");
}

#[test]
fn test_system_extraction_skips_self_closing_element() {
    let xml = event(
        "<Data Name=\"Who\">x</Data>",
        "<EventID /><EventID>7</EventID>",
    );
    let parsed = parser().parse_event(9001, &xml).expect("parses");
    assert_eq!(parsed.fields["EventID"], 7);
}

#[test]
fn test_enrichment_on_absent_optional_field_is_skipped() {
    let xml = "<Event><EventData><Data Name=\"Who\">bob</Data></EventData></Event>";
    let parsed = parser().parse_event(9002, xml).expect("parses");
    assert_eq!(parsed.fields["Who"], "bob");
    assert!(!parsed.fields.contains_key("Role"));
    assert!(parsed.enrichments.is_empty());
}

#[test]
fn test_unterminated_data_element_counts_as_missing_field() {
    let xml = "<Event><EventData><Data Name=\"Who\">bob</EventData></Event>";
    assert!(parser().parse_event(9002, xml).is_none());
}
