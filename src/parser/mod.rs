use anyhow::Context;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use tracing::{debug, info, warn};

/// Configuration for all event parsers
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct EventParserConfig {
    #[serde(rename = "event_parsers")]
    pub parsers: HashMap<u32, EventParserDefinition>,
}

/// Definition for parsing a specific event type
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct EventParserDefinition {
    pub name: String,
    pub description: String,
    pub fields: Vec<FieldDefinition>,
    #[serde(default)]
    pub enrichments: Vec<Enrichment>,
    #[serde(default)]
    pub output_format: Option<String>,
}

/// Definition for a field to extract from an event
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct FieldDefinition {
    pub name: String,
    pub source: FieldSource,
    pub xpath: String,
    #[serde(default)]
    pub required: bool,
    #[serde(default, rename = "type")]
    pub field_type: FieldType,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum FieldSource {
    EventData,
    System,
    RenderingInfo,
    UserData,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum FieldType {
    #[default]
    String,
    Integer,
    Boolean,
    IpAddress,
    Guid,
}

/// Enrichment rules for fields
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Enrichment {
    pub field: String,
    #[serde(rename = "lookup_table")]
    pub lookup: HashMap<String, String>,
}

/// Parsed event data with extracted fields
#[derive(Debug, Clone, Serialize)]
pub struct ParsedEventData {
    pub event_id: u32,
    pub parser_name: String,
    pub fields: HashMap<String, serde_json::Value>,
    pub enrichments: HashMap<String, String>,
    pub formatted_message: Option<String>,
}

/// Generic event parser that loads configuration from YAML
pub struct GenericEventParser {
    config: EventParserConfig,
}

impl GenericEventParser {
    /// Load parser configuration from a YAML file or directory.
    ///
    /// If the path is a directory, loads all `.yml` and `.yaml` files from it.
    /// If the path is a file, loads that single YAML file.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use wef_server::parser::GenericEventParser;
    ///
    /// // Load from a directory containing parser YAML files
    /// let parser = GenericEventParser::from_file("config/event_parsers")?;
    ///
    /// // Check if a parser exists for event ID 4624
    /// let has_parser = parser.has_parser(4624);
    /// println!("Has parser for 4624: {}", has_parser);
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn from_file<P: AsRef<Path>>(path: P) -> anyhow::Result<Self> {
        let path = path.as_ref();
        info!("Loading event parser configuration from {:?}", path);

        let config = if path.is_dir() {
            Self::load_from_directory(path)?
        } else {
            let content = fs::read_to_string(path)?;
            serde_yaml::from_str(&content)?
        };

        info!("Loaded {} event parser definitions", config.parsers.len());

        for (event_id, parser) in &config.parsers {
            debug!(
                "Event {}: {} ({} fields)",
                event_id,
                parser.name,
                parser.fields.len()
            );
        }

        Ok(Self { config })
    }

    fn load_from_directory(dir: &Path) -> anyhow::Result<EventParserConfig> {
        let mut yaml_files: Vec<PathBuf> = fs::read_dir(dir)?
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.path())
            .filter(|path| {
                path.is_file()
                    && path
                        .extension()
                        .and_then(|ext| ext.to_str())
                        .map(|ext| matches!(ext.to_lowercase().as_str(), "yml" | "yaml"))
                        .unwrap_or(false)
            })
            .collect();

        yaml_files.sort();

        let mut parsers = HashMap::new();

        for file_path in yaml_files {
            let content = fs::read_to_string(&file_path)
                .with_context(|| format!("Failed to read {:?}", file_path))?;
            let parser_file: EventParserFile = serde_yaml::from_str(&content)
                .with_context(|| format!("Failed to parse {:?}", file_path))?;

            if parsers
                .insert(parser_file.event_id, parser_file.definition)
                .is_some()
            {
                warn!(
                    "Duplicate parser definition detected for event {} in {:?}",
                    parser_file.event_id, file_path
                );
            }
        }

        if parsers.is_empty() {
            return Err(anyhow::anyhow!(
                "No parser definitions found in directory {:?}",
                dir
            ));
        }

        Ok(EventParserConfig { parsers })
    }

    /// Parse a Windows event XML using the appropriate parser.
    ///
    /// Extracts fields based on the parser configuration, applies enrichments,
    /// and formats the output message.
    ///
    /// Returns `None` if no parser is defined for the event ID or if required fields are missing.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use wef_server::parser::GenericEventParser;
    ///
    /// let parser = GenericEventParser::from_file("config/event_parsers").unwrap();
    ///
    /// let xml = r#"<Event>
    ///   <System>
    ///     <EventID>4624</EventID>
    ///   </System>
    ///   <EventData>
    ///     <Data Name="TargetUserName">admin</Data>
    ///     <Data Name="LogonType">3</Data>
    ///   </EventData>
    /// </Event>"#;
    ///
    /// if let Some(parsed) = parser.parse_event(4624, xml) {
    ///     println!("Parsed {} fields", parsed.fields.len());
    ///     println!("Message: {:?}", parsed.formatted_message);
    /// }
    /// ```
    pub fn parse_event(&self, event_id: u32, xml: &str) -> Option<ParsedEventData> {
        let parser_def = self.config.parsers.get(&event_id)?;

        debug!(
            "Parsing event {} using parser: {}",
            event_id, parser_def.name
        );

        let mut fields = HashMap::new();

        // Extract each field defined in the configuration
        for field_def in &parser_def.fields {
            match self.extract_field(xml, field_def) {
                Ok(value) => {
                    fields.insert(field_def.name.clone(), value);
                }
                Err(e) => {
                    if field_def.required {
                        warn!(
                            "Required field '{}' missing for event {}: {}",
                            field_def.name, event_id, e
                        );
                        return None;
                    } else {
                        debug!(
                            "Optional field '{}' not found for event {}: {}",
                            field_def.name, event_id, e
                        );
                    }
                }
            }
        }

        // Apply enrichments
        let mut enrichments = HashMap::new();
        for enrichment in &parser_def.enrichments {
            if let Some(value) = fields.get(&enrichment.field) {
                let value_str = match value {
                    serde_json::Value::String(s) => s.clone(),
                    serde_json::Value::Number(n) => n.to_string(),
                    _ => value.to_string(),
                };

                if let Some(enriched) = enrichment.lookup.get(&value_str) {
                    let enriched_field_name = format!("{}_Name", enrichment.field);
                    enrichments.insert(enriched_field_name, enriched.clone());
                }
            }
        }

        // Format output message if template exists
        let formatted_message = parser_def
            .output_format
            .as_ref()
            .and_then(|template| self.format_message(template, &fields, &enrichments));

        Some(ParsedEventData {
            event_id,
            parser_name: parser_def.name.clone(),
            fields,
            enrichments,
            formatted_message,
        })
    }

    /// Extract a field from the XML using the field definition
    fn extract_field(
        &self,
        xml: &str,
        field_def: &FieldDefinition,
    ) -> anyhow::Result<serde_json::Value> {
        let value = match field_def.source {
            FieldSource::EventData => self.extract_from_event_data(xml, &field_def.xpath),
            FieldSource::System => self.extract_from_system(xml, &field_def.name),
            FieldSource::RenderingInfo => self.extract_from_rendering_info(xml, &field_def.name),
            FieldSource::UserData => self.extract_from_user_data(xml, &field_def.xpath),
        }?;

        // Convert to appropriate type
        let converted = match field_def.field_type {
            FieldType::String => serde_json::Value::String(value),
            FieldType::Integer => value
                .parse::<i64>()
                .map(|n| serde_json::Value::Number(serde_json::Number::from(n)))
                .map_err(|e| anyhow::anyhow!("Failed to parse integer: {}", e))?,
            FieldType::Boolean => {
                serde_json::Value::Bool(value.to_lowercase() == "true" || value == "1")
            }
            FieldType::IpAddress | FieldType::Guid => serde_json::Value::String(value),
        };

        Ok(converted)
    }

    /// Extract a value from EventData section
    fn extract_from_event_data(&self, xml: &str, xpath: &str) -> anyhow::Result<String> {
        // Parse the xpath to extract attribute name
        // Expected format: Data[@Name='FieldName']
        let attr_name = xpath
            .trim_start_matches("Data[@Name='")
            .trim_end_matches("']");

        // Look for Data element with the specified Name attribute
        let search_pattern = format!(r#"Data Name="{}""#, attr_name);

        if let Some(pos) = xml.find(&search_pattern) {
            // Find the start of this element
            let start = xml[..pos]
                .rfind('<')
                .ok_or_else(|| anyhow::anyhow!("Could not find element start for {}", attr_name))?;

            // Find the end of the start tag
            let tag_end = xml[pos..]
                .find('>')
                .ok_or_else(|| anyhow::anyhow!("Could not find tag end for {}", attr_name))?;

            // Check if it's a self-closing tag
            let full_tag = &xml[start..pos + tag_end + 1];
            if full_tag.ends_with("/>") {
                return Ok(String::new());
            }

            // Extract content between tags
            let content_start = pos + tag_end + 1;
            let end_tag = format!("</Data>");

            if let Some(end_pos) = xml[content_start..].find(&end_tag) {
                let value = xml[content_start..content_start + end_pos].trim();
                return Ok(value.to_string());
            }
        }

        Err(anyhow::anyhow!(
            "Field with attribute Name='{}' not found in EventData",
            attr_name
        ))
    }

    /// Extract a value from System section
    fn extract_from_system(&self, xml: &str, field_name: &str) -> anyhow::Result<String> {
        let start_tag = format!("<{}>", field_name);
        let end_tag = format!("</{}>", field_name);

        if let Some(start) = xml.find(&start_tag) {
            let content_start = start + start_tag.len();
            if let Some(end) = xml[content_start..].find(&end_tag) {
                return Ok(xml[content_start..content_start + end].to_string());
            }
        }

        Err(anyhow::anyhow!(
            "Field '{}' not found in System section",
            field_name
        ))
    }

    /// Extract a value from RenderingInfo section
    fn extract_from_rendering_info(&self, xml: &str, _field_name: &str) -> anyhow::Result<String> {
        // RenderingInfo contains the message template
        let message_pattern = "<Message>";
        if let Some(start) = xml.find(message_pattern) {
            let content_start = start + message_pattern.len();
            if let Some(end) = xml[content_start..].find("</Message>") {
                return Ok(xml[content_start..content_start + end].to_string());
            }
        }

        Err(anyhow::anyhow!("RenderingInfo Message not found"))
    }

    /// Extract a value from UserData section
    fn extract_from_user_data(&self, xml: &str, xpath: &str) -> anyhow::Result<String> {
        // Similar to EventData extraction for UserData section
        self.extract_from_event_data(xml, xpath)
    }

    /// Format an output message using the template
    fn format_message(
        &self,
        template: &str,
        fields: &HashMap<String, serde_json::Value>,
        enrichments: &HashMap<String, String>,
    ) -> Option<String> {
        let mut result = template.to_string();

        // Replace field placeholders
        for (field_name, value) in fields {
            let placeholder = format!("{{{}}}", field_name);
            let value_str = match value {
                serde_json::Value::String(s) => s.clone(),
                serde_json::Value::Number(n) => n.to_string(),
                serde_json::Value::Bool(b) => b.to_string(),
                _ => value.to_string(),
            };
            result = result.replace(&placeholder, &value_str);
        }

        // Replace enrichment placeholders
        for (field_name, value) in enrichments {
            let placeholder = format!("{{{}}}", field_name);
            result = result.replace(&placeholder, value);
        }

        Some(result.trim().to_string())
    }

    /// Check if a parser exists for the given event ID
    pub fn has_parser(&self, event_id: u32) -> bool {
        self.config.parsers.contains_key(&event_id)
    }

    /// Get list of supported event IDs
    pub fn supported_events(&self) -> Vec<u32> {
        self.config.parsers.keys().copied().collect()
    }
}

#[derive(Debug, Deserialize)]
struct EventParserFile {
    event_id: u32,
    #[serde(flatten)]
    definition: EventParserDefinition,
}

#[cfg(test)]
mod tests;
