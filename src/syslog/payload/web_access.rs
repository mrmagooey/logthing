//! Web access log payload parser. STUB — real implementation lands in Task 2.7.
use crate::syslog::SyslogMessage;
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct WebAccessRecord;

pub fn try_parse(_msg: &SyslogMessage) -> Option<WebAccessRecord> {
    None
}
