//! RADIUS payload parser. STUB — real implementation lands in Task 2.6.
use crate::syslog::SyslogMessage;
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct RadiusRecord;

pub fn try_parse(_msg: &SyslogMessage) -> Option<RadiusRecord> {
    None
}
