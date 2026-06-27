//! LEEF payload parser. STUB — real implementation lands in Task 2.3.
use crate::syslog::SyslogMessage;
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct LeefRecord;

pub fn try_parse(_msg: &SyslogMessage) -> Option<LeefRecord> {
    None
}
