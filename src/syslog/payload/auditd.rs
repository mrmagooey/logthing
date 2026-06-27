//! Auditd payload parser. STUB — real implementation lands in Task 2.4.
use crate::syslog::SyslogMessage;
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct AuditdRecord;

pub fn try_parse(_msg: &SyslogMessage) -> Option<AuditdRecord> {
    None
}
