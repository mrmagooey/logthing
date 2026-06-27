//! DHCP payload parser. STUB — real implementation lands in Task 2.5.
use crate::syslog::SyslogMessage;
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct DhcpRecord;

pub fn try_parse(_msg: &SyslogMessage) -> Option<DhcpRecord> {
    None
}
