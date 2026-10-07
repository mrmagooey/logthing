-- OCSF 1.3 Detection Finding (class_uid 2004, category 2) from Suricata EVE alerts.
-- Suricata severity 1 (high) .. 3 (low) maps to OCSF 4 (High) .. 2 (Low).
with alerts as (
    select
        received_at,
        src_ip,
        json_extract_scalar(payload, '$.timestamp') as ts_raw,
        json_extract_scalar(payload, '$.src_ip') as payload_src_ip,
        try(cast(json_extract_scalar(payload, '$.src_port') as integer)) as src_port,
        json_extract_scalar(payload, '$.dest_ip') as dst_ip,
        try(cast(json_extract_scalar(payload, '$.dest_port') as integer)) as dst_port,
        json_extract_scalar(payload, '$.proto') as proto,
        json_extract_scalar(payload, '$.alert.signature') as signature,
        try(cast(json_extract_scalar(payload, '$.alert.signature_id') as bigint)) as signature_id,
        try(cast(json_extract_scalar(payload, '$.alert.severity') as integer)) as severity,
        json_extract_scalar(payload, '$.alert.category') as category,
        json_extract_scalar(payload, '$.alert.action') as action
    from {{ ref('stg_suricata') }}
    where event_type = 'alert'
)

select
    coalesce(
        try(cast(parse_datetime(ts_raw, 'yyyy-MM-dd''T''HH:mm:ss.SSSSSSZ') as timestamp(6) with time zone)),
        received_at) as "time",
    2 as category_uid,
    'Findings' as category_name,
    2004 as class_uid,
    'Detection Finding' as class_name,
    1 as activity_id,
    'Create' as activity_name,
    2004 * 100 + 1 as type_uid,
    case severity when 1 then 4 when 2 then 3 when 3 then 2 else 1 end as severity_id,
    case severity when 1 then 'High' when 2 then 'Medium' when 3 then 'Low'
         else 'Informational' end as severity,
    'logthing' as metadata_product_name,
    '{{ var("ocsf_version") }}' as metadata_version,
    'suricata' as metadata_log_name,
    signature as finding_info_title,
    cast(signature_id as varchar) as finding_info_uid,
    category as finding_info_category,
    action as disposition_name,
    coalesce(src_ip, payload_src_ip) as src_endpoint_ip,
    src_port as src_endpoint_port,
    dst_ip as dst_endpoint_ip,
    dst_port as dst_endpoint_port,
    lower(proto) as connection_info_protocol_name
from alerts
