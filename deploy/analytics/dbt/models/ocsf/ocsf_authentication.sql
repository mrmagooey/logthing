-- OCSF 1.3 Authentication (class_uid 3002, category 3) from Windows security events
-- 4624 logon, 4625 failed logon, 4634 logoff, 4648 logon with explicit credentials.
-- Fields come from the event XML (see macros/wef_field.sql); malformed JSON/XML yields NULLs, the
-- row's time then falls back to the receipt time.
with base as (
    select
        event_id,
        received_at,
        source_host,
        json_extract_scalar(event_data, '$.raw_xml') as raw_xml,
        json_extract_scalar(event_data, '$.parsed.computer') as computer,
        try(cast(from_iso8601_timestamp(json_extract_scalar(event_data, '$.parsed.time_created'))
                 as timestamp(6) with time zone)) as created_at
    from {{ ref('stg_wef') }}
    where event_id in (4624, 4625, 4634, 4648)
)

select
    coalesce(created_at, received_at) as "time",
    3 as category_uid,
    'Identity & Access Management' as category_name,
    3002 as class_uid,
    'Authentication' as class_name,
    case when event_id = 4634 then 2 else 1 end as activity_id,
    case when event_id = 4634 then 'Logoff' else 'Logon' end as activity_name,
    3002 * 100 + case when event_id = 4634 then 2 else 1 end as type_uid,
    case when event_id = 4625 then 2 else 1 end as severity_id,
    case when event_id = 4625 then 'Low' else 'Informational' end as severity,
    case when event_id = 4625 then 2 else 1 end as status_id,
    case when event_id = 4625 then 'Failure' else 'Success' end as status,
    'logthing' as metadata_product_name,
    '{{ var("ocsf_version") }}' as metadata_version,
    'wef' as metadata_log_name,
    cast(event_id as varchar) as metadata_event_code,
    {{ wef_field('raw_xml', 'TargetUserName') }} as user_name,
    {{ wef_field('raw_xml', 'TargetDomainName') }} as user_domain,
    {{ wef_field('raw_xml', 'SubjectUserName') }} as actor_user_name,
    try(cast({{ wef_field('raw_xml', 'LogonType') }} as integer)) as logon_type_id,
    {{ wef_field('raw_xml', 'IpAddress') }} as src_endpoint_ip,
    try(cast({{ wef_field('raw_xml', 'IpPort') }} as integer)) as src_endpoint_port,
    {{ wef_field('raw_xml', 'WorkstationName') }} as src_endpoint_hostname,
    coalesce(computer, source_host) as dst_endpoint_hostname,
    case when event_id = 4625
         then coalesce({{ wef_field('raw_xml', 'SubStatus') }}, {{ wef_field('raw_xml', 'Status') }})
    end as status_detail
from base
