-- OCSF 1.3 DNS Activity (class_uid 4003, category 4) from Zeek dns.log. A row with an rcode is a
-- Response (activity 2), otherwise a Query (activity 1).
select
    coalesce(ts, partition_time) as "time",
    4 as category_uid,
    'Network Activity' as category_name,
    4003 as class_uid,
    'DNS Activity' as class_name,
    case when rcode_name is null then 1 else 2 end as activity_id,
    case when rcode_name is null then 'Query' else 'Response' end as activity_name,
    4003 * 100 + case when rcode_name is null then 1 else 2 end as type_uid,
    1 as severity_id,
    'Informational' as severity,
    'logthing' as metadata_product_name,
    '{{ var("ocsf_version") }}' as metadata_version,
    'zeek_dns' as metadata_log_name,
    uid as metadata_correlation_uid,
    query as query_hostname,
    qtype_name as query_type,
    qclass_name as query_class,
    rcode_name as rcode,
    answers,
    id_orig_h as src_endpoint_ip,
    id_orig_p as src_endpoint_port,
    id_resp_h as dst_endpoint_ip,
    id_resp_p as dst_endpoint_port,
    lower(proto) as connection_info_protocol_name
from {{ ref('stg_zeek_dns') }}
