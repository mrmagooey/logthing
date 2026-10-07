-- OCSF 1.3 Network Activity (class_uid 4001, category 4), activity 6 "Traffic".
-- Sources: Zeek conn.log, IPFIX flow records, sFlow flow samples. OCSF dotted attributes are
-- flattened with underscores (src_endpoint.ip -> src_endpoint_ip).
with zeek as (
    select
        coalesce(ts, partition_time) as event_time,
        ts as start_time,
        case when duration is not null
             then date_add('millisecond', cast(round(duration * 1000) as bigint), ts) end as end_time,
        id_orig_h as src_endpoint_ip,
        id_orig_p as src_endpoint_port,
        id_resp_h as dst_endpoint_ip,
        id_resp_p as dst_endpoint_port,
        cast(null as integer) as connection_info_protocol_num,
        lower(proto) as connection_info_protocol_name,
        resp_bytes as traffic_bytes_in,
        orig_bytes as traffic_bytes_out,
        case when orig_bytes is null and resp_bytes is null then null
             else coalesce(orig_bytes, 0) + coalesce(resp_bytes, 0) end as traffic_bytes,
        resp_pkts as traffic_packets_in,
        orig_pkts as traffic_packets_out,
        case when orig_pkts is null and resp_pkts is null then null
             else coalesce(orig_pkts, 0) + coalesce(resp_pkts, 0) end as traffic_packets,
        uid as metadata_correlation_uid,
        'zeek_conn' as metadata_log_name
    from {{ ref('stg_zeek_conn') }}
),

ipfix as (
    select
        coalesce(flow_start, export_time, partition_time) as event_time,
        flow_start as start_time,
        flow_end as end_time,
        src_addr as src_endpoint_ip,
        src_port as src_endpoint_port,
        dst_addr as dst_endpoint_ip,
        dst_port as dst_endpoint_port,
        ip_protocol as connection_info_protocol_num,
        {{ ip_protocol_name('ip_protocol') }} as connection_info_protocol_name,
        cast(null as bigint) as traffic_bytes_in,
        cast(null as bigint) as traffic_bytes_out,
        octet_delta_count as traffic_bytes,
        cast(null as bigint) as traffic_packets_in,
        cast(null as bigint) as traffic_packets_out,
        packet_delta_count as traffic_packets,
        cast(null as varchar) as metadata_correlation_uid,
        'ipfix' as metadata_log_name
    from {{ ref('stg_ipfix') }}
),

sflow as (
    select
        coalesce(received_at, partition_time) as event_time,
        cast(null as timestamp(6) with time zone) as start_time,
        cast(null as timestamp(6) with time zone) as end_time,
        src_addr as src_endpoint_ip,
        src_port as src_endpoint_port,
        dst_addr as dst_endpoint_ip,
        dst_port as dst_endpoint_port,
        ip_protocol as connection_info_protocol_num,
        {{ ip_protocol_name('ip_protocol') }} as connection_info_protocol_name,
        cast(null as bigint) as traffic_bytes_in,
        cast(null as bigint) as traffic_bytes_out,
        cast(null as bigint) as traffic_bytes,
        cast(null as bigint) as traffic_packets_in,
        cast(null as bigint) as traffic_packets_out,
        cast(null as bigint) as traffic_packets,
        cast(null as varchar) as metadata_correlation_uid,
        'sflow_flow' as metadata_log_name
    from {{ ref('stg_sflow_flow') }}
),

unioned as (
    select * from zeek
    union all select * from ipfix
    union all select * from sflow
)

select
    event_time as "time",
    4 as category_uid,
    'Network Activity' as category_name,
    4001 as class_uid,
    'Network Activity' as class_name,
    6 as activity_id,
    'Traffic' as activity_name,
    4001 * 100 + 6 as type_uid,
    1 as severity_id,
    'Informational' as severity,
    'logthing' as metadata_product_name,
    '{{ var("ocsf_version") }}' as metadata_version,
    metadata_log_name,
    metadata_correlation_uid,
    start_time,
    end_time,
    src_endpoint_ip,
    src_endpoint_port,
    dst_endpoint_ip,
    dst_endpoint_port,
    connection_info_protocol_num,
    connection_info_protocol_name,
    traffic_bytes,
    traffic_bytes_in,
    traffic_bytes_out,
    traffic_packets,
    traffic_packets_in,
    traffic_packets_out
from unioned
