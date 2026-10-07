/* Detection: destination ports that are new (unseen in the previous 7 days) and rare (fewer than
   rare_port_max_connections connections in the last day). Direction is not recorded by every
   source, so read "outbound" as "towards the responder". */
with recent as (
    select
        dst_endpoint_port as port,
        count(*) as connections,
        count(distinct src_endpoint_ip) as sources,
        min(dst_endpoint_ip) as example_destination
    from {{ ref('ocsf_network_activity') }}
    where "time" > {{ detection_now() }} - interval '1' day
      and dst_endpoint_port is not null
    group by 1
),

baseline as (
    select distinct dst_endpoint_port as port
    from {{ ref('ocsf_network_activity') }}
    where "time" <= {{ detection_now() }} - interval '1' day
      and "time" > {{ detection_now() }} - interval '8' day
      and dst_endpoint_port is not null
)

select r.port, r.connections, r.sources, r.example_destination
from recent r
left join baseline b on r.port = b.port
where b.port is null
  and r.connections < {{ var('rare_port_max_connections', 5) }}
order by r.connections, r.port
