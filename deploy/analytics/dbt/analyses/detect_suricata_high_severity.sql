/* Detection: Suricata alerts of high severity, grouped by destination.
   suricata_min_severity_id is the OCSF severity (4 = High, 5 = Critical). Last 24 hours. */
select
    dst_endpoint_ip,
    count(*) as alerts,
    count(distinct finding_info_uid) as distinct_signatures,
    min("time") as first_seen,
    max("time") as last_seen,
    array_agg(distinct finding_info_title) as signatures
from {{ ref('ocsf_detection_finding') }}
where severity_id >= {{ var('suricata_min_severity_id', 4) }}
  and "time" > {{ detection_now() }} - interval '1' day
  {{ detection_upper_bound() }}
group by 1
order by alerts desc
