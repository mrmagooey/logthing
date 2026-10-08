/* Detection: repeated failed Windows logons (4625) from one source IP.
   Fires for a source IP with at least bruteforce_threshold failures inside one 10-minute
   tumbling window during the last day (a sliding window would be more precise; see README).
   Override: dbt compile --vars '{bruteforce_threshold: 20}'. detection_as_of pins "now". */
select
    src_endpoint_ip,
    from_unixtime(floor(to_unixtime("time") / 600) * 600) as window_start,
    count(*) as failures,
    count(distinct user_name) as distinct_users,
    array_agg(distinct user_name) filter (where user_name is not null) as users
from {{ ref('ocsf_authentication') }}
where activity_id = 1
  and status_id = 2
  and src_endpoint_ip is not null
  and "time" > {{ detection_now() }} - interval '1' day
  {{ detection_upper_bound() }}
group by 1, 2
having count(*) >= {{ var('bruteforce_threshold', 10) }}
order by failures desc
