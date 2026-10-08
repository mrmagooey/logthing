{#
  One row per event_uuid: the earliest-received copy wins (then the earliest partition_time,
  then "time" so ties are deterministic).
  Rows whose event_uuid is NULL (HEC rows written before 0.22.0) are all kept: they have no
  identity to dedup on, and `partition by` would otherwise collapse them into one row.
  `columns` must list every column of `relation` (Trino has no SELECT * EXCEPT); a pytest
  keeps each list equal to the typed model's.
#}
{% macro dedup_by_event_uuid(relation, columns) %}
select
{%- for c in columns %}
    "{{ c }}"{{ "," if not loop.last }}
{%- endfor %}
from (
    select *,
        row_number() over (
            partition by event_uuid order by received_at, partition_time, "time"
        ) as dedup_rn
    from {{ relation }}
) as ranked
where event_uuid is null or dedup_rn = 1
{% endmacro %}
