{# Reference time of the detections. Defaults to the wall clock; pin it for reproducible runs:
   dbt compile --vars '{detection_as_of: "2026-10-05T12:00:00Z"}' #}
{% macro detection_now() -%}
{%- if var('detection_as_of', none) is not none -%}
from_iso8601_timestamp('{{ var("detection_as_of") }}')
{%- else -%}
current_timestamp
{%- endif -%}
{%- endmacro %}

{# Upper bound on "time", applied ONLY when detection_as_of is set (a true replay must not see
   events after the pinned instant). Live runs stay unbounded. #}
{% macro detection_upper_bound() -%}
{%- if var('detection_as_of', none) is not none -%}
and "time" <= {{ detection_now() }}
{%- endif -%}
{%- endmacro %}
