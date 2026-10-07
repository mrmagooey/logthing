{# Reference time of the detections. Defaults to the wall clock; pin it for reproducible runs:
   dbt compile --vars '{detection_as_of: "2026-10-05T12:00:00Z"}' #}
{% macro detection_now() -%}
{%- if var('detection_as_of', none) is not none -%}
from_iso8601_timestamp('{{ var("detection_as_of") }}')
{%- else -%}
current_timestamp
{%- endif -%}
{%- endmacro %}
