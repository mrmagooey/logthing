{#
  Select the given columns, cast to the given Trino types, from a logthing source table. The
  committer creates each Iceberg table only once data for it has arrived (no Zeek rows -> no
  zeek_conn table), and a view over a missing table cannot be created. When the table does not
  exist this emits a typed empty result with the same shape instead, so `dbt build` works on a
  fresh stack. The view then stays empty until `dbt run` is executed again after the table exists.
  columns: dict of column name -> Trino type, e.g. {'ts': 'timestamp(6) with time zone'}.
#}
{% macro source_or_empty(source_name, table_name, columns) %}
{%- set src = source(source_name, table_name) -%}
{%- set rel = adapter.get_relation(database=src.database, schema=src.schema, identifier=src.identifier) -%}
{%- if execute and rel is none -%}
select
{%- for name, type in columns.items() %}
    cast(null as {{ type }}) as "{{ name }}"{{ "," if not loop.last }}
{%- endfor %}
where false
{%- else -%}
select
{%- for name, type in columns.items() %}
    cast("{{ name }}" as {{ type }}) as "{{ name }}"{{ "," if not loop.last }}
{%- endfor %}
from {{ src }}
{%- endif -%}
{% endmacro %}
