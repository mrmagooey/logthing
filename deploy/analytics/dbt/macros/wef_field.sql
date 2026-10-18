{#
  Value of the EventData field `name` for a WEF event, read from `parsed.data.<name>` in the
  serialized WindowsEvent JSON held in `json_col` (logthing stores every `Data Name=...` there as
  untrimmed text). Absent fields, blank values and Windows' "-" placeholder all become NULL, and
  so does malformed JSON (json_extract_scalar of a non-match or non-JSON is NULL). Rows written
  before logthing 0.23.0 have no `parsed.data` and yield NULL.
#}
{% macro wef_field(json_col, name) -%}
nullif(nullif(trim(json_extract_scalar({{ json_col }}, '$.parsed.data.{{ name }}')), ''), '-')
{%- endmacro %}
