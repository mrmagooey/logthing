{#
  Value of <Data Name="<name>">...</Data> inside the WEF event XML held in `xml_col`.
  logthing stores WEF events as JSON whose `raw_xml` is the original Windows event; the fields the
  generic parser extracts are never persisted, so this regexp is the only way to read them.
  Handles both quote styles and extra attributes; absent fields, self-closing elements, blank
  values and Windows' "-" placeholder all become NULL (regexp_extract of a non-match is NULL).
#}
{% macro wef_field(xml_col, name) -%}
nullif(nullif(trim(regexp_extract({{ xml_col }}, 'Name=[''"]{{ name }}[''"](?:[^>]*[^/>])?>([^<]*)<', 1)), ''), '-')
{%- endmacro %}
