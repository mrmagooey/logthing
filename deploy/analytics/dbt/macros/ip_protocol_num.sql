{% macro ip_protocol_num(col) -%}
case lower({{ col }}) when 'icmp' then 1 when 'tcp' then 6 when 'udp' then 17
     when 'icmp6' then 58 when 'ipv6-icmp' then 58 end
{%- endmacro %}
