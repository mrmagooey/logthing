{% macro ip_protocol_name(col) -%}
case {{ col }} when 1 then 'icmp' when 6 then 'tcp' when 17 then 'udp' when 58 then 'ipv6-icmp' end
{%- endmacro %}
