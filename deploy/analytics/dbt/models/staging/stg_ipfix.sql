with src as (
    {{ source_or_empty('logthing', 'ipfix', {
        'observation_domain_id': 'bigint',
        'template_id': 'integer',
        'protocol_version': 'integer',
        'exporter': 'varchar',
        'export_time': 'timestamp(6) with time zone',
        'src_addr': 'varchar',
        'dst_addr': 'varchar',
        'src_port': 'integer',
        'dst_port': 'integer',
        'ip_protocol': 'integer',
        'octet_delta_count': 'bigint',
        'packet_delta_count': 'bigint',
        'flow_start': 'timestamp(6) with time zone',
        'flow_end': 'timestamp(6) with time zone',
        'tcp_flags': 'integer',
        'input_interface': 'bigint',
        'output_interface': 'bigint',
        'extra': 'varchar',
        'partition_time': 'timestamp(6) with time zone'
    }) }}
)

select * from src
