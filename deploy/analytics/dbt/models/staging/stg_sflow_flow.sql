with src as (
    {{ source_or_empty('logthing', 'sflow_flow', {
        'sample_type': 'varchar',
        'exporter': 'varchar',
        'received_at': 'timestamp(6) with time zone',
        'src_addr': 'varchar',
        'dst_addr': 'varchar',
        'src_port': 'integer',
        'dst_port': 'integer',
        'ip_protocol': 'integer',
        'sampling_rate': 'bigint',
        'input_ifindex': 'bigint',
        'output_ifindex': 'bigint',
        'extra': 'varchar',
        'partition_time': 'timestamp(6) with time zone'
    }) }}
)

select * from src
