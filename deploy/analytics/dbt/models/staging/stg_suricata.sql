with src as (
    {{ source_or_empty('logthing', 'suricata', {
        'event_type': 'varchar',
        'received_at': 'timestamp(6) with time zone',
        'src_ip': 'varchar',
        'payload': 'varchar',
        'partition_time': 'timestamp(6) with time zone'
    }) }}
)

select * from src
