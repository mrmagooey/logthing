with src as (
    {{ source_or_empty('logthing', 'otlp', {
        'event_uuid': 'varchar',
        'time': 'timestamp(6) with time zone',
        'observed_time': 'timestamp(6) with time zone',
        'received_at': 'timestamp(6) with time zone',
        'severity_number': 'integer',
        'severity_text': 'varchar',
        'body': 'varchar',
        'service_name': 'varchar',
        'service_namespace': 'varchar',
        'service_instance_id': 'varchar',
        'host_name': 'varchar',
        'peer_addr': 'varchar',
        'trace_id': 'varchar',
        'span_id': 'varchar',
        'flags': 'bigint',
        'event_name': 'varchar',
        'scope_name': 'varchar',
        'scope_version': 'varchar',
        'resource_attributes': 'varchar',
        'attributes': 'varchar',
        'partition_time': 'timestamp(6) with time zone'
    }) }}
)

select * from src
