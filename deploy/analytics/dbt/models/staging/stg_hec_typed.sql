with src as (
    {{ source_or_empty('logthing', 'hec', {
        'sourcetype': 'varchar',
        'host': 'varchar',
        'time': 'timestamp(6) with time zone',
        'received_at': 'timestamp(6) with time zone',
        'fields': 'varchar',
        'partition_time': 'timestamp(6) with time zone',
        'event_uuid': 'varchar',
        'source': 'varchar',
        'index': 'varchar',
        'indexed_fields': 'varchar'
    }) }}
)

select * from src
