{{ dedup_by_event_uuid(ref('stg_hec_typed'), [
    'sourcetype', 'host', 'time', 'received_at', 'fields', 'partition_time', 'event_uuid',
    'source', 'index', 'indexed_fields'
]) }}
