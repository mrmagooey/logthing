{{ dedup_by_event_uuid(ref('stg_otlp_typed'), [
    'event_uuid', 'time', 'observed_time', 'received_at', 'severity_number', 'severity_text',
    'body', 'service_name', 'service_namespace', 'service_instance_id', 'host_name',
    'peer_addr', 'trace_id', 'span_id', 'flags', 'event_name', 'scope_name', 'scope_version',
    'resource_attributes', 'attributes', 'partition_time'
]) }}
