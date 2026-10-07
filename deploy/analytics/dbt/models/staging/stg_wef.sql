with src as (
    {{ source_or_empty('logthing', 'wef', {
        'event_id': 'bigint',
        'timestamp': 'timestamp(6) with time zone',
        'source_host': 'varchar',
        'subscription_id': 'varchar',
        'event_data': 'varchar',
        'partition_time': 'timestamp(6) with time zone'
    }) }}
)

select
    event_id,
    "timestamp" as received_at,
    source_host,
    subscription_id,
    event_data,
    partition_time
from src
