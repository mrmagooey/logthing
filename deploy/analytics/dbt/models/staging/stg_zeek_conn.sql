with src as (
    {{ source_or_empty('logthing', 'zeek_conn', {
        'ts': 'timestamp(6) with time zone',
        'uid': 'varchar',
        'id_orig_h': 'varchar',
        'id_orig_p': 'integer',
        'id_resp_h': 'varchar',
        'id_resp_p': 'integer',
        'proto': 'varchar',
        'service': 'varchar',
        'duration': 'double',
        'orig_bytes': 'bigint',
        'resp_bytes': 'bigint',
        'conn_state': 'varchar',
        'history': 'varchar',
        'orig_pkts': 'bigint',
        'resp_pkts': 'bigint',
        'partition_time': 'timestamp(6) with time zone'
    }) }}
)

select * from src
