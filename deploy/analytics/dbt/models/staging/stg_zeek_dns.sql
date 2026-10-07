with src as (
    {{ source_or_empty('logthing', 'zeek_dns', {
        'ts': 'timestamp(6) with time zone',
        'uid': 'varchar',
        'id_orig_h': 'varchar',
        'id_orig_p': 'integer',
        'id_resp_h': 'varchar',
        'id_resp_p': 'integer',
        'proto': 'varchar',
        'trans_id': 'bigint',
        'query': 'varchar',
        'qtype_name': 'varchar',
        'qclass_name': 'varchar',
        'rcode_name': 'varchar',
        'answers': 'varchar',
        'partition_time': 'timestamp(6) with time zone'
    }) }}
)

select * from src
