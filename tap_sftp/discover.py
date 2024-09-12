import singer
from singer import metadata

from tap_sftp import client
from tap_sftp.singer_encodings import json_schema

LOGGER = singer.get_logger()


def discover_streams(config):
    streams = []

    conn = client.connection(config)

    tables = config['tables']
    for table_spec in tables:
        visible_name = table_spec['table_name'].replace("/", "_")
        original_name = table_spec['table_name']
        if visible_name != original_name:
            LOGGER.info(f"Table name has been renamed from {original_name} to {visible_name} due to unsupported characters.")
        LOGGER.info('Sampling records to determine table JSON schema "%s".', table_spec['table_name'])
        schema = json_schema.get_schema_for_table(conn, table_spec, config)
        stream_md = metadata.get_standard_metadata(schema,
                                                   key_properties=table_spec.get('key_properties'),
                                                   replication_method='INCREMENTAL')
        streams.append(
            {
                'stream': visible_name,
                'tap_stream_id': original_name,
                'schema': schema,
                'metadata': stream_md
            }
        )

    return streams
