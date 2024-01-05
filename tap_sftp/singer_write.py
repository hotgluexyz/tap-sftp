import sys
import simplejson as json
from singer.messages import RecordMessage

def format_message(message):
    return json.dumps(message.asdict(), use_decimal=True, ensure_ascii=False)


def write_message(message):
    sys.stdout.write(format_message(message) + '\n')
    sys.stdout.flush()


def write_record(stream_name, record, stream_alias=None, time_extracted=None):
    """Write a single record for the given stream.

    write_record("users", {"id": 2, "email": "mike@stitchdata.com"})
    """
    write_message(RecordMessage(stream=(stream_alias or stream_name),
                                record=record,
                                time_extracted=time_extracted))