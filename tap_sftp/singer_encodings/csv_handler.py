import codecs
import csv
import io
import os
import chardet

from chardet.universaldetector import UniversalDetector
from tap_sftp.singer_encodings import compression

SDC_EXTRA_COLUMN = "_sdc_extra"


def get_row_iterators(iterable, options={}, infer_compression=False):
    """Accepts an interable, options and a flag to infer compression and yields
    csv.DictReader objects which can be used to yield CSV rows."""
    if infer_compression:
        compressed_iterables = compression.infer(iterable, options.get('file_name'))
    for item in compressed_iterables:
        yield get_row_iterator(item, options=options)


def get_row_iterator(iterable, options=None):
    """Accepts an interable, options and returns a csv.DictReader object
    which can be used to yield CSV rows."""
    options = options or {}

    # Replace any NULL bytes in the line given to the DictReader
    detector = UniversalDetector()
    for line in iterable:
        detector.feed(line)
        if detector.done: break
    detector.close()
    
    iterable.seek(0)
    reader = csv.DictReader(
        io.TextIOWrapper(iterable, encoding=(options.get("encoding") or detector.result.get('encoding'))),
        fieldnames=None,
        restkey=SDC_EXTRA_COLUMN,
        delimiter=options.get('delimiter', ',')
    )

    headers = set(reader.fieldnames)
    if options.get('key_properties'):
        key_properties = set(options['key_properties'])
        if not key_properties.issubset(headers):
            raise Exception('CSV file missing required headers: {}'
                            .format(key_properties - headers))

    if options.get('date_overrides'):
        date_overrides = set(options['date_overrides'])
        if not date_overrides.issubset(headers):
            raise Exception('CSV file missing date_overrides headers: {}'
                            .format(date_overrides - headers))
    return reader
