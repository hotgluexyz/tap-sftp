import logging
import os
import re
import stat
import tempfile
import time
from datetime import datetime
from io import StringIO
import backoff
import paramiko
import pytz
import singer
from paramiko.ssh_exception import AuthenticationException, SSHException

from tap_sftp import decrypt
from paramiko.sftp_file import SFTPFile

from paramiko.sftp_attr import SFTPAttributes
from paramiko.sftp import (
    CMD_HANDLE,
    SFTPError,
    SFTP_FLAG_READ,
    SFTP_FLAG_WRITE,
    SFTP_FLAG_CREATE,
    SFTP_FLAG_TRUNC,
    SFTP_FLAG_APPEND,
    SFTP_FLAG_EXCL,
    CMD_OPEN,
)
from paramiko.common import DEBUG
from paramiko.util import u
from binascii import hexlify

LOGGER = singer.get_logger()
MAX_TRIES = 6

logging.getLogger("paramiko").setLevel(logging.CRITICAL)

def handle_backoff(details):
    LOGGER.warn(
        "SSH Connection closed unexpectedly. Waiting {wait} seconds and retrying...".format(**details)
    )

class MySFTPClient(paramiko.SFTPClient):

    def open(self, filename, mode="r", bufsize=-1):
        
        filename = self._adjust_cwd(filename)
        self._log(DEBUG, "open({!r}, {!r})".format(filename, mode))
        imode = 0
        if ("r" in mode) or ("+" in mode):
            imode |= SFTP_FLAG_READ
        if ("w" in mode) or ("+" in mode) or ("a" in mode):
            imode |= SFTP_FLAG_WRITE
        if "w" in mode:
            imode |= SFTP_FLAG_CREATE | SFTP_FLAG_TRUNC
        if "a" in mode:
            imode |= SFTP_FLAG_CREATE | SFTP_FLAG_APPEND
        if "x" in mode:
            imode |= SFTP_FLAG_CREATE | SFTP_FLAG_EXCL
        attrblock = SFTPAttributes()
        t, msg = self._request(CMD_OPEN, filename, imode, attrblock)
        if t != CMD_HANDLE:
            raise SFTPError("Expected handle")
        handle = msg.get_binary()
        self._log(
            DEBUG,
            "open({!r}, {!r}) -> {}".format(
                filename, mode, u(hexlify(handle))
            ),
        )
        sftp_client = SFTPFile(self, handle, mode, bufsize)
        #TODO make this configurable
        sftp_client.MAX_REQUEST_SIZE = 3276
        return sftp_client

class SFTPConnection():
    def __init__(self, host, username, password=None, private_key_file=None, private_key= None, port=None,max_request_size=None):
        self.host = host
        self.username = username
        self.password = password
        self.port = int(port or 22)
        self.decrypted_file = None
        self.key = None
        self.transport = None
        self.retries = 10
        self.__sftp = None
        #TODO make it useable in MySFTPClient class
        self.max_request_size = max_request_size
        if private_key_file:
            key_path = os.path.expanduser(private_key_file)
            self.key = paramiko.RSAKey.from_private_key_file(key_path)
        elif private_key:
            key_string = StringIO(private_key)
            self.key = paramiko.RSAKey.from_private_key(key_string)

    # If connection is snapped during connect flow, retry up to a
    # minute for SSH connection to succeed. 2^6 + 2^5 + ...
    @backoff.on_exception(
        backoff.expo,
        (EOFError),
        max_tries=MAX_TRIES,
        on_backoff=handle_backoff,
        jitter=None,
        factor=2)
    def __connect(self):
        for i in range(self.retries+1):
            try:
                LOGGER.info('Creating new connection to SFTP...')
                self.transport = paramiko.Transport((self.host, self.port))
                self.transport.use_compression(True)
                self.transport.connect(username=self.username, password=self.password, hostkey=None, pkey=self.key)
                self.__sftp = MySFTPClient.from_transport(self.transport)
                LOGGER.info('Connection successful')
                break
            except (AuthenticationException, SSHException) as ex:
                self.close()
                LOGGER.info(f'Connection failed, retrying after {5*i} seconds...')
                time.sleep(5*i)
                LOGGER.info('Retrying now')
                if i >= (self.retries):
                    raise ex            

    @property
    def sftp(self):
        if self.__sftp is None:
            self.__connect()
        return self.__sftp

    @sftp.setter
    def sftp(self, sftp):
        self.__sftp = sftp

    def close(self):
        if self.__sftp:
            self.__sftp.close()
        if self.transport:
            self.transport.close()

    def match_files_for_table(self, files, table_name, search_pattern):
        LOGGER.info("Searching for files for table '%s', matching pattern: %s", table_name, search_pattern)
        matcher = re.compile(search_pattern)
        return [f for f in files if matcher.search(f["filepath"])]

    def is_empty(self, file_attr):
        return file_attr.st_size == 0

    def is_directory(self, file_attr):
        return stat.S_ISDIR(file_attr.st_mode)

    def get_files_by_prefix(self, prefix, search_subdirectories=True):
        """
        Accesses the underlying file system and gets all files that match "prefix", in this case, a directory path.

        Returns a list of filepaths from the root.
        """
        files = []

        if prefix is None or prefix == '':
            prefix = '.'

        try:
            result = self.sftp.listdir_attr(prefix)
        except FileNotFoundError as e:
            raise Exception("Directory '{}' does not exist".format(prefix)) from e
        except OSError as e:
            LOGGER.info("Socket closed. Retrying")
            self.__connect()
            result = self.sftp.listdir_attr(prefix)


        for file_attr in result:
            # NB: This only looks at the immediate level beneath the prefix directory
            if self.is_directory(file_attr) and search_subdirectories:
                files += self.get_files_by_prefix(prefix + '/' + file_attr.filename)
            else:
                if self.is_empty(file_attr):
                    continue

                last_modified = file_attr.st_mtime
                if last_modified is None:
                    LOGGER.warning("Cannot read m_time for file %s, defaulting to current epoch time",
                                   os.path.join(prefix, file_attr.filename))
                    last_modified = datetime.utcnow().timestamp()

                # NB: SFTP specifies path characters to be '/'
                #     https://tools.ietf.org/html/draft-ietf-secsh-filexfer-13#section-6
                files.append({"filepath": prefix + '/' + file_attr.filename,
                              "last_modified": datetime.utcfromtimestamp(last_modified).replace(tzinfo=pytz.UTC)})

        return files

    def get_files(self, prefix, search_pattern, modified_since=None, search_subdirectories=True):
        files = self.get_files_by_prefix(prefix, search_subdirectories)
        if files:
            LOGGER.info('Found %s files in "%s"', len(files), prefix)
        else:
            LOGGER.warning('Found no files on specified SFTP server at "%s"', prefix)

        matching_files = self.get_files_matching_pattern(files, search_pattern)

        if matching_files:
            LOGGER.info('Found %s files in "%s" matching "%s"', len(matching_files), prefix, search_pattern)
        else:
            LOGGER.warning('Found no files on specified SFTP server at "%s" matching "%s"', prefix, search_pattern)

        for f in matching_files:
            LOGGER.info("Found file: %s", f['filepath'])

        if modified_since is not None:
            matching_files = [f for f in matching_files if f["last_modified"] > modified_since]

        return matching_files
    
    def download_file_in_chunks(self, remote_file, local_file, chunk_size=1024 * 1024, counting = 1):  # 1 MB chunks by default
        """Download a file in chunks from the SFTP server and merge it locally."""
        try:
            logging.info("Downloading the file by chunks")
            # Get the total size of the remote file
            remote_size = self.sftp.stat(remote_file).st_size
            logging.info(f"Remote file size: {remote_size}")            
            # Open the remote file
            with self.sftp.file(remote_file, 'r') as remote_f:
                # If local file exists, start from where it left off
                local_size = 0
                if os.path.exists(local_file):
                    local_size = os.path.getsize(local_file)
                logging.info(f"Local file size: {local_size}")

                # Resume download or start fresh
                remote_f.seek(local_size)
                
                # Open local file in append mode
                with open(local_file, 'ab') as local_f:
                    while local_size < remote_size:
                        # Read a chunk from the remote file
                        chunk = remote_f.read(min(chunk_size, remote_size - local_size))
                        if not chunk:
                            break
                        # Write the chunk to the local file
                        local_f.write(chunk)
                        local_size += len(chunk)
                        logging.info(f"Downloaded {local_size} of {remote_size} bytes - Progress: {local_size/remote_size*100}%")

        except Exception as e:
            if counting > MAX_TRIES:
                logging.error(f"Error downloading {remote_file} by chunks: {str(e)}")
                raise Exception(e)
            self.close()
            self.__connect()
            self.download_file_in_chunks(remote_file,local_file,counting=counting+1)

    @backoff.on_exception(
        backoff.expo,
        (SSHException),
        max_tries=MAX_TRIES,
        on_backoff=handle_backoff,
        jitter=None,
        factor=2)
    def get_file_handle(self, f, decryption_configs=None):
        """ Takes a file dict {"filepath": "...", "last_modified": "..."} and returns a handle to the file. """
        with tempfile.TemporaryDirectory() as tmpdirname:
            sftp_file_path = f["filepath"]
            local_path = f'{tmpdirname}/{os.path.basename(sftp_file_path)}'
            if decryption_configs:
                LOGGER.info(f'Decrypting file: {sftp_file_path}')
                # Getting sftp file to local, then reading it is much faster than reading it directly from the SFTP
                self.sftp.get(sftp_file_path, local_path)
                decrypted_path = decrypt.gpg_decrypt(
                    local_path,
                    tmpdirname,
                    decryption_configs.get('key'),
                    decryption_configs.get('gnupghome'),
                    decryption_configs.get('passphrase')
                )
                LOGGER.info(f'Decrypting file complete')
                try:
                    return open(decrypted_path, 'rb')
                except FileNotFoundError:
                    raise Exception(f'Decryption of file failed: {sftp_file_path}')
            else:
                LOGGER.info(f'Getting the file from {sftp_file_path} to {local_path}...')
                try:
                    self.sftp.get(sftp_file_path, local_path)
                except:
                    self.download_file_in_chunks(sftp_file_path, local_path)
                return open(local_path, 'rb')

    def get_files_matching_pattern(self, files, pattern):
        """ Takes a file dict {"filepath": "...", "last_modified": "..."} and a regex pattern string, and returns
            files matching that pattern. """
        matcher = re.compile(pattern)
        LOGGER.info(f"Searching for files for matching pattern: {pattern}")
        return [f for f in files if matcher.search(f["filepath"])]


def connection(config):
    return SFTPConnection(config['host'],
                          config['username'],
                          password=config.get('password'),
                          private_key_file=config.get('private_key_file'),
                          private_key=config.get('private_key'),
                          port=config.get('port'),
                          max_request_size = int(config.get('max_request_size',32768)))
