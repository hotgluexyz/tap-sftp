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
from typing import Optional
from paramiko.ssh_exception import AuthenticationException, SSHException

from tap_sftp import decrypt

LOGGER = singer.get_logger()

logging.getLogger("paramiko").setLevel(logging.CRITICAL)


class FileHandleWithCleanup:
    """
    Context manager that keeps a file handle and its temp directory alive.
    
    This ensures the temp directory is not deleted until the file is fully processed.
    Fixes the race condition where TemporaryDirectory() would delete files
    before they were done being read.
    """
    def __init__(self, file_handle, temp_dir):
        self.file_handle = file_handle
        self.temp_dir = temp_dir  # Keep reference to prevent deletion
    
    def __enter__(self):
        return self.file_handle
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        try:
            # Close file handle first
            if self.file_handle and not self.file_handle.closed:
                self.file_handle.close()
        finally:
            # Always cleanup temp directory, even if close() fails
            if self.temp_dir:
                self.temp_dir.cleanup()
        
        return False  # Don't suppress exceptions


def handle_backoff(details):
    LOGGER.warn(
        "SSH Connection closed unexpectedly. Waiting {wait} seconds and retrying...".format(**details)
    )


class SFTPConnection():
    def __init__(self, host, username, password=None, private_key_file=None, private_key= None, port=None):
        self.host = host
        self.username = username
        self.password = password
        self.port = int(port or 22)
        self.decrypted_file = None
        self.key = None
        self.transport = None
        self.retries = 10
        self.__sftp = None
        self._setup_key(private_key_file, private_key, password)

    def _setup_key(self, private_key_file: Optional[str] = None, private_key: Optional[str] = None, passphrase: Optional[str] = None):
        key_classes = [paramiko.RSAKey, paramiko.DSSKey, paramiko.ECDSAKey, paramiko.Ed25519Key]
    
        for key_class in key_classes:
            try:
                if private_key_file:
                    key_path = os.path.expanduser(private_key_file)
                    self.key = key_class.from_private_key_file(key_path, passphrase)
                elif private_key:
                    key_string = StringIO(private_key)
                    self.key = key_class.from_private_key(key_string, passphrase)
                break  # Successfully loaded, no need to try other types
            except paramiko.SSHException:
                continue # Try the next key type
        
        if not self.key and (private_key_file or private_key):
            error_message = "Could not determine the SSH key type or load the key."
            LOGGER.error(error_message)
            raise Exception(error_message)

    # If connection is snapped during connect flow, retry up to a
    # minute for SSH connection to succeed. 2^6 + 2^5 + ...
    @backoff.on_exception(
        backoff.expo,
        (EOFError, ConnectionResetError),
        max_tries=6,
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
                self.__sftp = paramiko.SFTPClient.from_transport(self.transport)
                LOGGER.info('Connection successful')
                break
            except (AuthenticationException, SSHException, ConnectionResetError) as ex:
                if self.__sftp:
                    self.__sftp.close()
                if self.transport:
                    self.transport.close()
                LOGGER.info(f'Connection failed, sleeping for {5*i} secconds...')
                time.sleep(5*i)
                LOGGER.info("Retrying to establish a connection...")
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
        self.__sftp.close()
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

    def get_file_handle(self, f, decryption_configs=None):
        """
        Takes a file dict {"filepath": "...", "last_modified": "..."} and returns a context manager
        that provides a handle to the file while keeping the temp directory alive.
        
        The temp directory will only be cleaned up when the context manager exits,
        ensuring the file remains accessible during processing.
        """
        # Create temp directory but DON'T use 'with' - we need to keep it alive
        temp_dir = tempfile.TemporaryDirectory()
        tmpdirname = temp_dir.name

        try:
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
                LOGGER.info('Decrypting file complete')
                try:
                    file_handle = open(decrypted_path, 'rb')
                except FileNotFoundError:
                    raise Exception(f'Decryption of file failed: {sftp_file_path}')
            else:
                self.sftp.get(sftp_file_path, local_path)
                file_handle = open(local_path, 'rb')
            
            # Return context manager that keeps temp_dir alive until processing completes
            return FileHandleWithCleanup(file_handle, temp_dir)
            
        except Exception:
            # If anything fails, cleanup and re-raise
            temp_dir.cleanup()
            raise

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
                          port=config.get('port'))
