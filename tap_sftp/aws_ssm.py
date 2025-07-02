import boto3
import threading


class AWS_SSM:

    _client = None
    _lock = threading.Lock()

    @classmethod
    def _get_client(cls):
        if cls._client:
            return cls._client
        
        # Use double-checked locking pattern for thread safety
        with cls._lock:
            if cls._client is None:
                cls._client = boto3.client('ssm')
            return cls._client

    @classmethod
    def get_decryption_key(cls, key_name):
        client = cls._get_client()
        response = client.get_parameter(
            Name=key_name,
            WithDecryption=True
        )
        return response.get('Parameter').get('Value')
