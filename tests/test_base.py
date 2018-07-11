"""
Base DXL client for unit tests
"""
import os

from unittest import TestCase
from dxlclient import DxlClientConfig, DxlClient

class BaseClientTest(TestCase):
    """
    Base DXL client class for unit tests
    """
    DEFAULT_TIMEOUT = 5 * 60
    DEFAULT_RETRIES = 3
    POST_OP_DELAY = 8
    REG_DELAY = 60

    @staticmethod
    def create_client(max_retries=DEFAULT_RETRIES, thread_pool_size=1):
        """
        Creates base DXL client
        """

        config = DxlClientConfig.create_dxl_config_from_file(
            str(os.path.dirname(os.path.abspath(__file__))) + "/dxlclient.config"
        )

        config.incoming_message_thread_pool_size = thread_pool_size

        config.connect_retries = max_retries

        return DxlClient(config)
