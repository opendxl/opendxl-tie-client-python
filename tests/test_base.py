"""
Base DXL client for unit tests
"""
import json
import os
import re
import sys

from tempfile import NamedTemporaryFile
from unittest import TestCase
from mock import patch
from dxlclient import DxlClientConfig, DxlClient

if sys.version_info[0] > 2:
    import builtins  # pylint: disable=import-error, unused-import
else:
    import __builtin__  # pylint: disable=import-error
    builtins = __builtin__  # pylint: disable=invalid-name

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


    #pylint: disable=invalid-name, no-member, deprecated-method
    def assertRaisesRegex(self, expected_exception, expected_regex, *args, **kwargs):
        if sys.version_info[0] < 3:
            return self.assertRaisesRegexp(
                expected_exception,
                expected_regex,
                *args,
                **kwargs
            )

        return super(BaseClientTest, self).assertRaisesRegex(
            expected_exception,
            expected_regex,
            *args,
            **kwargs
        )


    @staticmethod
    def run_sample(sample_file):
        with open(sample_file) as f, \
                patch.object(builtins, 'print') as mock_print:
            sample_globals = {"__file__": sample_file}
            exec(f.read(), sample_globals)  # pylint: disable=exec-used
        return mock_print


    @staticmethod
    def expected_print_output(detail):
        json_string = json.dumps(
            detail,
            sort_keys=True,
            separators=(".*", ": ")
        )

        return re.sub(
            r"(\.\*)+",
            ".*",
            re.sub(
                r"[{[\]}]",
                ".*",
                json_string
            )
        )

class StringContains(object):
    def __init__(self, pattern):
        self.pattern = pattern

    def __eq__(self, other):
        return self.pattern in other


class StringDoesNotContain(object):
    def __init__(self, pattern):
        self.pattern = pattern

    def __eq__(self, other):
        return not self.pattern in other


class StringMatchesRegEx(object):
    def __init__(self, pattern):
        self.pattern = pattern

    def __eq__(self, other):
        return re.match(self.pattern, other, re.DOTALL)


class StringDoesNotMatchRegEx(object):
    def __init__(self, pattern):
        self.pattern = pattern

    def __eq__(self, other):
        return not re.match(self.pattern, other)


class TempSampleFile(object):

    @property
    def temp_file(self):
        return self._temp_file

    def __init__(self, sample_filename):
        self._temp_file = NamedTemporaryFile(
            mode="w+",
            dir=os.path.dirname(sample_filename),
            delete=False)
        self._temp_file.close()
        os.chmod(self._temp_file.name, 0o777)
        self.base_filename = sample_filename
        self.write_file_line(full_copy=True)

    def write_file_line(self, target=None, replacement=None, full_copy=False):
        if full_copy:
            base_filename = self.base_filename
            target_filename = self._temp_file.name
        else:
            base_filename = self._temp_file.name
            target_filename = base_filename + "new"

        with open(base_filename, 'r') as base_file:
            with open(target_filename, 'w+') as new_sample_file:
                for line in base_file:
                    if target != None and replacement != None:
                        if line.startswith(target):
                            line = replacement
                    new_sample_file.write(line)

        if not full_copy:
            os.remove(base_filename)
            os.rename(target_filename, base_filename)
            os.chmod(base_filename, 0o777)


    def __del__(self):
        self.temp_file.close()
        os.remove(self._temp_file.name)
