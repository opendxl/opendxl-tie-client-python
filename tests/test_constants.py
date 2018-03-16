import base64
import struct
import unittest
from dxltieclient.constants import EnterpriseAttrib, FileEnterpriseAttrib


class TestEnterpriseAttrib(unittest.TestCase):
    def test_to_version_tuple(self):
        self.assertEqual((1, 4, 0, 190),
                         EnterpriseAttrib.to_version_tuple("73183493944770750"))
    def test_to_version_string(self):
        self.assertEqual("1.4.0.190",
                         EnterpriseAttrib.to_version_string("73183493944770750"))


class TestFileEnterpriseAttrib(unittest.TestCase):
    def test_to_aggregate_tuple(self):
        aggregate = base64.b64encode(struct.pack("<5H", 2, 100, 50, 100, 7500))
        self.assertEqual((2, 100, 50, 100, 75.0),
                         FileEnterpriseAttrib.to_aggregate_tuple(aggregate))
    def test_to_aggregate_tuple_with_zero_trust_across_files(self):
        aggregate = base64.b64encode(struct.pack("<5H", 1, 0, 0, 0, 0))
        self.assertEqual((1, 0, 0, 0, 0),
                         FileEnterpriseAttrib.to_aggregate_tuple(aggregate))
