from unittest import TestCase
from tests.test_value_constants import *

class TestEpockMixinToLocalTime(TestCase):

    def test_tolocaltime(self):
        sample_epoch_time = 1234

        expected_localtime = time.localtime(float(sample_epoch_time))

        returned_local_time = EpochMixin.to_localtime(sample_epoch_time)

        self.assertEqual(returned_local_time.tm_year, expected_localtime.tm_year)
        self.assertEqual(returned_local_time.tm_mon, expected_localtime.tm_mon)
        self.assertEqual(returned_local_time.tm_mday, expected_localtime.tm_mday)
        self.assertEqual(returned_local_time.tm_hour, expected_localtime.tm_hour)
        self.assertEqual(returned_local_time.tm_min, expected_localtime.tm_min)
        self.assertEqual(returned_local_time.tm_sec, expected_localtime.tm_sec)
        self.assertEqual(returned_local_time.tm_wday, expected_localtime.tm_wday)
        self.assertEqual(returned_local_time.tm_yday, expected_localtime.tm_yday)
        self.assertEqual(returned_local_time.tm_isdst, expected_localtime.tm_isdst)


    def test_tolocaltime_string(self):
        sample_epoch_time = 1234
        localtime_string_partial_format = "%Y-%m-%d %H:%M:%S"

        expected_localtime = time.localtime(float(sample_epoch_time))
        expected_localtime_string = time.strftime(
            localtime_string_partial_format,
            expected_localtime
        )

        returned_local_time_string = EpochMixin.to_localtime_string(sample_epoch_time)

        self.assertEqual(returned_local_time_string, expected_localtime_string)


class TestEnterpriseAttribToVersion(TestCase):

    def test_toversion_tuple(self):
        enterprise_version_tuple = (int(1), int(4), int(0), int(190))

        returned_tuple = EnterpriseAttrib.to_version_tuple(SAMPLE_ENTERPRISE_VERSION)

        self.assertEqual(returned_tuple, enterprise_version_tuple)


    def test_toversion_string(self):
        enterprise_version_string = "1.4.0.190"

        returned_string = EnterpriseAttrib.to_version_string(SAMPLE_ENTERPRISE_VERSION)

        self.assertEqual(returned_string, enterprise_version_string)


class TestFileEnterpriseAttribToAggregate(TestCase):

    def test_toaggregate_tuple(self):
        # To generate sample aggregate strings:
        #  base64.b64encode(struct.pack("<5H", 1, 0, 0, 0, 0))
        sample_aggregate_string = "AgBkADIAZABMHQ=="
        aggregate_tuple_expected = (2, 100, 50, 100, 75.0)

        returned_tuple = FileEnterpriseAttrib.to_aggregate_tuple(sample_aggregate_string)

        self.assertEqual(returned_tuple, aggregate_tuple_expected)

    def test_toaggregate_tuple_zerotrust(self):
        aggregate_string_zerotrust = "AQAAAAAAAAAAAA=="

        self.assertEqual(
            (1, 0, 0, 0, 0),
            FileEnterpriseAttrib.to_aggregate_tuple(aggregate_string_zerotrust)
        )
