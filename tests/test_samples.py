from tests.mock_tieserver import MockTieServer
from tests.test_base import *
from tests.test_value_constants import *


class TestSamples(BaseClientTest):
    SAMPLE_FOLDER = str(os.path.dirname(
        os.path.dirname(
            os.path.abspath(__file__)
        )
    ).replace("\\", "/")) + "/sample"

    BASIC_FOLDER = SAMPLE_FOLDER + "/basic"
    ADVANCED_FOLDER = SAMPLE_FOLDER + "/advanced"

    def test_basicfirstref_example(self):
        # Modify sample file to include necessary sample data
        sample_filename = self.BASIC_FOLDER + "/basic_first_ref_example.py"
        temp_sample_file = TempSampleFile(sample_filename)

        target_line = "FILE_MD5 = "
        replacement_line = target_line + "\"" + FILE_NOTEPAD_EXE_HASH_DICT[HashType.MD5] + "\"\n"
        temp_sample_file.write_file_line(
            target_line,
            replacement_line
        )

        target_line = "FILE_SHA1 = "
        replacement_line = target_line + "\"" + FILE_NOTEPAD_EXE_HASH_DICT[HashType.SHA1] + "\"\n"
        temp_sample_file.write_file_line(
            target_line,
            replacement_line
        )

        target_line = "FILE_SHA256 = "
        replacement_line = target_line + "\"" + FILE_NOTEPAD_EXE_HASH_DICT[HashType.SHA256] + "\"\n"
        temp_sample_file.write_file_line(
            target_line,
            replacement_line
        )

        with self.create_client(max_retries=0) as dxl_client:
            # Set up client, and register mock service
            dxl_client.connect()

            with MockTieServer(dxl_client):
                mock_print = BaseClientTest.run_sample(temp_sample_file.temp_file.name)

                for guid in FIRST_REF_AGENT_GUIDS:
                    mock_print.assert_any_call(
                        StringContains(guid)
                    )

                mock_print.assert_any_call(
                    StringDoesNotContain("Error")
                )

            dxl_client.disconnect()

    def test_basicgetrep_example(self):
        # Modify sample file to include necessary sample data
        sample_filename = self.BASIC_FOLDER + "/basic_get_reputation_example.py"

        with self.create_client(max_retries=0) as dxl_client:
            # Set up client, and register mock service
            dxl_client.connect()

            with MockTieServer(dxl_client):
                mock_print = BaseClientTest.run_sample(sample_filename)

                output_string = ""

                for print_call in mock_print.mock_calls:
                    output_string += str(print_call[1])  # Gets text argument for each print call

                self.assertTrue(
                    StringContains('"trustLevel": 99')
                )
                self.assertTrue(
                    StringContains('"createDate": 1451502875')
                )
                self.assertTrue(
                    StringContains('"providerId": 1')
                )
                self.assertTrue(
                    StringContains('"2139285": "72339069014638857"')
                )

                mock_print.assert_any_call(
                    StringDoesNotContain("Error")
                )

            dxl_client.disconnect()

    def test_basicsetrep_example(self):
        # Modify sample file to include necessary sample data
        sample_filename = self.BASIC_FOLDER + "/basic_set_reputation_example.py"
        temp_sample_file = TempSampleFile(sample_filename)

        with self.create_client(max_retries=0) as dxl_client:
            # Set up client, and register mock service
            dxl_client.connect()

            with MockTieServer(dxl_client):
                mock_print = BaseClientTest.run_sample(temp_sample_file.temp_file.name)

                mock_print.assert_any_call(
                    StringContains("Succeeded")
                )

                mock_print.assert_any_call(
                    StringDoesNotContain("Error")
                )

            dxl_client.disconnect()

    def test_basicsetexternalrep_example_abort_due_to_existing_rep(self):
        # Modify sample file to include necessary sample data
        sample_filename = self.BASIC_FOLDER + "/basic_set_external_file_reputation.py"
        temp_sample_file = TempSampleFile(sample_filename)

        target_line = "fileMD5 = "
        replacement_line = target_line + "\"" + FILE_NOTEPAD_EXE_HASH_DICT[HashType.MD5] + "\"\n"
        temp_sample_file.write_file_line(
            target_line,
            replacement_line
        )
        target_line = "fileSHA1 = "
        replacement_line = target_line + "\"" + FILE_NOTEPAD_EXE_HASH_DICT[HashType.SHA1] + "\"\n"
        temp_sample_file.write_file_line(
            target_line,
            replacement_line
        )
        target_line = "fileSHA256 = "
        replacement_line = target_line + "\"" + FILE_NOTEPAD_EXE_HASH_DICT[HashType.SHA256] + "\"\n"
        temp_sample_file.write_file_line(
            target_line,
            replacement_line
        )

        with self.create_client(max_retries=0) as dxl_client:
            # Set up client, and register mock service
            dxl_client.connect()

            with MockTieServer(dxl_client):
                mock_print = BaseClientTest.run_sample(temp_sample_file.temp_file.name)

                mock_print.assert_any_call(
                    StringContains("Abort")
                )

                mock_print.assert_any_call(
                    StringDoesNotContain("Error")
                )

            dxl_client.disconnect()

    def test_basicsetexternalrep_example_succeed(self):

        # Modify sample file to include necessary sample data
        sample_filename = self.BASIC_FOLDER + "/basic_set_external_file_reputation.py"
        temp_sample_file = TempSampleFile(sample_filename)

        target_line = "fileMD5 = "
        replacement_line = target_line + "\"" + FILE_UNKNOWN_HASH_DICT[HashType.MD5] + "\"\n"
        temp_sample_file.write_file_line(
            target_line,
            replacement_line
        )
        target_line = "fileSHA1 = "
        replacement_line = target_line + "\"" + FILE_UNKNOWN_HASH_DICT[HashType.SHA1] + "\"\n"
        temp_sample_file.write_file_line(
            target_line,
            replacement_line
        )
        target_line = "fileSHA256 = "
        replacement_line = target_line + "\"" + FILE_UNKNOWN_HASH_DICT[HashType.SHA256] + "\"\n"
        temp_sample_file.write_file_line(
            target_line,
            replacement_line
        )

        with self.create_client(max_retries=0) as dxl_client:
            # Set up client, and register mock service
            dxl_client.connect()

            with MockTieServer(dxl_client):
                mock_print = BaseClientTest.run_sample(temp_sample_file.temp_file.name)

                mock_print.assert_any_call(
                    StringContains("Event Sent")
                )

                mock_print.assert_any_call(
                    StringDoesNotContain("Error")
                )

            dxl_client.disconnect()

    def test_advancedgetrep_example(self):
        # Modify sample file to include necessary sample data
        sample_filename = self.ADVANCED_FOLDER + "/advanced_get_reputation_example.py"
        temp_sample_file = TempSampleFile(sample_filename)

        target_line = "FILE_MD5 = "
        replacement_line = target_line + "\"" + FILE_NOTEPAD_EXE_HASH_DICT[HashType.MD5] + "\"\n"
        temp_sample_file.write_file_line(
            target=target_line,
            replacement=replacement_line
        )

        target_line = "FILE_SHA1 = "
        replacement_line = target_line + "\"" + FILE_NOTEPAD_EXE_HASH_DICT[HashType.SHA1] + "\"\n"
        temp_sample_file.write_file_line(
            target=target_line,
            replacement=replacement_line
        )

        target_line = "FILE_SHA256 = "
        replacement_line = target_line + "\"" + FILE_NOTEPAD_EXE_HASH_DICT[HashType.SHA256] + "\"\n"
        temp_sample_file.write_file_line(
            target=target_line,
            replacement=replacement_line
        )

        target_line = "CERTIFICATE_BODY_SHA1 = "
        replacement_line = target_line + "\"" + CERT_CERT1_SHA1 + "\"\n"
        temp_sample_file.write_file_line(
            target=target_line,
            replacement=replacement_line
        )

        target_line = "CERTIFICATE_PUBLIC_KEY_SHA1 = "
        replacement_line = target_line + "\"" + CERT_CERT1_PUBLIC_KEY_SHA1 + "\"\n"
        temp_sample_file.write_file_line(
            target=target_line,
            replacement=replacement_line
        )

        with self.create_client(max_retries=0) as dxl_client:
            # Set up client, and register mock service
            dxl_client.connect()

            with MockTieServer(dxl_client):
                mock_print = BaseClientTest.run_sample(temp_sample_file.temp_file.name)

                mock_print.assert_any_call(
                    StringContains(GtiAttrib.ORIGINAL_RESPONSE)
                )

                mock_print.assert_any_call(
                    StringContains(FileEnterpriseAttrib.FIRST_CONTACT)
                )

                mock_print.assert_any_call(
                    StringDoesNotContain("Error")
                )

            dxl_client.disconnect()
