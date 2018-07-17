from dxltieclient import *
from tests.test_base import BaseClientTest
from tests.test_value_constants import *
from tests.mock_tieserver import MockTieServer

class JsonDumpCallback(DetectionCallback):

    def on_detection(self, detection_dict, original_event):
        pass


class TestSubscribeUnsubscribe(BaseClientTest):

    def test_subscribeunsubscribe(self):

        file_reputation_change_topic = "/mcafee/event/tie/file/repchange/broadcast"
        cert_reputation_change_topic = "/mcafee/event/tie/cert/repchange/broadcast"
        file_detection_topic = "/mcafee/event/tie/file/detection"
        file_first_instance_topic = "/mcafee/event/tie/file/firstinstance"
        #TIE_EVENT_FILE_PREVALENCE_CHANGE_TOPIC = "/mcafee/event/tie/file/prevalence"

        with self.create_client(max_retries=0) as dxl_client:
            tie_client = TieClient(dxl_client)
            dxl_client.connect()

            # Event Callbacks
            # Create detection callback, register detection callback with the client
            detection_callback = JsonDumpCallback()

            # Subscribe to all Event topics
            tie_client.add_file_reputation_change_callback(detection_callback)
            tie_client.add_certificate_reputation_change_callback(detection_callback)
            tie_client.add_file_first_instance_callback(detection_callback)
            tie_client.add_file_detection_callback(detection_callback)

            self.assertIn(file_reputation_change_topic, dxl_client.subscriptions)
            self.assertIn(cert_reputation_change_topic, dxl_client.subscriptions)
            self.assertIn(file_first_instance_topic, dxl_client.subscriptions)
            self.assertIn(file_detection_topic, dxl_client.subscriptions)
            #self.assertIn(TIE_EVENT_FILE_PREVALENCE_CHANGE_TOPIC, dxl_client.subscriptions)

            # Unsubscribe from Event Topics
            tie_client.remove_file_reputation_change_callback(detection_callback)
            tie_client.remove_certificate_reputation_change_callback(detection_callback)
            tie_client.remove_file_first_instance_callback(detection_callback)
            tie_client.remove_file_detection_callback(detection_callback)

            self.assertNotIn(file_reputation_change_topic, dxl_client.subscriptions)
            self.assertNotIn(cert_reputation_change_topic, dxl_client.subscriptions)
            self.assertNotIn(file_first_instance_topic, dxl_client.subscriptions)
            self.assertNotIn(file_detection_topic, dxl_client.subscriptions)
            #self.assertIn(TIE_EVENT_FILE_PREVALENCE_CHANGE_TOPIC, dxl_client.subscriptions)

            dxl_client.disconnect()


class TestGetFileReputation(BaseClientTest):

    def test_getfilerep(self):
        with self.create_client(max_retries=0) as dxl_client:
            # Set up client, and register mock service
            tie_client = TieClient(dxl_client)
            dxl_client.connect()
            with MockTieServer(dxl_client):

                # Notepad.exe reputations
                reputations_dict = \
                    tie_client.get_file_reputation(FILE_NOTEPAD_EXE_HASH_DICT)

                self.assertEqual(
                    reputations_dict[FileProvider.GTI][ReputationProp.TRUST_LEVEL],
                    TrustLevel.KNOWN_TRUSTED
                )
                self.assertEqual(
                    reputations_dict[FileProvider.ENTERPRISE][ReputationProp.TRUST_LEVEL],
                    TrustLevel.NOT_SET
                )

                # EICAR reputations
                reputations_dict = \
                    tie_client.get_file_reputation(FILE_EICAR_HASH_DICT)

                self.assertEqual(
                    reputations_dict[FileProvider.GTI][ReputationProp.TRUST_LEVEL],
                    TrustLevel.KNOWN_MALICIOUS
                )
                self.assertEqual(
                    reputations_dict[FileProvider.ENTERPRISE][ReputationProp.TRUST_LEVEL],
                    TrustLevel.NOT_SET
                )

            dxl_client.disconnect()


    def test_getfilerep_invalid(self):
        with self.create_client(max_retries=0) as dxl_client:
            # Set up client, and register mock service
            tie_client = TieClient(dxl_client)
            dxl_client.connect()
            with MockTieServer(dxl_client):
                self.assertRaisesRegex(
                    Exception,
                    r"Error: Could not find reputation \(0\)",
                    tie_client.get_file_reputation,
                    FILE_INVALID_HASH_DICT
                )

            dxl_client.disconnect()


class TestSetFileReputation(BaseClientTest):

    def test_setfilerep(self):

        file_notepad_exe_filename = "notepad.exe"

        with self.create_client(max_retries=0) as dxl_client:
            # Set up client, and register mock service
            tie_client = TieClient(dxl_client)
            dxl_client.connect()
            with MockTieServer(dxl_client):
                # Set Notepad.exe reputations
                # Set the Enterprise reputation for notepad.exe to Most Likely Trusted
                tie_client.set_file_reputation(
                    TrustLevel.MOST_LIKELY_TRUSTED,
                    FILE_NOTEPAD_EXE_HASH_DICT,
                    filename=file_notepad_exe_filename,
                    comment=SET_REP_COMMENT
                )

                # Get Notepad.exe reputations
                reputations_dict = \
                    tie_client.get_file_reputation(FILE_NOTEPAD_EXE_HASH_DICT)

                self.assertEqual(
                    reputations_dict[FileProvider.ENTERPRISE][ReputationProp.TRUST_LEVEL],
                    TrustLevel.MOST_LIKELY_TRUSTED
                )

            dxl_client.disconnect()


class TestGetCertReputation(BaseClientTest):

    def test_getcertrep(self):
        with self.create_client(max_retries=0) as dxl_client:
            # Set up client, and register mock service
            tie_client = TieClient(dxl_client)
            dxl_client.connect()
            with MockTieServer(dxl_client):
                # cert1 reputations
                reputations_dict = \
                    tie_client.get_certificate_reputation(
                        CERT_CERT1_SHA1,
                        CERT_CERT1_PUBLIC_KEY_SHA1
                    )

                self.assertEqual(
                    reputations_dict[CertProvider.GTI][ReputationProp.TRUST_LEVEL],
                    TrustLevel.KNOWN_TRUSTED
                )
                self.assertEqual(
                    reputations_dict[CertProvider.ENTERPRISE][ReputationProp.TRUST_LEVEL],
                    TrustLevel.NOT_SET
                )

            dxl_client.disconnect()


    def test_getcertrep_invalid(self):
        with self.create_client(max_retries=0) as dxl_client:
            # Set up client, and register mock service
            tie_client = TieClient(dxl_client)
            dxl_client.connect()
            with MockTieServer(dxl_client):
                self.assertRaisesRegex(
                    Exception,
                    r"Error: Could not find reputation \(0\)",
                    tie_client.get_certificate_reputation,
                    CERT_INVALID_SHA1,
                    CERT_INVALID_SHA1
                )

            dxl_client.disconnect()


class TestSetCertReputation(BaseClientTest):

    def test_setcertrep(self):
        with self.create_client(max_retries=0) as dxl_client:
            # Set up client, and register mock service
            tie_client = TieClient(dxl_client)
            dxl_client.connect()
            with MockTieServer(dxl_client):
                # Set cert1 reputations
                # Set the Enterprise reputation for cert1 to Most Likely Trusted
                reputations_dict = \
                    tie_client.set_certificate_reputation(
                        trust_level=TrustLevel.MOST_LIKELY_TRUSTED,
                        sha1=CERT_CERT1_SHA1,
                        public_key_sha1=CERT_CERT1_PUBLIC_KEY_SHA1,
                        comment=SET_REP_COMMENT
                    )

                # Get cert1 reputations
                reputations_dict = \
                    tie_client.get_certificate_reputation(
                        CERT_CERT1_SHA1,
                        CERT_CERT1_PUBLIC_KEY_SHA1
                    )

                self.assertEqual(
                    reputations_dict[CertProvider.ENTERPRISE][ReputationProp.TRUST_LEVEL],
                    TrustLevel.MOST_LIKELY_TRUSTED
                )

            dxl_client.disconnect()


class TestGetFileFirstReference(BaseClientTest):

    def test_getfilefirstrefs(self):
        with self.create_client(max_retries=0) as dxl_client:
            # Set up client, and register mock service
            tie_client = TieClient(dxl_client)
            dxl_client.connect()
            with MockTieServer(dxl_client):
                # Notepad.exe reputations
                systems_list = \
                    tie_client.get_file_first_references(FILE_NOTEPAD_EXE_HASH_DICT)

                for system in systems_list:
                    self.assertIn(system[FirstRefProp.SYSTEM_GUID], FIRST_REF_AGENT_GUIDS)

            dxl_client.disconnect()


    def test_getfilefirstrefs_invalid(self):
        with self.create_client(max_retries=0) as dxl_client:
            # Set up client, and register mock service
            tie_client = TieClient(dxl_client)
            dxl_client.connect()
            with MockTieServer(dxl_client):
                self.assertRaisesRegex(
                    Exception,
                    r"Error: Could not find reputation \(0\)",
                    tie_client.get_file_first_references,
                    FILE_INVALID_HASH_DICT
                )

            dxl_client.disconnect()


class TestGetCertFirstReference(BaseClientTest):

    def test_getcertfirstrefs(self):
        with self.create_client(max_retries=0) as dxl_client:
            # Set up client, and register mock service
            tie_client = TieClient(dxl_client)
            dxl_client.connect()
            with MockTieServer(dxl_client):
                systems_list = \
                    tie_client.get_certificate_first_references(
                        CERT_CERT1_SHA1,
                        CERT_CERT1_PUBLIC_KEY_SHA1
                    )

                for system in systems_list:
                    self.assertIn(system[FirstRefProp.SYSTEM_GUID], FIRST_REF_AGENT_GUIDS)

            dxl_client.disconnect()


    def test_getcertfirstrefs_invalid(self):
        with self.create_client(max_retries=0) as dxl_client:
            # Set up client, and register mock service
            tie_client = TieClient(dxl_client)
            dxl_client.connect()
            with MockTieServer(dxl_client):
                self.assertRaisesRegex(
                    Exception,
                    r"Error: Could not find reputation \(0\)",
                    tie_client.get_certificate_first_references,
                    CERT_INVALID_SHA1,
                    CERT_INVALID_SHA1
                )

            dxl_client.disconnect()


class TestBase64toHex(BaseClientTest):

    def test_base64tohex(self):
        test_string_base64_input = "test"
        test_string_base64_expected = "74657374"

        # Tests in here
        test_base64string = base64.b64encode(test_string_base64_input.encode('utf-8'))

        expected_hex_string = test_string_base64_expected
        test_hex_string = TieClient._base64_to_hex(test_base64string)

        self.assertEqual(test_hex_string, expected_hex_string)


class TestTransforms(BaseClientTest):

    def test_transformhashes(self):
        notepad_hashes_payload_expected = \
            {
                HashType.SHA256: FILE_NOTEPAD_EXE_HASH_DICT[HashType.SHA256],
                HashType.SHA1: FILE_NOTEPAD_EXE_HASH_DICT[HashType.SHA1],
                HashType.MD5: FILE_NOTEPAD_EXE_HASH_DICT[HashType.MD5]
            }

        # Tests in here
        transformed_hashes = TieClient._transform_hashes(SAMPLE_NOTEPAD_HASHES_PAYLOAD_DICT)

        self.assertDictEqual(transformed_hashes, notepad_hashes_payload_expected)


    def test_transformreps(self):
        payload_reps_dict_input = [
            {
                ReputationProp.ATTRIBUTES: {
                    CertGtiAttrib.PREVALENCE: "94",
                    CertGtiAttrib.FIRST_CONTACT: "1454912619",
                    CertGtiAttrib.REVOKED: "0",
                    "2120596": "0"
                },
                ReputationProp.CREATE_DATE: 1476318514,
                ReputationProp.PROVIDER_ID: CertProvider.GTI,
                ReputationProp.TRUST_LEVEL: TrustLevel.KNOWN_TRUSTED
            },
            {
                ReputationProp.ATTRIBUTES: {
                    CertEnterpriseAttrib.PREVALENCE: "12",
                    CertEnterpriseAttrib.FIRST_CONTACT: "1476318514",
                    EnterpriseAttrib.SERVER_VERSION: SAMPLE_ENTERPRISE_VERSION
                },
                ReputationProp.CREATE_DATE: 1476318514,
                ReputationProp.PROVIDER_ID: CertProvider.ENTERPRISE,
                ReputationProp.TRUST_LEVEL: TrustLevel.NOT_SET,
                }
        ]

        payload_reps_dict_expected = {
            CertProvider.GTI: {
                ReputationProp.ATTRIBUTES: {
                    CertGtiAttrib.PREVALENCE: "94",
                    CertGtiAttrib.FIRST_CONTACT: "1454912619",
                    CertGtiAttrib.REVOKED: "0",
                    "2120596": "0"
                },
                ReputationProp.CREATE_DATE: 1476318514,
                ReputationProp.PROVIDER_ID: CertProvider.GTI,
                ReputationProp.TRUST_LEVEL: TrustLevel.KNOWN_TRUSTED
            },
            CertProvider.ENTERPRISE: {
                ReputationProp.ATTRIBUTES: {
                    CertEnterpriseAttrib.PREVALENCE: "12",
                    CertEnterpriseAttrib.FIRST_CONTACT: "1476318514",
                    EnterpriseAttrib.SERVER_VERSION: SAMPLE_ENTERPRISE_VERSION
                },
                ReputationProp.CREATE_DATE: 1476318514,
                ReputationProp.PROVIDER_ID: CertProvider.ENTERPRISE,
                ReputationProp.TRUST_LEVEL: TrustLevel.NOT_SET,
                }
        }

        transformed_reps = TieClient._transform_reputations(payload_reps_dict_input)

        self.assertDictEqual(transformed_reps, payload_reps_dict_expected)


    def test_transformreps_withoverrides(self):
        payload_reps_dict_input_or = [
            {
                ReputationProp.ATTRIBUTES: {
                    CertGtiAttrib.PREVALENCE: "94",
                    CertGtiAttrib.FIRST_CONTACT: "1454912619",
                    CertGtiAttrib.REVOKED: "0",
                    "2120596": "0"
                },
                ReputationProp.CREATE_DATE: 1476318514,
                ReputationProp.PROVIDER_ID: CertProvider.GTI,
                ReputationProp.TRUST_LEVEL: TrustLevel.KNOWN_TRUSTED
            },
            {
                ReputationProp.ATTRIBUTES: {
                    CertEnterpriseAttrib.PREVALENCE: "12",
                    CertEnterpriseAttrib.FIRST_CONTACT: "1476318514",
                    EnterpriseAttrib.SERVER_VERSION: SAMPLE_ENTERPRISE_VERSION
                },
                ReputationProp.CREATE_DATE: 1476318514,
                ReputationProp.PROVIDER_ID: CertProvider.ENTERPRISE,
                ReputationProp.TRUST_LEVEL: TrustLevel.NOT_SET,
                CertReputationProp.OVERRIDDEN: {
                    CertReputationOverriddenProp.FILES: [
                        {
                            RepChangeEventProp.HASHES: SAMPLE_NOTEPAD_HASHES_PAYLOAD_DICT
                        }
                    ]
                }
            }
        ]

        payload_reps_dict_expected_or = {
            CertProvider.GTI: {
                ReputationProp.ATTRIBUTES: {
                    CertGtiAttrib.PREVALENCE: "94",
                    CertGtiAttrib.FIRST_CONTACT: "1454912619",
                    CertGtiAttrib.REVOKED: "0",
                    "2120596": "0"
                },
                ReputationProp.CREATE_DATE: 1476318514,
                ReputationProp.PROVIDER_ID: CertProvider.GTI,
                ReputationProp.TRUST_LEVEL: TrustLevel.KNOWN_TRUSTED
            },
            CertProvider.ENTERPRISE: {
                ReputationProp.ATTRIBUTES: {
                    CertEnterpriseAttrib.PREVALENCE: "12",
                    CertEnterpriseAttrib.FIRST_CONTACT: "1476318514",
                    EnterpriseAttrib.SERVER_VERSION: SAMPLE_ENTERPRISE_VERSION
                },
                ReputationProp.CREATE_DATE: 1476318514,
                ReputationProp.PROVIDER_ID: CertProvider.ENTERPRISE,
                ReputationProp.TRUST_LEVEL: TrustLevel.NOT_SET,
                CertReputationProp.OVERRIDDEN: {
                    CertReputationOverriddenProp.FILES:[
                        {
                            RepChangeEventProp.HASHES: FILE_NOTEPAD_EXE_HASH_DICT
                        }
                    ]
                }
            }
        }

        transformed_reps = TieClient._transform_reputations(payload_reps_dict_input_or)

        self.assertDictEqual(transformed_reps, payload_reps_dict_expected_or)
