"""
Unit tests for dxltieclient built-in callbacks
"""

import json

from unittest import TestCase
from dxlclient import Event
from dxltieclient.callbacks import *
from tests.test_value_constants import *

class TestReputationChangeCallback(TestCase):

    def test_repchangecallback(self):

        class MyReputationChangeCallback(ReputationChangeCallback):

            def __init__(self):
                super(MyReputationChangeCallback, self).__init__()
                self.rep_change_dict_received = {}
                self.original_event_received = None

            def on_reputation_change(self, rep_change_dict, original_event):
                self.rep_change_dict_received = rep_change_dict
                self.original_event_received = original_event

        rep_change_event_payload = {
            RepChangeEventProp.OLD_REPUTATIONS:{
                "reputations":[
                    {
                        ReputationProp.TRUST_LEVEL: TrustLevel.NOT_SET,
                        ReputationProp.PROVIDER_ID: FileProvider.ENTERPRISE,
                        ReputationProp.CREATE_DATE: 1409783001,
                        ReputationProp.ATTRIBUTES:{
                            "2098277":"256",
                            }
                    },
                    {
                        ReputationProp.TRUST_LEVEL: TrustLevel.KNOWN_TRUSTED,
                        ReputationProp.PROVIDER_ID: FileProvider.GTI,
                        ReputationProp.CREATE_DATE: 1409783001,
                        ReputationProp.ATTRIBUTES:{
                            GtiAttrib.ORIGINAL_RESPONSE:"2139160704"
                        }
                    }
                ],
                "props":{
                    "serverTime":1409851328
                }
            },
            RepChangeEventProp.NEW_REPUTATIONS:{
                "reputations":[
                    {
                        ReputationProp.TRUST_LEVEL: TrustLevel.MOST_LIKELY_TRUSTED,
                        ReputationProp.PROVIDER_ID: FileProvider.ENTERPRISE,
                        ReputationProp.CREATE_DATE: 1409783001,
                        ReputationProp.ATTRIBUTES:{
                            "2098277":"256",
                            }
                    },
                    {
                        ReputationProp.TRUST_LEVEL: TrustLevel.KNOWN_TRUSTED,
                        ReputationProp.PROVIDER_ID: FileProvider.GTI,
                        ReputationProp.CREATE_DATE: 1409783001,
                        ReputationProp.ATTRIBUTES:{
                            GtiAttrib.ORIGINAL_RESPONSE:"2139160704"
                        }
                    }
                ],
                "props":{
                    "serverTime":1409851328
                }
            },
            FileRepChangeEventProp.RELATIONSHIPS: {
                "certificate": {
                    RepChangeEventProp.HASHES: [
                        {
                            "value": "rB/QkipKKm5XeazdYodHwoOUsLk=",
                            "type": HashType.SHA1
                        }
                    ],
                    "publicKeySha1": "Q139Rw9ydDfHy08Hy6H5ofQnJlY="
                }
            },
            RepChangeEventProp.HASHES:[
                {
                    "type":HashType.MD5,
                    "value":"bQvLG6j1WmwRB8LZ2gPa1w=="
                },
                {
                    "type":HashType.SHA1,
                    "value":"OxbrjQd0H6+3meBW5YuBoInTcqM="
                },
                {
                    "type":HashType.SHA256,
                    "value":"yXfKH1ESH+5YzaiIJ6YXOtTx1y2AJihOTE9EMCqWfkA="
                }
            ],
            RepChangeEventProp.UPDATE_TIME:1409851328
        }

        rep_change_expected = {
            RepChangeEventProp.NEW_REPUTATIONS: {
                FileProvider.GTI: {
                    ReputationProp.ATTRIBUTES: {
                        GtiAttrib.ORIGINAL_RESPONSE: "2139160704"
                    },
                    ReputationProp.TRUST_LEVEL: TrustLevel.KNOWN_TRUSTED,
                    ReputationProp.CREATE_DATE: 1409783001,
                    ReputationProp.PROVIDER_ID: FileProvider.GTI
                },
                FileProvider.ENTERPRISE: {
                    ReputationProp.ATTRIBUTES: {
                        "2098277": "256"
                    },
                    ReputationProp.TRUST_LEVEL: TrustLevel.MOST_LIKELY_TRUSTED,
                    ReputationProp.CREATE_DATE: 1409783001,
                    ReputationProp.PROVIDER_ID: FileProvider.ENTERPRISE
                }
            },
            FileRepChangeEventProp.RELATIONSHIPS: {
                "certificate": {
                    RepChangeEventProp.HASHES: {
                        HashType.SHA1: "ac1fd0922a4a2a6e5779acdd628747c28394b0b9"
                    },
                    "publicKeySha1": "435dfd470f727437c7cb4f07cba1f9a1f4272656"
                }
            },
            RepChangeEventProp.HASHES: {
                HashType.SHA256: "c977ca1f51121fee58cda88827a6173ad4f1d72d8026284e4c4f44302a967e40",
                HashType.SHA1: "3b16eb8d07741fafb799e056e58b81a089d372a3",
                HashType.MD5: "6d0bcb1ba8f55a6c1107c2d9da03dad7"
            },
            RepChangeEventProp.UPDATE_TIME: 1409851328,
            RepChangeEventProp.OLD_REPUTATIONS: {
                FileProvider.GTI: {
                    ReputationProp.ATTRIBUTES: {
                        GtiAttrib.ORIGINAL_RESPONSE: "2139160704"
                    },
                    ReputationProp.TRUST_LEVEL: TrustLevel.KNOWN_TRUSTED,
                    ReputationProp.CREATE_DATE: 1409783001,
                    ReputationProp.PROVIDER_ID: FileProvider.GTI
                },
                FileProvider.ENTERPRISE: {
                    ReputationProp.ATTRIBUTES: {
                        "2098277": "256"
                    },
                    ReputationProp.TRUST_LEVEL: TrustLevel.NOT_SET,
                    ReputationProp.CREATE_DATE: 1409783001,
                    ReputationProp.PROVIDER_ID: FileProvider.ENTERPRISE
                }
            }
        }

        test_event = Event(TEST_TOPIC)

        # Set the payload
        test_event.payload = json.dumps(rep_change_event_payload)\
            .encode(encoding="UTF-8")

        rep_change_callback = MyReputationChangeCallback()

        rep_change_callback.on_event(test_event)

        self.assertDictEqual(
            rep_change_callback.rep_change_dict_received,
            rep_change_expected
        )
        self.assertEqual(
            rep_change_callback.original_event_received,
            test_event
        )


class TestDetectionCallback(TestCase):

    def test_detectioncallback(self):

        class MyDetectionCallback(DetectionCallback):

            def __init__(self):
                super(MyDetectionCallback, self).__init__()
                self.detection_dict_received = None
                self.original_event_received = None

            def on_detection(self, detection_dict, original_event):
                self.detection_dict_received = detection_dict
                self.original_event_received = original_event

        detect_event_payload = {
            RepChangeEventProp.HASHES:[
                {
                    "value":"CZnbhOFq32TBWnuAOUhLMw==",
                    "type":HashType.MD5
                },
                {
                    "value":"7vZcAfgW1DgH2WrHY5A3h14Fbks=",
                    "type":HashType.SHA1
                },
                {
                    "type":HashType.SHA256,
                    "value":"yXfKH1ESH+5YzaiIJ6YXOtTx1y2AJihOTE9EMCqWfkA="
                }
            ],
            DetectionEventProp.SYSTEM_GUID:"{abc5d2c6-e959-11e3-baeb-005056c00009}",
            DetectionEventProp.REMEDIATION_ACTION:5,
            DetectionEventProp.LOCAL_REPUTATION:1,
            DetectionEventProp.DETECTION_TIME:1402617156
        }

        detect_expected = {
            DetectionEventProp.REMEDIATION_ACTION: 5,
            DetectionEventProp.SYSTEM_GUID: u"{abc5d2c6-e959-11e3-baeb-005056c00009}",
            RepChangeEventProp.HASHES: {
                HashType.SHA256: "c977ca1f51121fee58cda88827a6173ad4f1d72d8026284e4c4f44302a967e40",
                HashType.SHA1: "eef65c01f816d43807d96ac7639037875e056e4b",
                HashType.MD5: "0999db84e16adf64c15a7b8039484b33"
            },
            DetectionEventProp.LOCAL_REPUTATION: 1,
            DetectionEventProp.DETECTION_TIME: 1402617156
        }

        test_event = Event(TEST_TOPIC)

        # Set the payload
        test_event.payload = json.dumps(detect_event_payload)\
            .encode(encoding="UTF-8")

        detection_callback = MyDetectionCallback()

        detection_callback.on_event(test_event)

        self.assertDictEqual(
            detection_callback.detection_dict_received,
            detect_expected
        )
        self.assertEqual(
            detection_callback.original_event_received,
            test_event
        )


class TestFirstInstanceCallback(TestCase):

    def test_firstinstancecallback(self):

        class MyFirstInstanceCallback(FirstInstanceCallback):

            def __init__(self):
                super(MyFirstInstanceCallback, self).__init__()
                self.first_instance_dict_received = None
                self.original_event_received = None

            def on_first_instance(self, first_instance_dict, original_event):
                self.first_instance_dict_received = first_instance_dict
                self.original_event_received = original_event

        first_instance_event_payload = {
            RepChangeEventProp.HASHES:[
                {
                    "type":HashType.SHA1,
                    "value":"LWykUGG3lyMS4A5ZM/3/lbuQths="
                },
                {
                    "type":HashType.MD5,
                    "value":"MdvozEQ9LKf9I2rAClL7Fw=="
                },
                {
                    "type":HashType.SHA256,
                    "value":"qjxGHUwho5LjctDWykzrHk2ICY1YdllFTq9Nk8ZhiA8="
                }
            ],
            DetectionEventProp.SYSTEM_GUID:"testGuid",
            DetectionEventProp.NAME:"MORPH.EXE"
        }

        first_instance_expected = {
            DetectionEventProp.SYSTEM_GUID: "testGuid",
            RepChangeEventProp.HASHES: {
                HashType.SHA256: "aa3c461d4c21a392e372d0d6ca4ceb1e4d88098d587659454eaf4d93c661880f",
                HashType.SHA1: "2d6ca45061b7972312e00e5933fdff95bb90b61b",
                HashType.MD5: "31dbe8cc443d2ca7fd236ac00a52fb17"
            },
            DetectionEventProp.NAME:"MORPH.EXE"
        }

        test_event = Event(TEST_TOPIC)

        # Set the payload
        test_event.payload = json.dumps(first_instance_event_payload)\
            .encode(encoding="UTF-8")

        first_instance_callback = MyFirstInstanceCallback()

        first_instance_callback.on_event(test_event)

        self.assertIn("MORPH.EXE", str(test_event.payload))

        self.assertDictEqual(
            first_instance_callback.first_instance_dict_received,
            first_instance_expected
        )
        self.assertEqual(
            first_instance_callback.original_event_received,
            test_event
        )
