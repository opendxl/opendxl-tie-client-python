import copy
import time
import unittest
from dxlbootstrap.util import MessageUtils
from dxlclient.message import Event
from dxltieclient.callbacks import DetectionCallback, FirstInstanceCallback, \
    ReputationChangeCallback


class TestDetectionCallback(unittest.TestCase):
    def test_on_detection(self):
        class MyDetectionCallback(DetectionCallback):
            def __init__(self):
                super(MyDetectionCallback, self).__init__()
                self.detection_dict_received = None
                self.original_event_received = None

            def on_detection(self, detection_dict, original_event):
                self.detection_dict_received = detection_dict
                self.original_event_received = original_event

        detection_callback = MyDetectionCallback()
        event = Event("/event")
        event_payload_sent = {
            "agentGuid": event.message_id,
            "detectionTime": int(time.time()),
            "hashes": [
                {"type": "md5",
                 "value": "614rncUYF6CG17l+tSQQqw=="},
                {"type": "sha1",
                 "value": "Q139Rw9ydDfHy08Hy6H5ofQnJlY="},
                {"type": "sha256",
                 "value": "QUuxaxDs4tsthEjLnzE/gMt3wxDKDBnuA8c8ugwW/ts="}
            ],
            "localReputation": 1,
            "name": "FOCUS_MALWARE2.EXE",
            "remediationAction": 5
        }
        expected_payload_received = event_payload_sent.copy()
        expected_payload_received["hashes"] = {
            "md5": "eb5e2b9dc51817a086d7b97eb52410ab",
            "sha1": "435dfd470f727437c7cb4f07cba1f9a1f4272656",
            "sha256": "414bb16b10ece2db2d8448cb9f313f80cb77c310ca0c19ee03c73cba0c16fedb"
        }
        MessageUtils.dict_to_json_payload(event, event_payload_sent)
        detection_callback.on_event(event)
        self.assertEqual(expected_payload_received,
                         detection_callback.detection_dict_received)
        self.assertEqual(event, detection_callback.original_event_received)


class TestFirstInstanceCallback(unittest.TestCase):
    def test_on_first_instance(self):
        class MyFirstInstanceCallback(FirstInstanceCallback):
            def __init__(self):
                super(MyFirstInstanceCallback, self).__init__()
                self.first_instance_dict_received = None
                self.original_event_received = None

            def on_first_instance(self, first_instance_dict, original_event):
                self.first_instance_dict_received = first_instance_dict
                self.original_event_received = original_event

        first_instance_callback = MyFirstInstanceCallback()
        event = Event("/event")
        event_payload_sent = {
            "agentGuid": event.message_id,
            "hashes": [
                {"type": "md5",
                 "value": "MdvozEQ9LKf9I2rAClL7Fw=="},
                {"type": "sha1",
                 "value": "LWykUGG3lyMS4A5ZM/3/lbuQths="},
                {"type": "sha256",
                 "value": "qjxGHUwho5LjctDWykzrHk2ICY1YdllFTq9Nk8ZhiA8="}
            ],
            "name": "MORPH.EXE"
        }
        expected_payload_received = event_payload_sent.copy()
        expected_payload_received["hashes"] = {
            "md5": "31dbe8cc443d2ca7fd236ac00a52fb17",
            "sha1": "2d6ca45061b7972312e00e5933fdff95bb90b61b",
            "sha256": "aa3c461d4c21a392e372d0d6ca4ceb1e4d88098d587659454eaf4d93c661880f"
        }
        MessageUtils.dict_to_json_payload(event, event_payload_sent)
        first_instance_callback.on_event(event)
        self.assertEqual(
            expected_payload_received,
            first_instance_callback.first_instance_dict_received)
        self.assertEqual(event, first_instance_callback.original_event_received)


class TestReputationChangeCallback(unittest.TestCase):
    def test_on_reputation_change(self):
        class MyReputationChangeCallback(ReputationChangeCallback):
            def __init__(self):
                super(MyReputationChangeCallback, self).__init__()
                self.rep_change_dict_received = None
                self.original_event_received = None

            def on_reputation_change(self, rep_change_dict, original_event):
                self.rep_change_dict_received = rep_change_dict
                self.original_event_received = original_event

        reputation_change_callback = MyReputationChangeCallback()
        event = Event("/event")
        event_payload_sent = {
            "hashes": [
                {"type": "md5",
                 "value": "8se7isyX+S6Yei1Ah9AhsQ=="},
                {"type": "sha1",
                 "value": "frATnSF1c5s8yw0REAZ4IL5qvSk="},
                {"type": "sha256",
                 "value": "FC4daI7wVoNww3GH/Z8jUdfd7aV0+L+psPpO9C24WqI="}
            ],
            "publicKeySha1": "3B87A2D6F39770160364B79A152FCC73BAE27ADF",
            "newReputations": [
                {
                    "attributes": {
                        "2120340": "2139160704"
                    },
                    "createDate": 1480455704,
                    "providerId": 1,
                    "trustLevel": 99
                },
                {
                    "attributes": {
                        "2101652": "235",
                        "2102165": "1476902802",
                        "2111893": "244",
                        "2114965": "4",
                        "2139285": "73183493944770750"
                    },
                    "createDate": 1476902802,
                    "providerId": 3,
                    "trustLevel": 99
                }
            ],
            "oldReputations": [
                {
                    "attributes": {
                        "2120340": "2139160704"
                    },
                    "createDate": 1480455704,
                    "providerId": 1,
                    "trustLevel": 99
                },
                {
                    "attributes": {
                        "2101652": "235",
                        "2102165": "1476902802",
                        "2111893": "244",
                        "2114965": "4",
                        "2139285": "73183493944770750"
                    },
                    "createDate": 1476902802,
                    "providerId": 3,
                    "trustLevel": 85
                }
            ],
            "relationships": {
                "certificate": {
                    "hashes": [
                        {"type": "md5",
                         "value": "MdvozEQ9LKf9I2rAClL7Fw=="},
                        {"type": "sha1",
                         "value": "LWykUGG3lyMS4A5ZM/3/lbuQths="},
                        {"type": "sha256",
                         "value": "qjxGHUwho5LjctDWykzrHk2ICY1YdllFTq9Nk8ZhiA8="}
                    ],
                    "publicKeySha1": "Q139Rw9ydDfHy08Hy6H5ofQnJlY="
                }
            }
        }
        expected_payload_received = copy.deepcopy(event_payload_sent)
        expected_payload_received["hashes"] = {
            "md5": "f2c7bb8acc97f92e987a2d4087d021b1",
            "sha1": "7eb0139d2175739b3ccb0d1110067820be6abd29",
            "sha256": "142e1d688ef0568370c37187fd9f2351d7ddeda574f8bfa9b0fa4ef42db85aa2"
        }
        expected_payload_received["publicKeySha1"] = \
            "dc1f3b0360fa177f7bef4d7ad37eb807bf40d79d85082ef7040136ec00c5"
        expected_cert_info_received = expected_payload_received["relationships"]\
            ["certificate"]
        expected_cert_info_received["hashes"] = \
            {
                "md5": "31dbe8cc443d2ca7fd236ac00a52fb17",
                "sha1": "2d6ca45061b7972312e00e5933fdff95bb90b61b",
                "sha256":
                    "aa3c461d4c21a392e372d0d6ca4ceb1e4d88098d587659454eaf4d93c661880f"
            }
        expected_cert_info_received["publicKeySha1"] = \
            "435dfd470f727437c7cb4f07cba1f9a1f4272656"
        MessageUtils.dict_to_json_payload(event, event_payload_sent)
        reputation_change_callback.on_event(event)
        self.assertEqual(
            expected_payload_received,
            reputation_change_callback.rep_change_dict_received)
        self.assertEqual(event,
                         reputation_change_callback.original_event_received)
