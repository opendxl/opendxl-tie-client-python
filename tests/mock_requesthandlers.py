import copy
import time

from dxlclient.callbacks import RequestCallback
from dxlclient.message import Event, Response, ErrorResponse
from dxlbootstrap.util import MessageUtils

import dxltieclient.client

class FakeTieServerCallback(RequestCallback):
    """
    'fake_tie_file_reputation' request handler registered with topic
    '/mcafee/service/tie/file/reputation'
    """

    TEST_CERT_NAME = "cert1"

    REPUTATION_METADATA = {
        "notepad.exe": {
            "agents": [
                {
                    "agentGuid": "{3a6f574a-3e6f-436d-acd4-bcde336b054d}",
                    "date": 1475873692
                },
                {
                    "agentGuid": "{d48d3d1a-915e-11e6-323a-000c2992f5d9}",
                    "date": 1476316674
                },
                {
                    "agentGuid": "{68125cd6-a5d8-11e6-348e-000c29663178}",
                    "date": 1478626172
                }
            ],
            "hashes": {
                "md5": "8se7isyX+S6Yei1Ah9AhsQ==",
                "sha1": "frATnSF1c5s8yw0REAZ4IL5qvSk=",
                "sha256": "FC4daI7wVoNww3GH/Z8jUdfd7aV0+L+psPpO9C24WqI="
            },
            "reputations": [
                {
                    "attributes": {
                        "2120340": "2139160704"
                    },
                    "createDate": 1451502875,
                    "providerId": 1,
                    "trustLevel": 99
                },
                {
                    "attributes": {
                        "2101652": "17",
                        "2102165": "1451502875",
                        "2111893": "21",
                        "2114965": "0",
                        "2139285": "72339069014638857"
                    },
                    "createDate": 1451502875,
                    "providerId": 3,
                    "trustLevel": 0
                }
            ]
        },
        "EICAR": {
            "hashes": {
                "md5": "RNiGEv6oqPNt6C4SeKuwLw==",
                "sha1": "M5WFbOgfK3OC3ucmAveYtkLxQUA=",
                "sha256": "J1oCG7+2SJ5U1HGJn3250WY/xpXsL+KixFOKq/ZR/Q8="
            },
            "reputations": [
                {
                    "attributes": {
                        "2120340": "2139162632"
                    },
                    "createDate": 1451504331,
                    "providerId": 1,
                    "trustLevel": 1
                },
                {
                    "attributes": {
                        "2101652": "11",
                        "2102165": "1451504331",
                        "2111893": "22",
                        "2114965": "0",
                        "2139285": "72339069014638857"
                    },
                    "createDate": 1451504331,
                    "providerId": 3,
                    "trustLevel": 0
                }
            ]
        },
        TEST_CERT_NAME: {
            "agents": [
                {
                    "agentGuid": "{3a6f574a-3e6f-436d-acd4-bcde336b054d}",
                    "date": 1475873692
                },
                {
                    "agentGuid": "{d48d3d1a-915e-11e6-323a-000c2992f5d9}",
                    "date": 1476316674
                },
                {
                    "agentGuid": "{68125cd6-a5d8-11e6-348e-000c29663178}",
                    "date": 1478626172
                }
            ],
            # hashes based on raw text of 'cert1' and 'cert1publickey'
            # https://www.online-convert.com
            "hashes": {
                "sha1": "tbs4I8YPTz/alN7LUkbtz7Em8K0=",
                "publicKeySha1": "r1W/EdmDdcvulhvXHAj0e8GqGTc="
            },
            "reputations": [
                {
                    "attributes": {
                        "2108821": "94",
                        "2109077": "1454912619",
                        "2117524": "0",
                        "2120596": "0"
                    },
                    "createDate": 1476318514,
                    "providerId": 2,
                    "trustLevel": 99
                },
                {
                    "attributes": {
                        "2109333": "12",
                        "2109589": "1476318514",
                        "2139285": "73183493944770750"
                    },
                    "createDate": 1476318514,
                    "providerId": 4,
                    "trustLevel": 0
                }
            ]
        }
    }

    def _set_hash_algos_for_item(self, item_name, hashes):
        for hash_type, hash_value in hashes.items():
            if hash_type not in self.hash_algos_to_files:
                self.hash_algos_to_files[hash_type] = {}
            self.hash_algos_to_files[hash_type][hash_value] = item_name

    def _get_reputation_for_hashes(self, hashes):
        hash_match_result = None
        for hash_item in hashes:
            hash_match_current = None
            hash_type = hash_item["type"]
            if hash_item["type"] in self.hash_algos_to_files:
                hash_value = hash_item["value"]
                if hash_item["value"] in self.hash_algos_to_files[hash_type]:
                    hash_match_current = \
                        self.hash_algos_to_files[hash_type][hash_value]
            if not hash_match_current:
                hash_match_result = None
                break
            if hash_match_result is None:
                hash_match_result = hash_match_current
            elif hash_match_current != hash_match_result:
                hash_match_result = None
                break

        if not hash_match_result:
            raise Exception("Could not find reputation")
        return hash_match_result

    def __init__(self, client):
        """
        Constructor parameters:

        :param app: The application this handler is associated with
        """
        super(FakeTieServerCallback, self).__init__()

        self.hash_algos_to_files = {}

        for file_name, reputation in self.REPUTATION_METADATA.items():
            self._set_hash_algos_for_item(file_name, reputation["hashes"])

        self._client = client
        self._callbacks = {
            dxltieclient.client.TIE_SET_FILE_REPUTATION_TOPIC: self._set_file_reputation,
            dxltieclient.client.TIE_SET_CERT_REPUTATION_TOPIC: self._set_cert_reputation,

            dxltieclient.client.TIE_GET_FILE_REPUTATION_TOPIC: self._get_file_reputation,
            dxltieclient.client.TIE_GET_CERT_REPUTATION_TOPIC: self._get_cert_reputation,

            dxltieclient.client.TIE_GET_FILE_FIRST_REFS: self._get_file_first_instance,
            dxltieclient.client.TIE_GET_CERT_FIRST_REFS: self._get_cert_first_instance
        }

    def on_request(self, request):
        """
        Invoked when a request message is received.

        :param request: The request message
        """
        # Handle request
        request_payload = MessageUtils.json_payload_to_dict(request)
        if request.destination_topic in self._callbacks:
            try:
                self._callbacks[request.destination_topic](request,
                                                           request_payload)
            except Exception as ex:
                err_res = ErrorResponse(request, error_code=0,
                                        error_message=MessageUtils.encode(
                                            str(ex)))
                self._client.send_response(err_res)
        else:
            err_res = ErrorResponse(
                request,
                error_code=0,
                error_message=MessageUtils.encode(
                    "Unknown topic: " + request.destination_topic))
            self._client.send_response(err_res)

    # Reputation Setter Methods
    def _set_file_reputation(self, request, request_payload):
        self._set_item_reputation(request, request_payload,
                                  request_payload["filename"],
                                  dxltieclient.client.TIE_EVENT_FILE_REPUTATION_CHANGE_TOPIC)

    def _set_cert_reputation(self, request, request_payload):
        if "publicKeySha1" in request_payload:
            request_payload["hashes"].append({
                "type": "publicKeySha1",
                "value": request_payload["publicKeySha1"]
            })

        self._set_item_reputation(request, request_payload,
                                  self.TEST_CERT_NAME,
                                  dxltieclient.client.TIE_EVENT_CERT_REPUTATION_CHANGE_TOPIC)

    def _set_item_reputation(self, request, request_payload,
                             item_name, change_topic):
        new_entry = None

        if item_name in self.REPUTATION_METADATA:
            new_reputations = self.REPUTATION_METADATA[item_name]["reputations"]
            for reputation_entry in new_reputations:
                if reputation_entry["providerId"] == request_payload["providerId"]:
                    new_entry = reputation_entry
        else:
            new_reputations = []
            self.REPUTATION_METADATA[item_name] = {
                "hashes": {}, "reputations": new_reputations}

        old_reputations = copy.deepcopy(new_reputations)
        old_hashes = self.REPUTATION_METADATA[item_name]["hashes"]

        for hash_type, hash_value in old_hashes.items():
            if hash_type in self.hash_algos_to_files and \
                hash_value in self.hash_algos_to_files[hash_type]:
                del self.hash_algos_to_files[hash_type][hash_value]

        new_hashes = {new_hash["type"]: new_hash["value"] \
                      for new_hash in request_payload["hashes"]}
        self._set_hash_algos_for_item(item_name, new_hashes)
        self.REPUTATION_METADATA[item_name]["hashes"] = new_hashes

        if not new_entry:
            new_entry = {"attributes": {},
                         "providerId": request_payload["providerId"]}
        new_entry["trustLevel"] = request_payload["trustLevel"]
        new_entry["createDate"] = int(time.time())
        new_reputations.append(new_entry)

        self._client.send_response(Response(request))

        event = Event(change_topic)
        event_payload = {
            "hashes": request_payload["hashes"],
            "oldReputations": {"reputations": old_reputations},
            "newReputations": {"reputations": new_reputations},
            "updateTime": int(time.time())
        }

        MessageUtils.dict_to_json_payload(event, event_payload)
        self._client.send_event(event)

    # Reputation Getter Methods
    def _get_file_reputation(self, request, request_payload):
        self._get_reputation(request, request_payload)

    def _get_cert_reputation(self, request, request_payload):
        if "publicKeySha1" in request_payload:
            request_payload["hashes"].append({
                "type": "publicKeySha1",
                "value": request_payload["publicKeySha1"]
            })

            self._get_reputation(request, request_payload)

    def _get_reputation(self, request, request_payload):
        hash_match_result = self._get_reputation_for_hashes(
            request_payload["hashes"])

        res = Response(request)

        payload = {
            "props": {
                "serverTime": int(time.time()),
                "submitMetaData": 1
            },
            "reputations": self.REPUTATION_METADATA[
                hash_match_result]["reputations"],
        }

        MessageUtils.dict_to_json_payload(res, payload)

        self._client.send_response(res)

    # First Instance Getter Methods
    def _get_file_first_instance(self, request, request_payload):
        self._get_item_first_instance(request, request_payload)

    def _get_cert_first_instance(self, request, request_payload):
        if "publicKeySha1" in request_payload:
            request_payload["hashes"].append({
                "type": "publicKeySha1",
                "value": request_payload["publicKeySha1"]
            })
            self._get_item_first_instance(request, request_payload)

    def _get_item_first_instance(self, request, request_payload):
        hash_match_result = self._get_reputation_for_hashes(
            request_payload["hashes"])
        metadata = self.REPUTATION_METADATA[hash_match_result]

        res = Response(request)

        if "agents" in metadata:
            payload = {
                "totalCount": len(metadata["agents"]),
                "agents": metadata["agents"]
            }
        else:
            payload = {}

        MessageUtils.dict_to_json_payload(res, payload)
        self._client.send_response(res)
