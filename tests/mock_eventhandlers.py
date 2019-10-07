from dxlbootstrap.util import MessageUtils
from dxlclient import EventCallback

import dxltieclient
from dxltieclient import ReputationProp, FileProvider


class FakeTieServerEvent(EventCallback):

    def __init__(self, client, requests_handler):
        """
        Constructor parameters:

        :param client: DXL client
        :param requests_handler: Requests handler mock
        """
        super(FakeTieServerEvent, self).__init__()

        self._client = client
        self._requests_handler = requests_handler
        self._callbacks = {
            dxltieclient.client.TIE_EVENT_EXTERNAL_FILE_REPORT_TOPIC: self._set_external_file_reputation
        }

    def on_event(self, event):
        """
        Invoked when an event is received.

        :param event: The event
        """
        # Handle event
        event_payload = MessageUtils.json_payload_to_dict(event)
        if event.destination_topic in self._callbacks:
            self._callbacks[event.destination_topic](event_payload)
        else:
            raise NotImplementedError(MessageUtils.encode("Unknown topic: " + event.destination_topic))

    def _set_external_file_reputation(self, event_payload):
        filename = event_payload["file"]["attributes"]["filename"]
        if filename in self._requests_handler.REPUTATION_METADATA:
            reputations = self._requests_handler.REPUTATION_METADATA[filename]["reputations"]
            external_rep = next(
                (rep for rep in reputations if rep[ReputationProp.PROVIDER_ID] == FileProvider.EXTERNAL), None)
            if not external_rep:
                external_rep = {ReputationProp.ATTRIBUTES: {},
                                ReputationProp.PROVIDER_ID: FileProvider.EXTERNAL}
            external_rep[ReputationProp.TRUST_LEVEL] = event_payload["file"]["reputation"]["score"]
            external_rep[ReputationProp.CREATE_DATE] = int(dxltieclient.time.time())
            reputations.append(external_rep)
        else:
            raise ValueError("File not found")
