from dxlclient.service import ServiceRegistrationInfo

import dxltieclient
from tests.mock_eventhandlers import FakeTieServerEvent
from tests.mock_requesthandlers import FakeTieServerCallback


class MockTieServer(object):
    def __init__(self, client):
        self._client = client

        # Create DXL Service Registration object
        self._service_registration_info = ServiceRegistrationInfo(
            self._client,
            "/opendxl/mocktieserver"
        )
        self._mock_event = None

    def __enter__(self):
        mock_callback = FakeTieServerCallback(self._client)

        self._service_registration_info.add_topic(
            dxltieclient.client.TIE_GET_FILE_REPUTATION_TOPIC,
            mock_callback
        )
        self._service_registration_info.add_topic(
            dxltieclient.client.TIE_GET_CERT_REPUTATION_TOPIC,
            mock_callback
        )
        self._service_registration_info.add_topic(
            dxltieclient.client.TIE_SET_FILE_REPUTATION_TOPIC,
            mock_callback
        )
        self._service_registration_info.add_topic(
            dxltieclient.client.TIE_SET_CERT_REPUTATION_TOPIC,
            mock_callback
        )
        self._service_registration_info.add_topic(
            dxltieclient.client.TIE_GET_FILE_FIRST_REFS,
            mock_callback
        )
        self._service_registration_info.add_topic(
            dxltieclient.client.TIE_GET_CERT_FIRST_REFS,
            mock_callback
        )

        self._client.register_service_sync(self._service_registration_info, 10)

        self._mock_event = FakeTieServerEvent(self._client, mock_callback)
        self._client.add_event_callback(
            dxltieclient.client.TIE_EVENT_EXTERNAL_FILE_REPORT_TOPIC,
            self._mock_event
        )

        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self._client.unregister_service_sync(self._service_registration_info, 10)
        self._client.remove_event_callback(dxltieclient.client.TIE_EVENT_EXTERNAL_FILE_REPORT_TOPIC, self._mock_event)
