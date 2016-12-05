# -*- coding: utf-8 -*-
################################################################################
# Copyright (c) 2016 McAfee Inc. - All Rights Reserved.
################################################################################

import base64
import json
from dxlclient import Request, Message
from constants import FileProvider, ReputationProp, CertProvider

# Topic used to set the reputation of a file
TIE_SET_FILE_REPUTATION_TOPIC = "/mcafee/service/tie/file/reputation/set"
# Topic used to retrieve the reputation of a file
TIE_GET_FILE_REPUTATION_TOPIC = "/mcafee/service/tie/file/reputation"

# Topic used to set the reputation of a certificate
TIE_SET_CERT_REPUTATION_TOPIC = "/mcafee/service/tie/cert/reputation/set"
# Topic used to retrieve the reputation of a certificate
TIE_GET_CERT_REPUTATION_TOPIC = "/mcafee/service/tie/cert/reputation"

# Topic used to retrieve systems that have referenced the file
TIE_GET_FILE_FIRST_REFS = "/mcafee/service/tie/file/agents"
# Topic used to retrieve systems that have referenced the certificate
TIE_GET_CERT_FIRST_REFS = "/mcafee/service/tie/cert/agents"


# TIE event topics
TIE_EVENT_FILE_DETECTION_TOPIC = "/mcafee/event/tie/file/detection"
TIE_EVENT_FILE_REPUTATION_CHANGE_TOPIC = "/mcafee/event/tie/file/repchange/broadcast"
TIE_EVENT_FILE_FIRST_INSTANCE_TOPIC = "/mcafee/event/tie/file/firstinstance"
TIE_EVENT_FILE_PREVALENCE_CHANGE_TOPIC = "/mcafee/event/tie/file/prevalence"
TIE_EVENT_CERTIFICATE_REPUTATION_CHANGE_TOPIC = "/mcafee/event/tie/cert/repchange/broadcast"


class TieClient(object):
    """
    This client provides a high level wrapper for communicating with the 
    McAfee Threat Intelligence Exchange (TIE) DXL service.

    The purpose of this client is to allow users to access the features of TIE (manage reputations,
    determine where a file has executed, etc.) without having to focus on lower-level details such as
    TIE-specific DXL topics and message formats.
    """
    
    # The default amount of time (in seconds) to wait for a response from the TIE server
    __DEFAULT_RESPONSE_TIMEOUT = 30
    # The minimum amount of time (in seconds) to wait for a response from the TIE server
    __MIN_RESPONSE_TIMEOUT = 30
    
    def __init__(self, dxl_client):
        """
        Constructor parameters:

        :param dxl_client: The DXL client to use for communication with the TIE DXL service
        """
        self.__dxl_client = dxl_client
        self.__response_timeout = self.__DEFAULT_RESPONSE_TIMEOUT

    @property
    def response_timeout(self):
        """
        The maximum amount of time (in seconds) to wait for a response from the TIE server
        """
        return self.__response_timeout

    @response_timeout.setter
    def response_timeout(self, response_timeout):
        if response_timeout < self.__MIN_RESPONSE_TIMEOUT:
            raise Exception("Response timeout must be greater than or equal to " + str(self.__MIN_RESPONSE_TIMEOUT))
        self.__response_timeout = response_timeout

    def set_file_reputation(self, trust_level, hashes, filename="", comment="",
                            provider_id=FileProvider.ENTERPRISE):
        """
        Sets the reputation  (`trust level`) of a specified file (as identified by hashes).

        .. note::

            **Client Authorization**

            The OpenDXL Python client invoking this method must have permission to send messages to the
            ``/mcafee/service/tie/file/reputation/set`` topic which is part of the
            ``TIE Server Set Enterprise Reputation`` authorization group.

            The following page provides an example of authorizing a Python client to send messages to an
            `authorization group`. While the example is based on McAfee Active Response (MAR), the
            instructions are the same with the exception of swapping the ``TIE Server Set Enterprise Reputation``
            `authorization group` in place of ``Active Response Server API``:

            `<https://opendxl.github.io/opendxl-client-python/pydoc/marsendauth.html>`_

        **Example Usage**

            .. code-block:: python

                # Set the enterprise reputation (trust level) for notepad.exe to Known Trusted
                tie_client.set_file_reputation(
                    TrustLevel.KNOWN_TRUSTED,
                    {
                        HashType.SHA1: "7eb0139d2175739b3ccb0d1110067820be6abd29",
                        HashType.MD5: "f2c7bb8acc97f92e987a2d4087d021b1"
                    },
                    filename="notepad.exe",
                    comment="Reputation set via OpenDXL")

        :param trust_level: The new `trust level` for the file. The list of standard `trust levels` can be found in the
            :class:`dxltieclient.constants.TrustLevel` constants class.
        :param hashes: A ``dict`` (dictionary) of hashes that identify the file to update the reputation for.
            The ``key`` in the dictionary is the `hash type` and the ``value`` is the `hex` representation of the
            hash value. See the :class:`dxltieclient.constants.HashType` class for the list of `hash type`
            constants.
        :param filename: A file name to associate with the file (optional)
        :param comment: A comment to associate with the file (optional)
        :param provider_id: The identifier of the `file reputation provider` whose reputation is to be updated
            (defaults to the `Enterprise` reputation provider).
            The list of `file reputation providers` can be found in the :class:`dxltieclient.constants.FileProvider`
            constants class.
        """
        # Create the request message
        req = Request(TIE_SET_FILE_REPUTATION_TOPIC)

        # Create a dictionary for the payload
        payload_dict = {
            "trustLevel": trust_level,
            "providerId": provider_id,
            "filename": filename,
            "comment": comment,
            "hashes": []}

        for key, value in hashes.items():
            payload_dict["hashes"].append({"type": key, "value": base64.b64encode(value.decode('hex'))})
            
        # Set the payload
        req.payload = json.dumps(payload_dict).encode()

        # Send the request
        self.__dxl_sync_request(req)

    def get_file_reputation(self, hashes):
        """
        Retrieves the reputations for the specified file (as identified by hashes)

        At least one `hash value` of a particular `hash type` (MD5, SHA-1, etc.) must be specified.
        Passing additional hashes increases the likelihood of other reputations being located across the
        set of `file reputation providers`.

        **Example Usage**

            .. code-block:: python

                # Determine reputations for file (identified by hashes)
                reputations_dict = \\
                    tie_client.get_file_reputation({
                        HashType.SHA1: "7eb0139d2175739b3ccb0d1110067820be6abd29",
                        HashType.MD5: "f2c7bb8acc97f92e987a2d4087d021b1"
                    })

        **Reputations**

            The `Reputations` for the file are returned as a Python ``dict`` (dictionary).

            The `key` for each entry in the ``dict`` (dictionary) corresponds to a particular `provider` of the
            associated `reputation`. The list of `file reputation providers` can be found in the
            :class:`dxltieclient.constants.FileProvider` constants class.

            An example reputations ``dict`` is shown below:

            .. code-block:: python

                {
                    "1": {
                        "attributes": {
                            "2120340": "2139160704"
                        },
                        "createDate": 1480455704,
                        "providerId": 1,
                        "trustLevel": 99
                    },
                    "3": {
                        "attributes": {
                            "2101652": "52",
                            "2102165": "1476902802",
                            "2111893": "56",
                            "2114965": "1",
                            "2139285": "73183493944770750"
                        },
                        "createDate": 1476902802,
                        "providerId": 3,
                        "trustLevel": 99
                    }
                }

            The ``"1"`` `key` corresponds to a reputation from the "Global Threat Intelligence (GTI)" reputation
            provider while the ``"3"`` `key` corresponds to a reputation from the "Enterprise" reputation provider.

            Each reputation contains a standard set of properties (trust level, creation date, etc.). These
            properties are listed in the :class:`dxltieclient.constants.ReputationProp` constants class.

            The following example shows how to access the `trust level` property of the "Enterprise" reputation:

            .. code-block:: python

                trust_level = reputations_dict[FileProvider.ENTERPRISE][ReputationProp.TRUST_LEVEL]

            Each reputation can also contain a provider-specific set of attributes. These attributes can be found
            in the :class:`dxltieclient.constants` module:

              * :class:`dxltieclient.constants.FileEnterpriseAttrib`
               * Attributes associated with the `Enterprise` reputation provider for files
              * :class:`dxltieclient.constants.FileGtiAttrib`
               * Attributes associated with the `Global Threat Intelligence (GTI)` reputation provider for files
              * :class:`dxltieclient.constants.AtdAttrib`
               * Attributes associated with the `Advanced Threat Defense (ATD)` reputation provider

            The following example shows how to access the `prevalence` attribute from the "Enterprise" reputation:

            .. code-block:: python

                ent_rep = reputations_dict[FileProvider.ENTERPRISE]
                ent_rep_attribs = ent_rep[ReputationProp.ATTRIBUTES]
                prevalence = int(ent_rep_attribs[FileEnterpriseAttrib.PREVALENCE])

        :param hashes: A ``dict`` (dictionary) of hashes that identify the file to retrieve the reputations for.
            The ``key`` in the dictionary is the `hash type` and the ``value`` is the `hex` representation of the
            hash value. See the :class:`dxltieclient.constants.HashType` class for the list of `hash type`
            constants.
        :return: A ``dict`` (dictionary) where each `value` is a reputation from a particular `reputation provider`
            which is identified by the `key`. The list of `file reputation providers` can be found in the
            :class:`dxltieclient.constants.FileProvider` constants class.
        """
        # Create the request message
        req = Request(TIE_GET_FILE_REPUTATION_TOPIC)

        # Create a dictionary for the payload
        payload_dict = {"hashes": []}
        
        for key, value in hashes.items():
            payload_dict["hashes"].append({"type": key, "value": base64.b64encode(value.decode('hex'))})

        # Set the payload
        req.payload = json.dumps(payload_dict).encode()

        # Send the request
        response = self.__dxl_sync_request(req)
        
        resp_dict = json.loads(response.payload.decode())

        # Return the reputations list
        if "reputations" in resp_dict:
            reputation_dict = {}
            for reputation in resp_dict["reputations"]:
                reputation_dict[reputation[ReputationProp.PROVIDER_ID]] = reputation
            return reputation_dict
        else:
            return {}

    def get_file_first_references(self, hashes, query_limit=500):
        """
        Retrieves the set of systems which have referenced (typically executed) the specified file (as
        identified by hashes).

        **Example Usage**

            .. code-block:: python

                # Get the list of systems that have referenced the file
                system_list = \\
                    tie_client.get_file_first_references({
                        HashType.SHA1: "7eb0139d2175739b3ccb0d1110067820be6abd29",
                        HashType.MD5: "f2c7bb8acc97f92e987a2d4087d021b1"
                    })

        **Systems**

        The systems that have referenced the file are returned as a Python ``list``.

        An example ``list`` is shown below:

            .. code-block:: python

                [
                    {
                        "agentGuid": "{3a6f574a-3e6f-436d-acd4-bcde336b054d}",
                        "date": 1475873692
                    },
                    {
                        "agentGuid": "{68125cd6-a5d8-11e6-348e-000c29663178}",
                        "date": 1478626172
                    }
                ]

        Each entry in the ``list`` is a ``dict`` (dictionary) containing details about a system that has
        referenced the file. See the :class:`dxltieclient.constants.FirstRefProp` constants class for details
        about the information that is available for each system in the ``dict`` (dictionary).

        :param hashes: A ``dict`` (dictionary) of hashes that identify the file to lookup.
            The ``key`` in the dictionary is the `hash type` and the ``value`` is the `hex` representation of the
            hash value. See the :class:`dxltieclient.constants.HashType` class for the list of `hash type`
            constants.
        :param query_limit: The maximum number of results to return
        :return: A ``list`` containing a ``dict`` (dictionary) for each system that has referenced the file. See the
            :class:`dxltieclient.constants.FirstRefProp` constants class for details about the information that
            is available for each system in the ``dict`` (dictionary).
        """
        # Create the request message
        req = Request(TIE_GET_FILE_FIRST_REFS)

        # Create a dictionary for the payload
        payload_dict = {
            "queryLimit": query_limit,
            "hashes": []
        }

        for key, value in hashes.items():
            payload_dict["hashes"].append({"type": key, "value": base64.b64encode(value.decode('hex'))})

        # Set the payload
        req.payload = json.dumps(payload_dict).encode()

        # Send the request
        response = self.__dxl_sync_request(req)

        resp_dict = json.loads(response.payload.decode())

        # Return the agents list
        if "agents" in resp_dict:
            return resp_dict["agents"]
        else:
            return []

    def set_certificate_reputation(self, trust_level, sha1, public_key_sha1=None, comment="",
            provider_id=CertProvider.ENTERPRISE):
        """
        Sets the reputation (`trust level`) of a specified certificate (as identified by hashes).

        .. note::

            **Client Authorization**

            The OpenDXL Python client invoking this method must have permission to send messages to the
            ``/mcafee/service/tie/cert/reputation/set`` topic which is part of the
            ``TIE Server Set Enterprise Reputation`` authorization group.

            The following page provides an example of authorizing a Python client to send messages to an
            `authorization group`. While the example is based on McAfee Active Response (MAR), the
            instructions are the same with the exception of swapping the ``TIE Server Set Enterprise Reputation``
            `authorization group` in place of ``Active Response Server API``:

            `<https://opendxl.github.io/opendxl-client-python/pydoc/marsendauth.html>`_

        **Example Usage**

            .. code-block:: python

                    # Set the enterprise reputation (trust level) for the certificate to Known Trusted
                    tie_client.set_certificate_reputation(
                        TrustLevel.KNOWN_TRUSTED,
                        "1C26E2037C8E205B452CAB3565D696512207D66D",
                        public_key_sha1="B4C3B2D596D1461C1BB417B92DCD74817ABB829D",
                        comment="Reputation set via OpenDXL")

        :param trust_level: The new `trust level` for the file. The list of standard `trust levels` can be found in the
            :class:`dxltieclient.constants.TrustLevel` constants class.
        :param sha1: The SHA-1 of the certificate
        :param public_key_sha1: The SHA-1 of the certificate's public key (optional)
        :param comment: A comment to associate with the certificate (optional)
        :param provider_id: The identifier of the `certificate reputation provider` whose reputation is to be updated
            (defaults to the `Enterprise` reputation provider).
            The list of `certificate reputation providers` can be found in the
            :class:`dxltieclient.constants.CertProvider` constants class.
        """
        # Create the request message
        req = Request(TIE_SET_CERT_REPUTATION_TOPIC)

        # Create a dictionary for the payload
        payload_dict = {
            "trustLevel": trust_level,
            "providerId": provider_id,
            "comment": comment,
            "hashes": [
                {"type": "sha1", "value": base64.b64encode(sha1.decode('hex'))}
            ]}

        # Add public key SHA-1 (if specified)
        if public_key_sha1:
            payload_dict["publicKeySha1"] = base64.b64encode(public_key_sha1.decode('hex'))

        # Set the payload
        req.payload = json.dumps(payload_dict).encode()

        # Send the request
        self.__dxl_sync_request(req)

    def get_certificate_reputation(self, sha1, public_key_sha1=None):
        """
        Retrieves the reputations for the specified certificate (as identified by the SHA-1 of the certificate
        and optionally the SHA-1 of the certificate's public key)

        While the SHA-1 of the certificate is required, passing the optional SHA-1 of the certificate's public key
        can result in additional reputations being located across the set of `certificate reputation providers`.

        **Example Usage**

            .. code-block:: python

                # Determine reputations for certificate (identified by hashes)
                reputations_dict = \\
                    tie_client.get_certificate_reputation(
                        "6EAE26DB8C13182A7947982991B4321732CC3DE2",
                        public_key_sha1="3B87A2D6F39770160364B79A152FCC73BAE27ADF")

        **Reputations**

            The `Reputations` for the certificate are returned as a Python ``dict`` (dictionary).

            The `key` for each entry in the ``dict`` (dictionary) corresponds to a particular `provider` of the
            associated `reputation`. The list of `certificate reputation providers` can be found in the
            :class:`dxltieclient.constants.CertProvider` constants class.

            An example reputations ``dict`` is shown below:

            .. code-block:: python

                {
                    "2": {
                        "attributes": {
                            "2108821": "92",
                            "2109077": "1454912619",
                            "2117524": "0",
                            "2120596": "0"
                        },
                        "createDate": 1476318514,
                        "providerId": 2,
                        "trustLevel": 99
                    },
                    "4": {
                        "attributes": {
                            "2109333": "4",
                            "2109589": "1476318514",
                            "2139285": "73183493944770750"
                        },
                        "createDate": 1476318514,
                        "providerId": 4,
                        "trustLevel": 0
                    }
                }

            The ``"2"`` `key` corresponds to a reputation from the "Global Threat Intelligence (GTI)" reputation
            provider while the ``"4"`` `key` corresponds to a reputation from the "Enterprise" reputation provider.

            Each reputation contains a standard set of properties (trust level, creation date, etc.). These
            properties are listed in the :class:`dxltieclient.constants.ReputationProp` constants class.

            The following example shows how to access the `trust level` property of the "Enterprise" reputation:

            .. code-block:: python

                trust_level = reputations_dict[CertProvider.ENTERPRISE][ReputationProp.TRUST_LEVEL]

            Each reputation can also contain a provider-specific set of attributes. These attributes can be found
            in the :class:`dxltieclient.constants` module:

              * :class:`dxltieclient.constants.CertEnterpriseAttrib`
               * Attributes associated with the `Enterprise` reputation provider for certificates
              * :class:`dxltieclient.constants.CertGtiAttrib`
               * Attributes associated with the `Global Threat Intelligence (GTI)` reputation provider for certificates

            The following example shows how to access the `prevalence` attribute from the "Enterprise" reputation:

            .. code-block:: python

                ent_rep = reputations_dict[CertProvider.ENTERPRISE]
                ent_rep_attribs = ent_rep[ReputationProp.ATTRIBUTES]
                prevalence = int(ent_rep_attribs[CertEnterpriseAttrib.PREVALENCE])

        :param sha1: The SHA-1 of the certificate
        :param public_key_sha1: The SHA-1 of the certificate's public key (optional)
        :return: A ``dict`` (dictionary) where each `value` is a reputation from a particular `reputation provider`
            which is identified by the `key`. The list of `certificate reputation providers` can be found in the
            :class:`dxltieclient.constants.CertProvider` constants class.
        """
        # Create the request message
        req = Request(TIE_GET_CERT_REPUTATION_TOPIC)

        # Create a dictionary for the payload
        payload_dict = {
            "hashes": [
                {"type": "sha1", "value": base64.b64encode(sha1.decode('hex'))}
            ]}

        # Add public key SHA-1 (if specified)
        if public_key_sha1:
            payload_dict["publicKeySha1"] = base64.b64encode(public_key_sha1.decode('hex'))

        # Set the payload
        req.payload = json.dumps(payload_dict).encode()

        # Send the request
        response = self.__dxl_sync_request(req)
        
        resp_dict = json.loads(response.payload.decode())

        # Return the reputations list
        if "reputations" in resp_dict:
            reputation_dict = {}
            for reputation in resp_dict["reputations"]:
                reputation_dict[reputation[ReputationProp.PROVIDER_ID]] = reputation
            return reputation_dict
        else:
            return {}

    def get_certificate_first_references(self, sha1, public_key_sha1=None, query_limit=500):
        """
        Retrieves the set of systems which have referenced the specified certificate (as
        identified by hashes).

        **Example Usage**

            .. code-block:: python

                # Get the list of systems that have referenced the certificate
                system_list = \\
                    tie_client.get_certificate_first_references(
                        "6EAE26DB8C13182A7947982991B4321732CC3DE2",
                        "3B87A2D6F39770160364B79A152FCC73BAE27ADF")

        **Systems**

        The systems that have referenced the certificate are returned as a Python ``list``.

        An example ``list`` is shown below:

            .. code-block:: python

                [
                    {
                        "agentGuid": "{3a6f574a-3e6f-436d-acd4-bcde336b054d}",
                        "date": 1475873692
                    },
                    {
                        "agentGuid": "{68125cd6-a5d8-11e6-348e-000c29663178}",
                        "date": 1478626172
                    }
                ]

        Each entry in the ``list`` is a ``dict`` (dictionary) containing details about a system that has
        referenced the certificate. See the :class:`dxltieclient.constants.FirstRefProp` constants class for details
        about the information that is available for each system in the ``dict`` (dictionary).

        :param sha1: The SHA-1 of the certificate
        :param public_key_sha1: The SHA-1 of the certificate's public key (optional)
        :param query_limit: The maximum number of results to return
        :return: A ``list`` containing a ``dict`` (dictionary) for each system that has referenced the certificate.
            See the :class:`dxltieclient.constants.FirstRefProp` constants class for details about the information that
            is available for each system in the ``dict`` (dictionary).
        """
        # Create the request message
        req = Request(TIE_GET_CERT_FIRST_REFS)

        # Create a dictionary for the payload
        payload_dict = {
            "queryLimit": query_limit,
            "hashes": [
                {"type": "sha1", "value": base64.b64encode(sha1.decode('hex'))}
            ]}

        # Add public key SHA-1 (if specified)
        if public_key_sha1:
            payload_dict["publicKeySha1"] = base64.b64encode(public_key_sha1.decode('hex'))

        # Set the payload
        req.payload = json.dumps(payload_dict).encode()

        # Send the request
        response = self.__dxl_sync_request(req)

        resp_dict = json.loads(response.payload.decode())

        # Return the agents list
        if "agents" in resp_dict:
            return resp_dict["agents"]
        else:
            return []

    def __dxl_sync_request(self, request):
        """
        Performs a synchronous DXL request. Throws an exception if an error occurs

        :param request: The request to send
        :return: The DXL response
        """
        # Send the request and wait for a response (synchronous)
        res = self.__dxl_client.sync_request(request, timeout=self.__response_timeout)

        # Return a dictionary corresponding to the response payload
        if res.message_type != Message.MESSAGE_TYPE_ERROR:
            return res
        else:
            raise Exception("Error: " + res.error_message + " (" + str(res.error_code) + ")")
