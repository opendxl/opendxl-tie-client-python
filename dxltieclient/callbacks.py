# -*- coding: utf-8 -*-
################################################################################
# Copyright (c) 2017 McAfee LLC - All Rights Reserved.
################################################################################

from __future__ import absolute_import

from dxlbootstrap.util import MessageUtils
from dxlclient.callbacks import EventCallback
from dxltieclient import TieClient
from .constants import RepChangeEventProp, FileRepChangeEventProp, CertRepChangeEventProp, \
    DetectionEventProp, FirstInstanceEventProp


class ReputationChangeCallback(EventCallback):
    """
    Concrete instances of this class are used to receive "reputation change" events from the TIE
    server when the `reputation` of files or certificates change.

    The following steps must be performed to create and register a reputation change callback
    (as shown in the example below):

        * Create a derived class from :class:`ReputationChangeCallback`
        * Override the :func:`on_reputation_change` method to handle reputation change events
        * Register the callback with the client:

            For files:
                :func:`dxltieclient.client.TieClient.add_file_reputation_change_callback`
            For certificates:
                :func:`dxltieclient.client.TieClient.add_certificate_reputation_change_callback`

    **Example Usage**

        .. code-block:: python

            class MyReputationChangeCallback(ReputationChangeCallback):
                def on_reputation_change(self, rep_change_dict, original_event):

                    # Dump the reputation change dictionary
                    print(MessageUtils.dict_to_json(rep_change_dict, True))

            # Create the client
            with DxlClient(config) as client:

                # Connect to the fabric
                client.connect()

                # Create the McAfee Threat Intelligence Exchange (TIE) client
                tie_client = TieClient(client)

                # Create reputation change callback
                rep_change_callback = MyReputationChangeCallback()

                # Register callback with client to receive file reputation change events
                tie_client.add_file_reputation_change_callback(rep_change_callback)
    """
    def on_event(self, event):
        """
        Invoked when a DXL event has been received.

        NOTE: This method should not be overridden (it performs transformations to simplify TIE usage).
        Instead, the :func:`on_reputation_change` method must be overridden.

        :param event: The original DXL event message that was received
        """
        # Decode the event payload
        rep_change_dict = MessageUtils.json_payload_to_dict(event)

        # Transform hashes
        if RepChangeEventProp.HASHES in rep_change_dict:
            rep_change_dict[RepChangeEventProp.HASHES] = \
                TieClient._transform_hashes(rep_change_dict[RepChangeEventProp.HASHES])

        # Transform new reputations
        if RepChangeEventProp.NEW_REPUTATIONS in rep_change_dict:
            if "reputations" in rep_change_dict[RepChangeEventProp.NEW_REPUTATIONS]:
                rep_change_dict[RepChangeEventProp.NEW_REPUTATIONS] = \
                    TieClient._transform_reputations(
                        rep_change_dict[RepChangeEventProp.NEW_REPUTATIONS]["reputations"])

        # Transform old reputations
        if RepChangeEventProp.OLD_REPUTATIONS in rep_change_dict:
            if "reputations" in rep_change_dict[RepChangeEventProp.OLD_REPUTATIONS]:
                rep_change_dict[RepChangeEventProp.OLD_REPUTATIONS] = \
                    TieClient._transform_reputations(
                        rep_change_dict[RepChangeEventProp.OLD_REPUTATIONS]["reputations"])

        # Transform relationships
        if FileRepChangeEventProp.RELATIONSHIPS in rep_change_dict:
            relationships_dict = rep_change_dict[FileRepChangeEventProp.RELATIONSHIPS]
            if "certificate" in relationships_dict:
                cert_dict = relationships_dict["certificate"]
                if "hashes" in cert_dict:
                    cert_dict["hashes"] = \
                        TieClient._transform_hashes(cert_dict["hashes"])
                if "publicKeySha1" in cert_dict:
                    cert_dict["publicKeySha1"] = \
                        TieClient._base64_to_hex(cert_dict["publicKeySha1"])

        # Transform certificate public-key SHA-1 (if applicable)
        if CertRepChangeEventProp.PUBLIC_KEY_SHA1 in rep_change_dict:
            rep_change_dict[CertRepChangeEventProp.PUBLIC_KEY_SHA1] = \
                TieClient._base64_to_hex(rep_change_dict[CertRepChangeEventProp.PUBLIC_KEY_SHA1])

        # Invoke the reputation change method
        self.on_reputation_change(rep_change_dict, event)

    def on_reputation_change(self, rep_change_dict, original_event):
        """
        NOTE: This method must be overridden by derived classes.

        Each `reputation change event` that is received from the DXL fabric will cause this method to be
        invoked with the corresponding `reputation change information`.

        **Reputation Change Information**

            The `Reputation Change` information is provided as a Python ``dict`` (dictionary) via the
            ``rep_change_dict`` parameter.

            An example `reputation change` ``dict`` (dictionary) is shown below:

            .. code-block:: python

                {
                    "hashes": {
                        "md5": "f2c7bb8acc97f92e987a2d4087d021b1",
                        "sha1": "7eb0139d2175739b3ccb0d1110067820be6abd29",
                        "sha256": "142e1d688ef0568370c37187fd9f2351d7ddeda574f8bfa9b0fa4ef42db85aa2"
                    },
                    "newReputations": {
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
                    },
                    "oldReputations": {
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
                    },
                    "updateTime": 1481219581
                }

            The top level property names in the dictionary are listed in the following constants classes
            (which derive from the :class:`dxltieclient.constants.RepChangeEventProp` class):

                For files:
                    :class:`dxltieclient.constants.FileRepChangeEventProp`
                For certificates:
                    :class:`dxltieclient.constants.CertRepChangeEventProp`

            The `reputation change` information is separated into 4 distinct sections:

                **Hash values**

                    Keyed in the dictionary by the ``"hashes"`` string.

                    A ``dict`` (dictionary) of hashes that identify the file or certificate whose reputation has
                    changed. The ``key`` in the dictionary is the `hash type` and the ``value`` is the `hex`
                    representation of the hash value. See the :class:`dxltieclient.constants.HashType` class for the
                    list of `hash type` constants.

                    For certificates there may also be a top-level property named, ``"publicKeySha1"`` that
                    contains the SHA-1 of the certificate's public key.

                **New reputations**

                    Keyed in the dictionary by the ``"newReputations"`` string.

                    The new `Reputations` for the file or certificate whose reputation has changed as a
                    Python ``dict`` (dictionary).

                    The `key` for each entry in the ``dict`` (dictionary) corresponds to a particular `provider` of the
                    associated `reputation`. The list of `file reputation providers` can be found in the
                    :class:`dxltieclient.constants.FileProvider` constants class. The list of
                    `certificate reputation providers` can be found in the :class:`dxltieclient.constants.CertProvider`
                    constants class.

                    Each reputation contains a standard set of properties (trust level, creation date, etc.). These
                    properties are listed in the :class:`dxltieclient.constants.ReputationProp` constants class.

                    Each reputation can also contain a provider-specific set of attributes as a Python ``dict``
                    (dictionary). These attributes can be found in the :class:`dxltieclient.constants` module:

                        :class:`dxltieclient.constants.FileEnterpriseAttrib`
                            Attributes associated with the `Enterprise` reputation provider for files
                        :class:`dxltieclient.constants.FileGtiAttrib`
                            Attributes associated with the `Global Threat Intelligence (GTI)` reputation provider for
                            files
                        :class:`dxltieclient.constants.AtdAttrib`
                            Attributes associated with the `Advanced Threat Defense (ATD)` reputation provider
                        :class:`dxltieclient.constants.CertEnterpriseAttrib`
                            Attributes associated with the `Enterprise` reputation provider for certificates
                        :class:`dxltieclient.constants.CertGtiAttrib`
                            Attributes associated with the `Global Threat Intelligence (GTI)` reputation provider for
                            certificates

                **Old reputations**

                    Keyed in the dictionary by the ``"oldReputations"`` string.

                    The previous `Reputations` for the file or certificate whose reputation has changed as a
                    Python ``dict`` (dictionary).

                    See the "New reputations" section above for additional information regarding reputation
                    details.

                **Change time**

                    Keyed in the dictionary by the ``"updateTime"`` string.

                    The time the reputation change occurred (Epoch time).

        :param rep_change_dict: A Python ``dict`` (dictionary) containing the details of the reputation change
        :param original_event: The original DXL event message that was received
        """
        raise NotImplementedError("Must be implemented in a child class.")


class DetectionCallback(EventCallback):
    """
    Concrete instances of this class are used to receive "detection" events from the DXL fabric

    The following steps must be performed to create and register a detection callback
    (as shown in the example below):

        * Create a derived class from :class:`DetectionCallback`
        * Override the :func:`on_detection` method to handle detection events
        * Register the callback with the client:

            For files:
                :func:`dxltieclient.client.TieClient.add_file_detection_callback`

    **Example Usage**

        .. code-block:: python

            class MyDetectionCallback(DetectionCallback):
                def on_detection(self, detection_dict, original_event):

                    # Dump the dictionary
                    print(MessageUtils.dict_to_json(detection_dict, True))

            # Create the client
            with DxlClient(config) as client:

                # Connect to the fabric
                client.connect()

                # Create the McAfee Threat Intelligence Exchange (TIE) client
                tie_client = TieClient(client)

                # Create detection callback
                detection_callback = MyDetectionCallback()

                # Register detection callback with the client
                tie_client.add_file_detection_callback(detection_callback)
    """
    def on_event(self, event):
        """
        Invoked when a DXL event has been received.

        NOTE: This method should not be overridden (it performs transformations to simplify TIE usage).
        Instead, the :func:`on_detection` method must be overridden.

        :param event: The original DXL event message that was received
        """
        # Decode the event payload
        detection_dict = MessageUtils.json_payload_to_dict(event)

        # Transform hashes
        if DetectionEventProp.HASHES in detection_dict:
            detection_dict[RepChangeEventProp.HASHES] = \
                TieClient._transform_hashes(detection_dict[DetectionEventProp.HASHES])

        # Invoke the detection method
        self.on_detection(detection_dict, event)

    def on_detection(self, detection_dict, original_event):
        """
        NOTE: This method must be overridden by derived classes.

        Each `detection event` that is received from the DXL fabric will cause this method to be
        invoked with the corresponding `detection information`.

        **Detection Information**

            The `detection` information is provided as a Python ``dict`` (dictionary) via the
            ``detection_dict`` parameter.

            An example `detection` ``dict`` (dictionary) is shown below:

            .. code-block:: python

                {
                    "agentGuid": "{68125cd6-a5d8-11e6-348e-000c29663178}",
                    "detectionTime": 1481301038,
                    "hashes": {
                        "md5": "eb5e2b9dc51817a086d7b97eb52410ab",
                        "sha1": "435dfd470f727437c7cb4f07cba1f9a1f4272656",
                        "sha256": "414bb16b10ece2db2d8448cb9f313f80cb77c310ca0c19ee03c73cba0c16fedb"
                    },
                    "localReputation": 1,
                    "name": "TEST_MALWARE.EXE",
                    "remediationAction": 5
                }

            The top level property names in the dictionary are listed in the
            :class:`dxltieclient.constants.DetectionEventProp` constants class.

            The information provided in the dictionary includes:

                * System the detection occurred on
                * Time the detection occurred (Epoch time)
                * File that triggered the detection (file name and associated hashes)
                * Reputation value that was calculated locally which triggered the detection
                * Remediation action that occurred in response to the detection

        :param detection_dict: A Python ``dict`` (dictionary) containing the details of the detection
        :param original_event: The original DXL event message that was received
        """
        raise NotImplementedError("Must be implemented in a child class.")


class FirstInstanceCallback(EventCallback):
    """
    Concrete instances of this class are used to receive "first instance" events from the DXL fabric.
    The "first instance" event indicates that this is the first time the file has been encountered
    within the local enterprise.

    The following steps must be performed to create and register a first instance callback
    (as shown in the example below):

        * Create a derived class from :class:`FirstInstanceCallback`
        * Override the :func:`on_first_instance` method to handle first instance events
        * Register the callback with the client:

            For files:
                :func:`dxltieclient.client.TieClient.add_file_first_instance_callback`

    **Example Usage**

        .. code-block:: python

            class MyFirstInstanceCallback(FirstInstanceCallback):
                def on_first_instance(self, first_instance_dict, original_event):

                    # Dump the dictionary
                    print(MessageUtils.dict_to_json(first_instance_dict, True))

            # Create the client
            with DxlClient(config) as client:

                # Connect to the fabric
                client.connect()

                # Create the McAfee Threat Intelligence Exchange (TIE) client
                tie_client = TieClient(client)

                # Create first instance callback
                first_instance_callback = MyFirstInstanceCallback()

                # Register first instance callback with the client
                tie_client.add_file_first_instance_callback(first_instance_callback)
    """
    def on_event(self, event):
        """
        Invoked when a DXL event has been received.

        NOTE: This method should not be overridden (it performs transformations to simplify TIE usage).
        Instead, the :func:`on_first_instance` method must be overridden.

        :param event: The original DXL event message that was received
        """
        # Decode the event payload
        first_instance_dict = MessageUtils.json_payload_to_dict(event)

        # Transform hashes
        if FirstInstanceEventProp.HASHES in first_instance_dict:
            first_instance_dict[RepChangeEventProp.HASHES] = \
                TieClient._transform_hashes(first_instance_dict[FirstInstanceEventProp.HASHES])

        # Invoke the first instance method
        self.on_first_instance(first_instance_dict, event)

    def on_first_instance(self, first_instance_dict, original_event):
        """
        NOTE: This method must be overridden by derived classes.

        Each `first instance event` that is received from the DXL fabric will cause this method to be
        invoked with the corresponding `first instance information`.

        **First Instance Information**

            The `first instance` information is provided as a Python ``dict`` (dictionary) via the
            ``first_instance_dict`` parameter.

            An example `first instance` ``dict`` (dictionary) is shown below:

            .. code-block:: python

                {
                    "agentGuid": "{68125cd6-a5d8-11e6-348e-000c29663178}",
                    "hashes": {
                        "md5": "31dbe8cc443d2ca7fd236ac00a52fb17",
                        "sha1": "2d6ca45061b7972312e00e5933fdff95bb90b61b",
                        "sha256": "aa3c461d4c21a392e372d0d6ca4ceb1e4d88098d587659454eaf4d93c661880f"
                    },
                    "name": "MORPH.EXE"
                }

            The top level property names in the dictionary are listed in the
            :class:`dxltieclient.constants.FirstInstanceEventProp` constants class.

            The information provided in the dictionary includes:

                * System the first instance of the file was found on
                * File information (file name and associated hashes)

        :param first_instance_dict: A Python ``dict`` (dictionary) containing the details of the first instance event
        :param original_event: The original DXL event message that was received
        """
        raise NotImplementedError("Must be implemented in a child class.")
