# -*- coding: utf-8 -*-
################################################################################
# Copyright (c) 2016 McAfee Inc. - All Rights Reserved.
################################################################################

import base64
import json
import logging
from dxlclient import Request, Message
from constants import *

# TIE File Reputation Topics
TIE_SET_FILE_REPUTATION_TOPIC = "/mcafee/service/tie/file/reputation/set"
TIE_GET_FILE_REPUTATION_TOPIC = "/mcafee/service/tie/file/reputation"

# TIE Certificate Reputation Topics
TIE_SET_CERT_REPUTATION_TOPIC = "/mcafee/service/tie/cert/reputation/set"
TIE_GET_CERT_REPUTATION_TOPIC = "/mcafee/service/tie/cert/reputation"

# TIE file first reference topic
TIE_GET_FILE_FIRST_REFS = "/mcafee/service/tie/file/agents"

# TIE event topics
TIE_EVENT_FILE_DETECTION_TOPIC = "/mcafee/event/tie/file/detection"
TIE_EVENT_FILE_REPUTATION_CHANGE_TOPIC = "/mcafee/event/tie/file/repchange/broadcast"
TIE_EVENT_FILE_FIRST_INSTANCE_TOPIC = "/mcafee/event/tie/file/firstinstance"
TIE_EVENT_FILE_PREVALENCE_CHANGE_TOPIC = "/mcafee/event/tie/file/prevalence"
TIE_EVENT_CERTIFICATE_REPUTATION_CHANGE_TOPIC = "/mcafee/event/tie/cert/repchange/broadcast"

class TieClient(object):
    """
    This client provides a high level wrapper for communicating with the 
    McAfee Threat Intelligence Echange(TIE) DXL service.

    The purpose of this client is to allow the user to perform TIE queries without having to focus on
    lower-level details such as TIE-specific DXL topics and message formats.
    """
    
    # The default amount of time (in seconds) to wait for a response from the TIE server
    __DEFAULT_RESPONSE_TIMEOUT = 30
    # The minimum amount of time (in seconds) to wait for a response from the TIE server
    __MIN_RESPONSE_TIMEOUT = 30
    
    def __init__(self, dxl_client):
        """
        Constructs the Threat Intelligence Exchange client

        :param dxl_client: The DXL client to use for communication with the TIE service
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

    def set_file_reputation(self, hashes, reputation_level, filename="", comment="", 
            provider_id=FILE_ENTERPRISE_PROVIDER):
        """
        Sets the reputation for the specified file

        :param hashes: A dictionary of the hashes identifying this file
        :param reputation_level: The reputation level of the file
        :param filename: A filename to set for association with this file
        :param comment: A comment for this reputation change
        :param provider_id: The provider ID for this file
        """
        # Create the request message
        req = Request(TIE_SET_FILE_REPUTATION_TOPIC)

        # Create a dictionary for the payload
        payload_dict = {
            "trustLevel": reputation_level,
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
        Gets the TIE reputations for the specified file

        :param hashes: A dictionary of the hashes identifying this file
        :return: A dictionary of provider ID to reputation
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
                reputation_dict[reputation[PROVIDER_ID]] = reputation
            return reputation_dict
        else:
            return {}
        
    def set_certificate_reputation(self, sha1, public_key_sha1, reputation_level, comment="", 
            provider_id=CERTIFICATE_ENTERPRISE_PROVIDER):
        """
        Sets the reputation for the specified certificate

        :param sha1: The SHA1 of the certificate body
        :param public_key_sha1: The SHA1 of the certificate's public key
        :param reputation_level: The reputation level of the certificate
        :param comment: A comment for this reputation change
        :param provider_id: The provider ID to set this reputation as
        """
        # Create the request message
        req = Request(TIE_SET_CERT_REPUTATION_TOPIC)

        # Create a dictionary for the payload
        payload_dict = {
            "trustLevel": reputation_level,
            "providerId": provider_id,
            "publicKeySha1": base64.b64encode(public_key_sha1.decode('hex')),
            "comment": comment,
            "hashes": [
                {"type": "sha1", "value": base64.b64encode(sha1.decode('hex'))}
            ]}

        # Set the payload
        req.payload = json.dumps(payload_dict).encode()

        # Send the request
        self.__dxl_sync_request(req)

    def get_certificate_reputation(self, sha1, public_key_sha1):
        """
        Gets the reputation for the specified certificate

        :param sha1: The SHA1 of the certificate body
        :param public_key_sha1: The SHA1 of the certificate's public key
        :return: A dictionary of provider ID to reputation
        """
        # Create the request message
        req = Request(TIE_GET_CERT_REPUTATION_TOPIC)

        # Create a dictionary for the payload
        payload_dict = {
            "publicKeySha1": base64.b64encode(public_key_sha1.decode('hex')),
            "hashes": [
                {"type": "sha1", "value": base64.b64encode(sha1.decode('hex'))}
            ]}

        # Set the payload
        req.payload = json.dumps(payload_dict).encode()

        # Send the request
        response = self.__dxl_sync_request(req)
        
        resp_dict = json.loads(response.payload.decode())

        # Return the reputations list
        if "reputations" in resp_dict:
            reputation_dict = {}
            for reputation in resp_dict["reputations"]:
                reputation_dict[reputation[PROVIDER_ID]] = reputation
            return reputation_dict
        else:
            return []

    def get_file_first_references(self, hashes, query_limit=500):
        """
        Gets the agents which have run the specified file

        :param hashes: A dictionary of the hashes for the file to search by
        :param query_limit: The maximum number of results to return
        :return: A list of agent dictionary items
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
