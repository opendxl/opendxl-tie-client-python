# This sample demonstrates registering a ReputationChangeCallback with the
# DXL fabric to receive reputation change events sent by the
# McAfee Threat Intelligence Exchange (TIE) DXL service when the reputation
# of a file or certificate changes.

import logging
import os
import sys
import time
import json

from dxlclient.client import DxlClient
from dxlclient.client_config import DxlClientConfig
from dxltieclient import TieClient, ReputationChangeCallback

# Import common logging and configuration
sys.path.append(os.path.dirname(os.path.abspath(__file__)) + "/..")
from common import *

# Configure local logger
logging.getLogger().setLevel(logging.ERROR)
logger = logging.getLogger(__name__)

# Create DXL configuration from file
config = DxlClientConfig.create_dxl_config_from_file(CONFIG_FILE)


class MyReputationChangeCallback(ReputationChangeCallback):
    """
    My reputation change callback
    """
    def on_reputation_change(self, rep_change_dict, original_event):
        # Display the DXL topic that the event was received on
        print "Reputation change on topic: " + original_event.destination_topic

        # Dump the dictionary
        print json.dumps(rep_change_dict,
                         sort_keys=True, indent=4, separators=(',', ': '))

# Create the client
with DxlClient(config) as client:

    # Connect to the fabric
    client.connect()

    # Create the McAfee Threat Intelligence Exchange (TIE) client
    tie_client = TieClient(client)

    # Create reputation change callback
    rep_change_callback = MyReputationChangeCallback()

    # Register callbacks with client to receive both file and certificate reputation change events
    tie_client.add_file_reputation_change_callback(rep_change_callback)
    tie_client.add_certificate_reputation_change_callback(rep_change_callback)

    # Wait forever
    print "Waiting for reputation change events..."
    while True:
        time.sleep(60)
