# This sample demonstrates registering a FirstInstanceCallback with the
# DXL fabric. The callback will receive first instance events when files
# are encountered for the first time within the local enterprise.

import logging
import os
import sys
import time
import json

from dxlclient.client import DxlClient
from dxlclient.client_config import DxlClientConfig
from dxltieclient import TieClient, FirstInstanceCallback

# Import common logging and configuration
sys.path.append(os.path.dirname(os.path.abspath(__file__)) + "/..")
from common import *

# Configure local logger
logging.getLogger().setLevel(logging.ERROR)
logger = logging.getLogger(__name__)

# Create DXL configuration from file
config = DxlClientConfig.create_dxl_config_from_file(CONFIG_FILE)


class MyFirstInstanceCallback(FirstInstanceCallback):
    """
    My first instance callback
    """
    def on_first_instance(self, first_instance_dict, original_event):
        # Display the DXL topic that the event was received on
        print "First instance on topic: " + original_event.destination_topic

        # Dump the dictionary
        print json.dumps(first_instance_dict,
                         sort_keys=True, indent=4, separators=(',', ': '))

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

    # Wait forever
    print "Waiting for first instance events..."
    while True:
        time.sleep(60)
