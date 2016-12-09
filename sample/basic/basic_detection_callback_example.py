# This sample demonstrates registering a DetectionCallback
# with the DXL fabric to receive detection events when detections
# occur on managed systems.

import logging
import os
import sys
import time
import json

from dxlclient.client import DxlClient
from dxlclient.client_config import DxlClientConfig
from dxltieclient import TieClient, DetectionCallback

# Import common logging and configuration
sys.path.append(os.path.dirname(os.path.abspath(__file__)) + "/..")
from common import *

# Configure local logger
logging.getLogger().setLevel(logging.ERROR)
logger = logging.getLogger(__name__)

# Create DXL configuration from file
config = DxlClientConfig.create_dxl_config_from_file(CONFIG_FILE)


class MyDetectionCallback(DetectionCallback):
    """
    My detection callback
    """
    def on_detection(self, detection_dict, original_event):
        # Display the DXL topic that the event was received on
        print "Detection on topic: " + original_event.destination_topic

        # Dump the dictionary
        print json.dumps(detection_dict,
                         sort_keys=True, indent=4, separators=(',', ': '))

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

    # Wait forever
    print "Waiting for detection events..."
    while True:
        time.sleep(60)
