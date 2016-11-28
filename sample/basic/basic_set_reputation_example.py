# This sample demonstrates invoking the McAfee Threat Intelligence Exchange
# (TIE) DXL service to retrieve the reputation of files (as identified
# by their hashes)

import logging
import os
import sys
import json
import base64

from dxlclient.client import DxlClient
from dxlclient.client_config import DxlClientConfig
from dxltieclient import TieClient
from dxltieclient.constants import *

# Import common logging and configuration
sys.path.append(os.path.dirname(os.path.abspath(__file__)) + "/..")
from common import *

# Configure local logger
logging.getLogger().setLevel(logging.ERROR)
logger = logging.getLogger(__name__)

# Create DXL configuration from file
config = DxlClientConfig.create_dxl_config_from_file(CONFIG_FILE)

# Create the client
with DxlClient(config) as client:

    # Connect to the fabric
    client.connect()

    # Create the McAfee Threat Intelligence Exchange(TIE) client
    tie_client = TieClient(client)

    #
    # Set the enterprise reputation for notepad.exe to Known Trusted
    #
    response_dict = tie_client.set_file_reputation({
        "sha1": "7eb0139d2175739b3ccb0d1110067820be6abd29",
        "md5": "f2c7bb8acc97f92e987a2d4087d021b1"
    }, TIE_REPUTATION_KNOWN_TRUSTED, filename="notepad.exe",
    comment="Reputation override set via OpenDXL")