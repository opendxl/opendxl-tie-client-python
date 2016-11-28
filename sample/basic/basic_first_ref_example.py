# This sample demonstrates invoking the McAfee Threat Intelligence Exchange
# (TIE) DXL service to retrieve the agents which have run a file(as identified
# by its hash)

import logging
import os
import sys
import json
import base64
import time

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

# Hashes for the file to look up(notepad.exe)
# These can be replaced by a file which is known to have run within the enterprise for better results
FILE_SHA1 = "7eb0139d2175739b3ccb0d1110067820be6abd29"
FILE_MD5 = "f2c7bb8acc97f92e987a2d4087d021b1"

# Create the client
with DxlClient(config) as client:

    # Connect to the fabric
    client.connect()

    # Create the McAfee Threat Intelligence Exchange(TIE) client
    tie_client = TieClient(client)

    #
    # Request the agents which have run notepad.exe
    #
    response_list = tie_client.get_file_first_references({
        "sha1": FILE_SHA1,
        "md5": FILE_MD5
    })
    print "\nAgents that have run this file:\n"
    for agent in response_list:
        print "\n" + agent[AGENT_GUID] + ": " \
        + time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(float(agent[DATE])))