# This sample demonstrates invoking the McAfee Threat Intelligence Exchange
# (TIE) DXL service to retrieve the reputation of files (as identified
# by their hashes)

import logging
import os
import sys
import json

from dxlclient.client import DxlClient
from dxlclient.client_config import DxlClientConfig
from dxltieclient import TieClient
from dxltieclient.constants import HashType


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

    # Create the McAfee Threat Intelligence Exchange (TIE) client
    tie_client = TieClient(client)

    #
    # Request and display reputation for notepad.exe
    #
    reputations_dict = \
        tie_client.get_file_reputation({
            HashType.MD5: "f2c7bb8acc97f92e987a2d4087d021b1",
            HashType.SHA1: "7eb0139d2175739b3ccb0d1110067820be6abd29",
            HashType.SHA256: "142e1d688ef0568370c37187fd9f2351d7ddeda574f8bfa9b0fa4ef42db85aa2"
        })
    print "Notepad.exe reputations:"
    print json.dumps(reputations_dict,
                     sort_keys=True, indent=4, separators=(',', ': ')) + "\n"

    #
    # Request and display reputation for EICAR
    #
    reputations_dict = \
        tie_client.get_file_reputation({
            HashType.MD5: "44d88612fea8a8f36de82e1278abb02f",
            HashType.SHA1: "3395856ce81f2b7382dee72602f798b642f14140",
            HashType.SHA256: "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"

        })
    print "EICAR reputations:"
    print json.dumps(reputations_dict,
                     sort_keys=True, indent=4, separators=(',', ': '))
