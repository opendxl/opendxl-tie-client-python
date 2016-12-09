# This sample demonstrates invoking the McAfee Threat Intelligence Exchange
# (TIE) DXL service to set the trust level of a file (as identified
# by its hashes)

import logging
import os
import sys

from dxlclient.client import DxlClient
from dxlclient.client_config import DxlClientConfig
from dxltieclient import TieClient
from dxltieclient.constants import HashType, TrustLevel

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

    # Set the Enterprise reputation for notepad.exe to Known Trusted
    tie_client.set_file_reputation(
        TrustLevel.KNOWN_TRUSTED, {
            HashType.MD5: "f2c7bb8acc97f92e987a2d4087d021b1",
            HashType.SHA1: "7eb0139d2175739b3ccb0d1110067820be6abd29",
            HashType.SHA256: "142e1d688ef0568370c37187fd9f2351d7ddeda574f8bfa9b0fa4ef42db85aa2"
        },
        filename="notepad.exe",
        comment="Reputation set via OpenDXL")

    print "Succeeded."
