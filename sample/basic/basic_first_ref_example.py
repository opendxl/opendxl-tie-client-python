# This sample demonstrates invoking the McAfee Threat Intelligence Exchange
# (TIE) DXL service to retrieve the set of systems which have referenced
# (typically executed) a file (as identified by hashes).

import logging
import os
import sys

from dxlclient.client import DxlClient
from dxlclient.client_config import DxlClientConfig
from dxltieclient import TieClient
from dxltieclient.constants import FirstRefProp, HashType

# Import common logging and configuration
sys.path.append(os.path.dirname(os.path.abspath(__file__)) + "/..")
from common import *

# Configure local logger
logging.getLogger().setLevel(logging.ERROR)
logger = logging.getLogger(__name__)

# Create DXL configuration from file
config = DxlClientConfig.create_dxl_config_from_file(CONFIG_FILE)

FILE_MD5 = "<specify the MD5 for the file>"
FILE_SHA1 = "<specify the SHA-1 for the file>"
FILE_SHA256 = "<specify the SHA-256 for the file>"

# Create the client
with DxlClient(config) as client:

    # Connect to the fabric
    client.connect()

    # Create the McAfee Threat Intelligence Exchange (TIE) client
    tie_client = TieClient(client)

    # Get the list of systems that have referenced the file
    system_list = \
        tie_client.get_file_first_references({
            HashType.MD5: FILE_MD5,
            HashType.SHA1: FILE_SHA1,
            HashType.SHA256: FILE_SHA256
        })

    print "\nSystems that have referenced the file:\n"
    for system in system_list:
        print "\t" + system[FirstRefProp.SYSTEM_GUID] + ": " + \
                FirstRefProp.to_localtime_string(system[FirstRefProp.DATE])
