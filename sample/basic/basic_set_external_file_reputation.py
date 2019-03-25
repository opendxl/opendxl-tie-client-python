# This sample demonstrates invoking the McAfee Threat Intelligence Exchange
# (TIE) DXL service to set the trust level of a file as an external provider
# (as identified by its hashes)
from __future__ import absolute_import
from __future__ import print_function
import logging
import os
import sys

from dxlclient.client import DxlClient
from dxlclient.client_config import DxlClientConfig
from dxltieclient import TieClient
from dxltieclient.constants import HashType, TrustLevel, FileProvider, FileType

# Import common logging and configuration
sys.path.append(os.path.dirname(os.path.abspath(__file__)) + "/..")
from common import *

# Configure local logger
logging.getLogger().setLevel(logging.ERROR)
logger = logging.getLogger(__name__)

# Create DXL configuration from file
config = DxlClientConfig.create_dxl_config_from_file(CONFIG_FILE)


# Topic used to set external reputation of a file
EVENT_TOPIC_CUSTOM_FILE_REPORT = "/mcafee/event/custom/file/report"

# Create the client
with DxlClient(config) as client:

    # Connect to the fabric
    client.connect()

    # Create the McAfee Threat Intelligence Exchange (TIE) client
    tie_client = TieClient(client)

    # Hashes for the file whose reputation should be set. These use the hashes for
    # a random file "file.exe" by default but could be replaced with appropriate values for the
    # file whose reputation should be set.
    hashes = {
        HashType.MD5: "f2c7bb8acc97f92e987a2d4087d021b1",
        HashType.SHA1: "7eb0139d2175739b3ccb0d1110067820be6abd29",
        HashType.SHA256: "142e1d688ef0568370c37187fd9f2351d7ddeda574f8bfa9b0fa4ef42db85aa2"
    }
    #
    # Request and display reputation for file.exe
    #
    reputations_dict = tie_client.get_file_reputation(hashes)
    set_reputation = True
    for key in reputations_dict:
        # To minimize redundancy and conflict among providers ensure there is no other reputation with a relevant score,
        # detection content will only follow external provider as a fallback
        if key != 11:
            # If the oficial providers do not have a reputation for the specified file or is unknown and the external reputation
            # does not have conflicts with the oficial provider's reputation, then the reputation can be set
            if reputations_dict[key]["trustLevel"] != 50 and reputations_dict[key]["trustLevel"] != 0:
                set_reputation = False
                break

    if set_reputation:
        # Set the External reputation for a random file "file.exe" to Known Trusted
        try:
            tie_client.set_external_file_reputation(
                TrustLevel.KNOWN_TRUSTED,
                hashes,
                FileType.PEEXE,
                filename="file.exe",
                comment="Reputation set via OpenDXL")
            print("Event Sent")
        except ValueError as e:
            print("Error: "+ str(e))
    else:
        print("Error: The reputation you try to set has conflicts with the current reputation")



