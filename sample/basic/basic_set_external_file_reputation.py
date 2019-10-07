# This sample demonstrates invoking the McAfee Threat Intelligence Exchange
# (TIE) DXL service to set the trust level of a file as an external provider
# (as identified by its hashes)
from __future__ import absolute_import
from __future__ import print_function

import hashlib
import logging
import os
import sys
import time

from dxlclient.client import DxlClient
from dxlclient.client_config import DxlClientConfig

from dxltieclient import TieClient
from dxltieclient.constants import HashType, TrustLevel, FileType, FileProvider, ReputationProp

# Import common logging and configuration
sys.path.append(os.path.dirname(os.path.abspath(__file__)) + "/..")
from common import *

# Configure local logger
logging.getLogger().setLevel(logging.ERROR)
logger = logging.getLogger(__name__)

# Create DXL configuration from file
config = DxlClientConfig.create_dxl_config_from_file(CONFIG_FILE)

# Random values for testing
random = time.time()
fileMD5 = hashlib.md5(str(random).encode('utf-8')).hexdigest()
fileSHA1 = hashlib.sha1(str(random).encode('utf-8')).hexdigest()
fileSHA256 = hashlib.sha256(str(random).encode('utf-8')).hexdigest()

# Create the client
with DxlClient(config) as client:
    # Connect to the fabric
    client.connect()

    # Create the McAfee Threat Intelligence Exchange (TIE) client
    tie_client = TieClient(client)

    #
    # Hashes for the file whose reputation will be set.
    #
    # Replace the random values for the actual file hashes.
    #
    hashes = {
        HashType.MD5: fileMD5,
        HashType.SHA1: fileSHA1,
        HashType.SHA256: fileSHA256
    }
    #
    # Request reputation for the file
    #
    reputations_dict = tie_client.get_file_reputation(hashes)
    #
    # Check if there's any definitive reputation (different to Not Set [0] and Unknown [50])
    # for any provider except for External Provider (providerId=15)
    #
    has_definitive_reputation = \
        any([rep[ReputationProp.TRUST_LEVEL] != TrustLevel.NOT_SET
             and rep[ReputationProp.TRUST_LEVEL] != TrustLevel.UNKNOWN
             and rep[ReputationProp.PROVIDER_ID] != FileProvider.EXTERNAL
             for rep in reputations_dict.values()])

    if has_definitive_reputation:
        print("Abort: There is a reputation from another provider for the file, "
              "External Reputation is not necessary.")
    else:
        #
        # Set the External reputation for a the file "random.exe" to Might Be Trusted
        #
        try:
            tie_client.set_external_file_reputation(
                TrustLevel.MIGHT_BE_TRUSTED,
                hashes,
                FileType.PEEXE,
                filename="random.exe",
                comment="External Reputation set via OpenDXL")
            print("Event Sent")
        except ValueError as e:
            print("Error: " + str(e))
