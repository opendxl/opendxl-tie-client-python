# This sample demonstrates invoking the McAfee Threat Intelligence Exchange (TIE)
# DXL service to retrieve the reputation of a file and certificate (as identified
# by their hashes). Further, this example demonstrates using the constants classes
# to examine specific fields within the reputation responses.

import os
import sys
import json

from dxlclient.client_config import DxlClientConfig
from dxlclient.client import DxlClient
from dxltieclient import TieClient
from dxltieclient.constants import HashType, ReputationProp, FileProvider, FileEnterpriseAttrib, \
    CertProvider, CertEnterpriseAttrib

# Import common logging and configuration
sys.path.append(os.path.dirname(os.path.abspath(__file__)) + "/..")
from common import *

# Configure local logger
logging.getLogger().setLevel(logging.ERROR)
logger = logging.getLogger(__name__)

# Create DXL configuration from file
config = DxlClientConfig.create_dxl_config_from_file(CONFIG_FILE)

# Hashes for the file to look up (notepad.exe)
# These can be replaced by a file which is known to have run within the enterprise for better results
FILE_MD5 = "f2c7bb8acc97f92e987a2d4087d021b1"
FILE_SHA1 = "7eb0139d2175739b3ccb0d1110067820be6abd29"
FILE_SHA256 = "142e1d688ef0568370c37187fd9f2351d7ddeda574f8bfa9b0fa4ef42db85aa2"

# Hashes for the certificate to look up
# These can be replaced by a certificate which is known to have run within the enterprise for better results
CERTIFICATE_BODY_SHA1 = "6EAE26DB8C13182A7947982991B4321732CC3DE2"
CERTIFICATE_PUBLIC_KEY_SHA1 = "3B87A2D6F39770160364B79A152FCC73BAE27ADF"

# Create the client
with DxlClient(config) as client:

    # Connect to the fabric
    client.connect()

    # Create the McAfee Threat Intelligence Exchange (TIE) client
    tie_client = TieClient(client)

    #
    # Perform the file reputation query
    #
    reputations_dict = \
        tie_client.get_file_reputation({
            HashType.MD5: FILE_MD5,
            HashType.SHA1: FILE_SHA1,
            HashType.SHA256: FILE_SHA256
        })

    print "File reputation response:"
    
    # Display the Global Threat Intelligence (GTI) trust level for the file
    if FileProvider.GTI in reputations_dict:
        gti_rep = reputations_dict[FileProvider.GTI]
        print "\tGlobal Threat Intelligence (GTI) trust level: " + \
              str(gti_rep[ReputationProp.TRUST_LEVEL])
    
    # Display the Enterprise reputation information
    if FileProvider.ENTERPRISE in reputations_dict:
        ent_rep = reputations_dict[FileProvider.ENTERPRISE]

        # Retrieve the enterprise reputation attributes
        ent_rep_attribs = ent_rep[ReputationProp.ATTRIBUTES]

        # Display prevalence (if it exists)
        if FileEnterpriseAttrib.PREVALENCE in ent_rep_attribs:
            print "\tEnterprise prevalence: " + \
                  ent_rep_attribs[FileEnterpriseAttrib.PREVALENCE]

        # Display first contact date (if it exists)
        if FileEnterpriseAttrib.FIRST_CONTACT in ent_rep_attribs:
            print "\tFirst contact: " + \
                  FileEnterpriseAttrib.to_localtime_string(
                      ent_rep_attribs[FileEnterpriseAttrib.FIRST_CONTACT])

    # Display the full file reputation response
    print "\nFull file reputation response:\n" + \
          json.dumps(reputations_dict, sort_keys=True, indent=4, separators=(',', ': '))

    #
    # Perform the certificate reputation query
    #

    reputations_dict = tie_client.get_certificate_reputation(
        CERTIFICATE_BODY_SHA1, CERTIFICATE_PUBLIC_KEY_SHA1)

    print "\nCertificate reputation response:"
    
    # Display the Global Threat Intelligence(GTI) trust level for the certificate
    if CertProvider.GTI in reputations_dict:
        gti_rep = reputations_dict[CertProvider.GTI]
        print "\tGlobal Threat Intelligence (GTI) trust level: " \
            + str(gti_rep[ReputationProp.TRUST_LEVEL])
    
    # Display the Enterprise reputation information
    if CertProvider.ENTERPRISE in reputations_dict:
        ent_rep = reputations_dict[CertProvider.ENTERPRISE]

        # Retrieve the enterprise reputation attributes
        ent_rep_attribs = ent_rep[ReputationProp.ATTRIBUTES]

        # Display prevalence (if it exists)
        if CertEnterpriseAttrib.PREVALENCE in ent_rep_attribs:
            print "\tEnterprise prevalence: " \
                + ent_rep_attribs[CertEnterpriseAttrib.PREVALENCE]

        # Display first contact date (if it exists)
        if CertEnterpriseAttrib.FIRST_CONTACT in ent_rep_attribs:
            print "\tFirst contact: " + \
                  CertEnterpriseAttrib.to_localtime_string(
                      ent_rep_attribs[CertEnterpriseAttrib.FIRST_CONTACT])

    # Display the full certificate response
    print "\nFull certificate reputation response:\n" + \
          json.dumps(reputations_dict, sort_keys=True, indent=4, separators=(',', ': '))