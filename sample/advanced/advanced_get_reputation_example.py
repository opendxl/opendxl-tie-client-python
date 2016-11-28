# This sample queries a Threat Intelligence Exchange server for the reputations
# of a file and a certificate and displays the result

import os
import sys
import time
import json

from dxlclient.client_config import DxlClientConfig
from dxlclient.client import DxlClient
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

# Hashes for the certificate to look up
# These can be replaced by a certificate which is known to have run within the enterprise for better results
CERTIFICATE_BODY_SHA1 = "a14595d402f9579085f0a9dcb9d79fc17ea57b67"
CERTIFICATE_PUBLIC_KEY_SHA1 = "a14595d402f9579085f0a9dcb9d79fc17ea57b67"

# Create the client
with DxlClient(config) as client:

    # Connect to the fabric
    client.connect()

    # Create the McAfee Threat Intelligence Exchange(TIE) client
    tie_client = TieClient(client)

    # Prepare the dictionary of SHA1 and MD5 hases for the desired file
    file_hash_dict = {
        "sha1": FILE_SHA1,
        "md5": FILE_MD5
    }
    
    # Perform the file reputation query
    response = tie_client.get_file_reputation(file_hash_dict)
    
    print "\n\nFile Reputation Response:\n\n"
    
    # Display the Global Threat Intelligence(GTI) trust level for the file
    if FILE_GTI_PROVIDER in response:
        print "Global Threat Intelligence(GTI) Trust Level: " \
        + str(response[FILE_GTI_PROVIDER][TRUST_LEVEL])
    
    # Display the Enterprise prevalence if it exists
    if ENTERPRISE_FILE_PREVALENCE in response[FILE_ENTERPRISE_PROVIDER][ATTRIBUTES]:
        print "Enterprise Prevalence: " \
        + str(response[FILE_ENTERPRISE_PROVIDER][ATTRIBUTES][ENTERPRISE_FILE_PREVALENCE])
        
    # Display the first contact date
    if ENTERPRISE_FILE_FIRST_CONTACT in response[FILE_ENTERPRISE_PROVIDER][ATTRIBUTES]:
        first_contact_epoch = response[FILE_ENTERPRISE_PROVIDER][ATTRIBUTES][ENTERPRISE_FILE_FIRST_CONTACT]
        print "First Contact: " \
        + time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(float(first_contact_epoch)))

    # Display the full response
    print "\n\nFull Response:\n" + json.dumps(response, sort_keys=True, indent=4, separators=(',', ': '))
    
    # Perform the certificate reputation query
    response = tie_client.get_certificate_reputation(CERTIFICATE_BODY_SHA1, CERTIFICATE_PUBLIC_KEY_SHA1)
    
    print "\n\nCertificate Reputation Response:\n\n"
    
    # Display the Global Threat Intelligence(GTI) trust level for the certificate
    if CERTIFICATE_GTI_PROVIDER in response:
        print "Global Threat Intelligence(GTI) Trust Level: " \
        + str(response[CERTIFICATE_GTI_PROVIDER][TRUST_LEVEL])
    
    # Display the Enterprise prevalence if it exists
    if ENTERPRISE_CERTIFICATE_PREVALENCE in response[CERTIFICATE_ENTERPRISE_PROVIDER][ATTRIBUTES]:
        print "Enterprise Prevalence: " \
        + str(response[CERTIFICATE_ENTERPRISE_PROVIDER][ATTRIBUTES][ENTERPRISE_CERTIFICATE_PREVALENCE])
        
    # Display the first contact date
    if ENTERPRISE_CERTIFICATE_FIRST_CONTACT in response[CERTIFICATE_ENTERPRISE_PROVIDER][ATTRIBUTES]:
        first_contact_epoch = response[CERTIFICATE_ENTERPRISE_PROVIDER][ATTRIBUTES][ENTERPRISE_CERTIFICATE_FIRST_CONTACT]
        print "First Contact: " \
        + time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(float(first_contact_epoch)))

    # Display the full response
    print "\n\nFull Response:\n" + json.dumps(response, sort_keys=True, indent=4, separators=(',', ': '))
    