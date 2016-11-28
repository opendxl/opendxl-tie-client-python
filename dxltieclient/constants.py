"""
Constants for the numerical reputation levels used by TIE
"""
TIE_REPUTATION_KNOWN_TRUSTED = 99
TIE_REPUTATION_MOST_LIKELY_TRUSTER = 85
TIE_REPUTATION_MIGHT_BE_TRUSTED = 70
TIE_REPUTATION_UNKNOWN = 50
TIE_REPUTATION_MIGHT_BE_MALICIOUS = 30
TIE_REPUTATION_MOST_LIKELY_MALICIOUS = 15
TIE_REPUTATION_KNOWN_MALICIOUS = 1
TIE_REPUTATION_NOT_SET = 0
    
"""
Constants that are used to retrieve 

    The following statement:

        .. code-block:: python

            projections=[{
                "name": "HostInfo",
                "outputs": ["ip_address"]
            }]

    Can be rewritten to use :class:`ProjectionConstants` as follows:

        .. code-block:: python

            projections=[{
                ProjectionConstants.NAME: "HostInfo",
                ProjectionConstants.OUTPUTS: ["ip_address"]
            }]
"""

TRUST_LEVEL = "trustLevel"
PROVIDER_ID = "providerId"
CREATE_DATE = "createDate"
ATTRIBUTES = "attributes"

"""
Constants that are used to retrieve attributes from a reputation response

    The following statement:

        .. code-block:: python

            first_contact = response[0][ReputationConstants.ATTRIBUTES]["2102165"]

    Can be rewritten to use :class:`ReputationAttributeConstants` as follows:

        .. code-block:: python

            first_contact = response[0][ReputationConstants.ATTRIBUTES][ReputationAttributeConstants.ENTERPRISE_FILE_FIRST_CONTACT]
"""

# Enterprise Reputation Attributes
ENTERPRISE_FILE_FIRST_CONTACT = "2102165"
ENTERPRISE_FILE_PREVALENCE = "2101652"
ENTERPRISE_CERTIFICATE_FIRST_CONTACT = "2109589"
ENTERPRISE_CERTIFICATE_PREVALENCE = "2109333"
ENTERPRISE_ENTERPRISE_SIZE = "2111893"
ENTERPRISE_MINIMUM_LOCAL_REPUTATION = "2112148"
ENTERPRISE_MAXIMUM_LOCAL_REPUTATION = "2112404"
ENTERPRISE_AVERAGE_LOCAL_REPUTATION = "2112660"
ENTERPRISE_PARENT_MINIMUM_LOCAL_REPUTATION = "2112916"
ENTERPRISE_PARENT_MAXIMUM_LOCAL_REPUTATION = "2113172"
ENTERPRISE_PARENT_AVERAGE_LOCAL_REPUTATION = "2113428"
ENTERPRISE_FILE_NAME_COUNT = "2114965"
ENTERPRISE_DETECTION_COUNT = "2113685"
ENTERPRISE_LAST_DETECTION_TIME = "2113942"
ENTERPRISE_PREVALENT = "2123156"
ENTERPRISE_PARENT_FILE_REPUTATIONS = "2113942"
ENTERPRISE_CHILD_FILE_REPUTATIONS = "2123156"
ENTERPRISE_PARENT_FILE_REPUTATIONS = "2113942"

# GTI Reputation Attributes
GTI_FILE_PREVALENCE = "2102421"
GTI_FILE_FIRST_CONTACT = "2101908"
GTI_ORIGINAL_RESPONSE = "2120340"
GTI_CERTIFICATE_PREVALENCE = "2108821"
GTI_CERTIFICATE_FIRST_CONTACT = "2109077"

# ATD Reputation Attributes
ATD_GAM_SCORE = "4194962"
ATD_AV_ENGINE_SCORE = "4195218"
ATD_SANDBOX_SCORE = "4195474"
ATD_VERDICT = "4195730"
ATD_BEHAVIORS = "4197784"
    
"""
Constants used in the response list for a get_file_first_references call

    The following statement:

        .. code-block:: python

            date = response[0]["date"]
            agent_guid = response[0]["agentGuid"]

    Can be rewritten to use :class:`FileFirstReferencesConstants` as follows:

        .. code-block:: python

            date = response[0][FileFirstReferencesConstants.DATE]
            agent_guid = response[0][FileFirstReferencesConstants.AGENT_GUID]
            
"""
DATE = "date"
AGENT_GUID = "agentGuid"

"""
Constants that are used to identify reputation providers in reputation responses

    The following statement:

        .. code-block:: python

            for reputation in response:
                if reputation[ReputationConstants.PROVIDER_ID] == 3:
                    print reputation[ReputationConstants.TRUST_LEVEL]

    Can be rewritten to use :class:`ReputationProviderConstants` as follows:

        .. code-block:: python

            for reputation in response:
                if reputation[ReputationConstants.PROVIDER_ID] == ReputationProviderConstants.FILE_ENTERPRISE_PROVIDER:
                    print reputation[ReputationConstants.TRUST_LEVEL]
"""

# Reputation Provider Constants
FILE_GTI_PROVIDER = 1
FILE_ENTERPRISE_PROVIDER = 3
FILE_ATD_PROVIDER = 5
FILE_MWG_PROVIDER = 7

CERTIFICATE_GTI_PROVIDER = 2
CERTIFICATE_ENTERPRISE_PROVIDER = 4
	
"""
Constants for the numerical reputation levels used by ATD
"""
ATD_REPUTATION_NOT_SET = -2
ATD_REPUTATION_KNOWN_TRUSTED = -1
ATD_REPUTATION_MOST_LIKELY_TRUSTER = 0
ATD_REPUTATION_MIGHT_BE_TRUSTED = 1
ATD_REPUTATION_UNKNOWN = 2
ATD_REPUTATION_MIGHT_BE_MALICIOUS = 3
ATD_REPUTATION_MOST_LIKELY_MALICIOUS = 4
ATD_REPUTATION_KNOWN_MALICIOUS = 5
