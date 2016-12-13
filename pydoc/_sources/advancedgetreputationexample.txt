Advanced Get Reputation Example
===============================

This sample demonstrates invoking the McAfee Threat Intelligence Exchange (TIE) DXL service to retrieve the
reputation of a file and certificate (as identified by their hashes). Further, this example demonstrates using
the constants classes in the :class:`dxltieclient.constants` package to examine specific fields within the
reputation responses.

Prerequisites
*************
* The samples configuration step has been completed (see :doc:`sampleconfig`)
* A McAfee Threat Intelligence Exchange (TIE) Service is available on the DXL fabric

Running
*******

To run this sample execute the ``sample/advanced/advanced_get_reputation_example.py`` script as follows:

    .. parsed-literal::

        c:\\dxltieclient-python-sdk-\ |version|\>python sample/advanced/advanced_get_reputation_example.py

The output should appear similar to the following:

    .. code-block:: python

        File reputation response:
            Global Threat Intelligence (GTI) trust level: 99
            Enterprise prevalence: 242
            First contact: 2016-10-19 11:46:42

        Full file reputation response:
        {
            "1": {
                "attributes": {
                    "2120340": "2139160704"
                },
                "createDate": 1480455704,
                "providerId": 1,
                "trustLevel": 99
            },
            "3": {
                "attributes": {
                    "2101652": "242",
                    "2102165": "1476902802",
                    "2111893": "251",
                    "2114965": "4",
                    "2139285": "73183493944770750"
                },
                "createDate": 1476902802,
                "providerId": 3,
                "trustLevel": 99
            }
        }

        Certificate reputation response:
            Global Threat Intelligence (GTI) trust level: 99
            Enterprise prevalence: 12
            First contact: 2016-10-12 17:28:34

        Full certificate reputation response:
        {
            "2": {
                "attributes": {
                    "2108821": "94",
                    "2109077": "1454912619",
                    "2117524": "0",
                    "2120596": "0"
                },
                "createDate": 1476318514,
                "providerId": 2,
                "trustLevel": 99
            },
            "4": {
                "attributes": {
                    "2109333": "12",
                    "2109589": "1476318514",
                    "2139285": "73183493944770750"
                },
                "createDate": 1476318514,
                "providerId": 4,
                "trustLevel": 0
            }
        }

The sample outputs the reputation information for a file and a certificate.

In addition to dumping all of the reputation information received, this sample pulls out three specific
properties for the file and certificate:

    * The Global Threat Intelligence (GTI) trust level
    * The prevalence of the file or certificate within the enterprise
    * The first time the file or certificate was found within the enterprise

Details
*******

The majority of the sample code is shown below:

    .. code-block:: python

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

Once a connection is established to the DXL fabric, a :class:`dxltieclient.client.TieClient` instance is created
which will be used to communicate with the TIE DXL services.

To request the reputation of the file, a call is made to the
:func:`dxltieclient.client.TieClient.get_file_reputation` method of the :class:`dxltieclient.client.TieClient`
instance along with the hash values that are used to identify the file.

To request the reputation of the certificate, a call is made to the
:func:`dxltieclient.client.TieClient.get_certificate_reputation` method of the :class:`dxltieclient.client.TieClient`
instance along with the hash values that are used to identify the certificate.

Once reputations are received, the constants classes in the :class:`dxltieclient.constants` module are
used to examine specific fields within the reputation responses.


