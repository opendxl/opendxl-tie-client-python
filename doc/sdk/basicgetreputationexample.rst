Basic Get Reputation Example
============================

This sample demonstrates invoking the McAfee Threat Intelligence Exchange (TIE) DXL service to retrieve the
reputation of files (as identified by their hashes).

This is the same sample that is available in the OpenDXL Python SDK
(see `Threat Intelligence Exchange (TIE) File Reputation Sample <https://opendxl.github.io/opendxl-client-python/pydoc/tiefilerepexample.html>`_),
but has been refactored to use the McAfee Threat Intelligence Exchange (TIE) DXL client library.

Prerequisites
*************
* The samples configuration step has been completed (see :doc:`sampleconfig`)
* A McAfee Threat Intelligence Exchange (TIE) Service is available on the DXL fabric

Running
*******

To run this sample execute the ``sample/basic/basic_get_reputation_example.py`` script as follows:

    .. parsed-literal::

        c:\\dxltieclient-python-sdk-\ |version|\>python sample/basic/basic_get_reputation_example.py

The output should appear similar to the following:

    .. code-block:: python

        Notepad.exe reputations:
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
                    "2101652": "233",
                    "2102165": "1476902802",
                    "2111893": "242",
                    "2114965": "4",
                    "2139285": "73183493944770750"
                },
                "createDate": 1476902802,
                "providerId": 3,
                "trustLevel": 99
            }
        }

        EICAR reputations:
        {
            "1": {
                "attributes": {
                    "2120340": "2139162632"
                },
                "createDate": 1480616574,
                "providerId": 1,
                "trustLevel": 1
            },
            "3": {
                "attributes": {
                    "2101652": "120",
                    "2102165": "1476902803",
                    "2111893": "242",
                    "2114965": "0",
                    "2139285": "73183493944770750"
                },
                "createDate": 1476902803,
                "providerId": 3,
                "trustLevel": 0
            }
        }

The sample outputs the file reputation for two files.

The `key` for each entry in the ``dict`` (dictionary) corresponds to a particular `provider` of the
associated `reputation`. The list of `file reputation providers` can be found in the
:class:`dxltieclient.constants.FileProvider` constants class.

The first file queried in the TIE service is “notepad.exe”. The McAfee Global Threat Intelligence (GTI) service is
identified in the results as ``"providerId" : 1``. The trust level associated with the GTI response
(``"trustLevel": 99``) indicates that the file is known good.

The second file queried in the TIE service is the “EICAR Standard Anti-Virus Test File”. The trust level associated
with the GTI response (``"trustLevel": 1``) indicates that the file is known bad.

See the :class:`dxltieclient.constants.TrustLevel` constants class for the list of standard trust levels.

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

Once a connection is established to the DXL fabric, a :class:`dxltieclient.client.TieClient` instance is created
which will be used to communicate with the TIE DXL services.

For each file whose reputations are retrieved, a call is made to the
:func:`dxltieclient.client.TieClient.get_file_reputation` method of the :class:`dxltieclient.client.TieClient`
instance along with the hash values that are used to identify the file.

The reputations that are received for each file are printed by converting the response ``dict`` (dictionary) to
JSON.


