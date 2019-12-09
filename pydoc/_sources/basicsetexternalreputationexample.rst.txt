Basic Set External Reputation Example
=====================================

This sample demonstrates invoking the McAfee Threat Intelligence Exchange (TIE) DXL service to set the
External Provider `trust level` of a file (as identified by its hashes).

Prerequisites
*************
* The samples configuration step has been completed (see :doc:`sampleconfig`)
* A McAfee Threat Intelligence Exchange (TIE) Service is available on the DXL fabric
* TIE Server version is 3.0.0 or above
* The Python client must be authorized to send messages to the ``/mcafee/event/external/file/report``
  topic which is part of the ``TIE Server Set External Reputation`` authorization group.

  The following page provides an example of authorizing a Python client to send messages to an
  `authorization group`. While the example is based on McAfee Active Response (MAR), the
  instructions are the same with the exception of swapping the ``TIE Server Set External Reputation``
  `authorization group` in place of ``Active Response Server API``:

  `<https://opendxl.github.io/opendxl-client-python/pydoc/marsendauth.html>`_

Running
*******

To run this sample execute the ``sample/basic/basic_set_external_file_reputation.py`` script as follows:

    .. parsed-literal::

        c:\\dxltieclient-python-sdk-\ |version|\>python sample/basic/basic_set_external_file_reputation.py

If the `set external reputation` operation succeeds the following message will be displayed:

    .. code-block:: python

        Event Sent.

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
            # Hashes for the file whose reputation will be set.
            #
            hashes = {
                HashType.MD5: <FILE MD5>,
                HashType.SHA1: <FILE SHA1>,
                HashType.SHA256: <FILE SHA256>
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
                print("Abort: There is a reputation from another provider for the file, External Reputation is not necessary.")
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

Once a connection is established to the DXL fabric, a :class:`dxltieclient.client.TieClient` instance is created
which will be used to communicate with the TIE DXL services.

The recommended workflow is to first check the reputation for the file, and avoid setting the External Provider
`trust level` if the response already includes a definitive reputation. This is because External Provider
will be used as a fallback, only if no other reputation is available.

The External Provider `trust level` is then established for the file by invoking the
:func:`dxltieclient.client.TieClient.set_external_file_reputation` method of the :class:`dxltieclient.client.TieClient`
instance along with the `hash values` used to identify the file.

The ``filename``, ``filetype`` and ``comment`` fields are optional, but are useful in identifying the particular
file that is associated with the hashes (especially if the file did not previously exist in the TIE repository).

