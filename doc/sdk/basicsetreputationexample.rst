Basic Set Reputation Example
============================

This sample demonstrates invoking the McAfee Threat Intelligence Exchange (TIE) DXL service to set the
enterprise-specific `trust level` of a file (as identified by its hashes).

Prerequisites
*************
* The samples configuration step has been completed (see :doc:`sampleconfig`)
* A McAfee Threat Intelligence Exchange (TIE) Service is available on the DXL fabric
* The Python client must be authorized to send messages to the ``/mcafee/service/tie/file/reputation/set``
  topic which is part of the ``TIE Server Set Enterprise Reputation`` authorization group.

  The following page provides an example of authorizing a Python client to send messages to an
  `authorization group`. While the example is based on McAfee Active Response (MAR), the
  instructions are the same with the exception of swapping the ``TIE Server Set Enterprise Reputation``
  `authorization group` in place of ``Active Response Server API``:

  `<https://opendxl.github.io/opendxl-client-python/pydoc/marsendauth.html>`_

Running
*******

To run this sample execute the ``sample/basic/basic_set_reputation_example.py`` script as follows:

    .. parsed-literal::

        c:\\dxltieclient-python-sdk-\ |version|\>python sample/basic/basic_set_reputation_example.py

If the `set reputation` operation succeeds the following message will be displayed:

    .. code-block:: python

        Succeeded.

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

Once a connection is established to the DXL fabric, a :class:`dxltieclient.client.TieClient` instance is created
which will be used to communicate with the TIE DXL services.

The enterprise-specific `trust level` is established for the file by invoking the
:func:`dxltieclient.client.TieClient.set_file_reputation` method of the :class:`dxltieclient.client.TieClient`
instance along with the `hash values` used to identify the file.

The ``filename`` and ``comment`` are optional, but are useful in identifying the particular file that is associated
with the hashes (especially if the file did not previously exist in the TIE repository).

