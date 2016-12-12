Basic First Instance Callback Example
=====================================

This sample demonstrates registering a :class:`dxltieclient.callbacks.FirstInstanceCallback` with the DXL fabric.
The callback will receive `first instance` events when files are encountered for the first time within
the local enterprise.

Prerequisites
*************
* The samples configuration step has been completed (see :doc:`sampleconfig`)
* A McAfee Threat Intelligence Exchange (TIE) Service is available on the DXL fabric

Running
*******

To run this sample execute the ``sample/basic/basic_first_instance_callback.py`` script as follows:

    .. parsed-literal::

        c:\\dxltieclient-python-sdk-\ |version|\>python sample/basic/basic_first_instance_callback.py

The output should appear similar to the following:

    .. code-block:: python

        Waiting for first instance events...


At this point the sample is listening for first instance events from the DXL fabric.

Execute New File
****************

Execute a file that has not been previously seen within the local enterprise.

Detection Output
****************

After the file has executed the first instance information should appear within the console that the
sample is running (similar to the output below):

    .. code-block:: python

        First instance on topic: /mcafee/event/tie/file/firstinstance
        {
            "agentGuid": "{68125cd6-a5d8-11e6-348e-000c29663178}",
            "hashes": {
                "md5": "31dbe8cc443d2ca7fd236ac00a52fb17",
                "sha1": "2d6ca45061b7972312e00e5933fdff95bb90b61b",
                "sha256": "aa3c461d4c21a392e372d0d6ca4ceb1e4d88098d587659454eaf4d93c661880f"
            },
            "name": "MORPH.EXE"
        }

The first line displays the DXL topic that the event was received on. In this particular case it is,
``"/mcafee/event/tie/file/firstinstance"``, which indicates that this is a file first instance event.

The following information is included in the `first instance` ``dict`` (dictionary):

    * System the first instance of the file was found on
    * File information (file name and associated hashes)

Details
*******

The majority of the sample code is shown below:

    .. code-block:: python

        class MyFirstInstanceCallback(FirstInstanceCallback):
            """
            My first instance callback
            """
            def on_first_instance(self, first_instance_dict, original_event):
                # Display the DXL topic that the event was received on
                print "First instance on topic: " + original_event.destination_topic

                # Dump the dictionary
                print json.dumps(first_instance_dict,
                                 sort_keys=True, indent=4, separators=(',', ': '))

        # Create the client
        with DxlClient(config) as client:

            # Connect to the fabric
            client.connect()

            # Create the McAfee Threat Intelligence Exchange (TIE) client
            tie_client = TieClient(client)

            # Create first instance callback
            first_instance_callback = MyFirstInstanceCallback()

            # Register first instance callback with the client
            tie_client.add_file_first_instance_callback(first_instance_callback)

            # Wait forever
            print "Waiting for first instance events..."
            while True:
                time.sleep(60)

A derived class from :class:`dxltieclient.callbacks.FirstInstanceCallback` is defined which overrides the
:func:`dxltieclient.callbacks.FirstInstanceCallback.on_first_instance` method to handle first instance events.
When a new file is encountered within the local enterprise this method will display the topic that the event was
received on and dump the first instance details.

Once a connection is established to the DXL fabric, a :class:`dxltieclient.client.TieClient` instance is created.

An instance of the derived callback is constructed and registered with the
:func:`dxltieclient.client.TieClient.add_file_first_instance_callback` method to receive file first instance events.