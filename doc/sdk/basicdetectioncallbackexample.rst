Basic Detection Callback Example
================================

This sample demonstrates registering a :class:`dxltieclient.callbacks.DetectionCallback` with the DXL fabric to receive
`detection` events when `detections` occur on managed systems.

Prerequisites
*************
* The samples configuration step has been completed (see :doc:`sampleconfig`)
* A McAfee Threat Intelligence Exchange (TIE) Service is available on the DXL fabric

Running
*******

To run this sample execute the ``sample/basic/basic_detection_callback_example.py`` script as follows:

    .. parsed-literal::

        c:\\dxltieclient-python-sdk-\ |version|\>python sample/basic/basic_detection_callback_example.py

The output should appear similar to the following:

    .. code-block:: python

        Waiting for detection events...


At this point the sample is listening for detection events from the DXL fabric.

Force Detection
****************

The actual steps to force a detection are outside the scope of this client library. However, the following
guidelines might prove useful:

    * Select a test executable file that is not covered by a certificate.
    * Make a backup of the test file (it may be cleaned depending on the current action enforcement policy)
    * Ensure your reputation thresholds are properly configured in policy
    * Set the reputation for the test executable within the `TIE Reputations` page so that a detection will occur

Detection Output
****************

After the detection has occurred the detection information should appear within the console that the
sample is running (similar to the output below):

    .. code-block:: python

        Detection on topic: /mcafee/event/tie/file/detection
        {
            "agentGuid": "{68125cd6-a5d8-11e6-348e-000c29663178}",
            "detectionTime": 1481301796,
            "hashes": {
                "md5": "eb5e2b9dc51817a086d7b97eb52410ab",
                "sha1": "435dfd470f727437c7cb4f07cba1f9a1f4272656",
                "sha256": "414bb16b10ece2db2d8448cb9f313f80cb77c310ca0c19ee03c73cba0c16fedb"
            },
            "localReputation": 1,
            "name": "FOCUS_MALWARE2.EXE",
            "remediationAction": 5
        }

The first line displays the DXL topic that the event was received on. In this particular case it is,
"``/mcafee/event/tie/file/detection``", which indicates that this is a file detection event.

The following information is included in the `detection` ``dict`` (dictionary):

    * System the detection occurred on
    * Time the detection occurred (Epoch time)
    * File that triggered the detection (file name and associated hashes)
    * Reputation value that was calculated locally which triggered the detection
    * Remediation action that occurred in response to the detection

Details
*******

The majority of the sample code is shown below:

    .. code-block:: python

        class MyDetectionCallback(DetectionCallback):
            """
            My detection callback
            """
            def on_detection(self, detection_dict, original_event):
                # Display the DXL topic that the event was received on
                print "Detection on topic: " + original_event.destination_topic

                # Dump the dictionary
                print json.dumps(detection_dict,
                                 sort_keys=True, indent=4, separators=(',', ': '))

        # Create the client
        with DxlClient(config) as client:

            # Connect to the fabric
            client.connect()

            # Create the McAfee Threat Intelligence Exchange (TIE) client
            tie_client = TieClient(client)

            # Create detection callback
            detection_callback = MyDetectionCallback()

            # Register detection callback with the client
            tie_client.add_file_detection_callback(detection_callback)

            # Wait forever
            print "Waiting for detection events..."
            while True:
                time.sleep(60)

A derived class from :class:`dxltieclient.callbacks.DetectionCallback` is defined which overrides the
:func:`dxltieclient.callbacks.DetectionCallback.on_detection` method to handle detection events.
When a detection occurs this method will display the topic that the event was received on and dump the detection
details.

Once a connection is established to the DXL fabric, a :class:`dxltieclient.client.TieClient` instance is created.

An instance of the derived callback is constructed and registered with the
:func:`dxltieclient.client.TieClient.add_file_detection_callback` method to receive file detection events.




