Basic Reputation Change Callback Example
========================================

This sample demonstrates registering a :class:`dxltieclient.callbacks.ReputationChangeCallback` with the
DXL fabric to receive `reputation change` events sent by the McAfee Threat Intelligence Exchange (TIE) DXL service
when the `reputation` of a file or certificate changes.

Prerequisites
*************
* The samples configuration step has been completed (see :doc:`sampleconfig`)
* A McAfee Threat Intelligence Exchange (TIE) Service is available on the DXL fabric

Running
*******

To run this sample execute the ``sample/basic/basic_reputation_change_callback_example.py`` script as follows:

    .. parsed-literal::

        c:\\dxltieclient-python-sdk-\ |version|\>python sample/basic/basic_reputation_change_callback_example.py

The output should appear similar to the following:

    .. code-block:: python

        Waiting for reputation change events...


At this point the sample is listening for both file and certificate reputation events from the DXL fabric.

Force Reputation Change
***********************

The next step is to force a reputation change for a file or certificate via ePO. The steps to accomplish this are
listed below:

    * Open ePO and navigate to the `"TIE Reputations"` page.
    * Select the `"File Search"` or `"Certificate Search"` tab
    * Select a `file` or `certificate` in the list
    * Click the `"Actions"` button at the bottom left and select a new "Enterprise" reputation
      (for example, `Known Trusted`)
     * NOTE: It is safest to select a file (or certificate) that has a "GTI" Reputation of `Known Trusted` and simply
       set the "Enterprise" reputation to be the same (`Known Trusted`).
    * Remove the override by clicking on the `"Actions"` button again and selecting `"Remove Override"`

Reputation Change Output
************************

After the reputation change has occurred the reputation change information should appear within the console that the
sample is running (similar to the output below):

    .. code-block:: python

        Reputation change on topic: /mcafee/event/tie/file/repchange/broadcast
        {
            "hashes": {
                "md5": "f2c7bb8acc97f92e987a2d4087d01221",
                "sha1": "7eb0139d2175739b3ccb0d1110067820be6abd2b"
            },
            "newReputations": {
                "1": {
                    "attributes": {
                        "2120340": "0"
                    },
                    "createDate": 1480551590,
                    "providerId": 1,
                    "trustLevel": 0
                },
                "3": {
                    "attributes": {
                        "2101652": "0",
                        "2102165": "1480551374",
                        "2111893": "244",
                        "2114965": "1",
                        "2139285": "73183493944770750"
                    },
                    "createDate": 1480551374,
                    "providerId": 3,
                    "trustLevel": 99
                }
            },
            "oldReputations": {
                "1": {
                    "attributes": {
                        "2120340": "0"
                    },
                    "createDate": 1480551590,
                    "providerId": 1,
                    "trustLevel": 0
                },
                "3": {
                    "attributes": {
                        "2101652": "0",
                        "2102165": "1480551374",
                        "2111893": "244",
                        "2114965": "1",
                        "2139285": "73183493944770750"
                    },
                    "createDate": 1480551374,
                    "providerId": 3,
                    "trustLevel": 0
                }
            },
            "updateTime": 1481222923
        }

The first line displays the DXL topic that the event was received on. In this particular case it is,
"``/mcafee/event/tie/file/repchange/broadcast``", which indicates that this is a `file` reputation change event.

The `reputation change` information is separated into 4 distinct sections:

    **Hash values**

        A ``dict`` (dictionary) of hashes that identify the file or certificate whose reputation has
        changed.

    **New reputations**

        The new `Reputations` for the file or certificate whose reputation has changed as a
        Python ``dict`` (dictionary).

    **Old reputations**

        The previous `Reputations` for the file or certificate whose reputation has changed as a
        Python ``dict`` (dictionary).

    **Change time**

        The time the reputation change occurred.

Details
*******

The majority of the sample code is shown below:

    .. code-block:: python

        class MyReputationChangeCallback(ReputationChangeCallback):
            """
            My reputation change callback
            """
            def on_reputation_change(self, rep_change_dict, original_event):
                # Display the DXL topic that the event was received on
                print "Reputation change on topic: " + original_event.destination_topic

                # Dump the dictionary
                print json.dumps(rep_change_dict,
                                 sort_keys=True, indent=4, separators=(',', ': '))

        # Create the client
        with DxlClient(config) as client:

            # Connect to the fabric
            client.connect()

            # Create the McAfee Threat Intelligence Exchange (TIE) client
            tie_client = TieClient(client)

            # Create reputation change callback
            rep_change_callback = MyReputationChangeCallback()

            # Register callbacks with client to receive both file and certificate
            # reputation change events
            tie_client.add_file_reputation_change_callback(rep_change_callback)
            tie_client.add_certificate_reputation_change_callback(rep_change_callback)

            # Wait forever
            print "Waiting for reputation change events..."
            while True:
                time.sleep(60)

A derived class from :class:`dxltieclient.callbacks.ReputationChangeCallback` is defined which
overrides the :func:`dxltieclient.callbacks.ReputationChangeCallback.on_reputation_change` method to handle
reputation change events. When a reputation change event occurs this method will display the topic that
the event was received on and dump the reputation change details.

Once a connection is established to the DXL fabric, a :class:`dxltieclient.client.TieClient` instance is created.

An instance of the derived callback is constructed and registered with both the
:func:`dxltieclient.client.TieClient.add_file_reputation_change_callback` and
:func:`dxltieclient.client.TieClient.add_certificate_reputation_change_callback` methods to
receive file and certificate reputation change events.




