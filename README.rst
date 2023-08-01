.. _azure_iot_hub:

Cellular: Azure IoT Hub
#######################

.. contents::
   :local:
   :depth: 2

The Azure IoT Hub sample shows the communication of an nRF7002-based device with an `Azure IoT Hub`_ instance.
This sample uses the :ref:`lib_azure_iot_hub` library to communicate with the IoT hub.


Requirements
************

The sample supports the following development kits:

.. table-from-sample-yaml::

.. include:: /includes/tfm.txt

Overview
********

The sample supports the direct connection of an IoT device that is already registered to an Azure IoT Hub instance.
Alternatively, it supports the provisioning of the device using `Azure IoT Hub Device Provisioning Service (DPS)`_ to an IoT hub.
See the documentation on :ref:`lib_azure_iot_hub` library for more information.

The sample periodically publishes telemetry messages (events) to the connected Azure IoT Hub instance.
By default, telemetry messages are sent every 20 seconds.
To configure the default interval, set the device twin property ``desired.telemetryInterval``, which will be interpreted by the sample as seconds.
Here is an example of a telemetry message:

.. parsed-literal::
   :class: highlight

   {
     "temperature": 25.2,
     "timestamp": 151325
   }

In a telemetry message, ``temperature`` is a value between ``25.0`` and ``25.9``, and ``timestamp`` is the uptime of the device in milliseconds.

The sample has implemented the handling of `Azure IoT Hub direct method`_ with the name ``led``.
If the device receives a direct method invocation with the name ``led`` and payload ``1`` or ``0``, LED 1 on the device is turned on or off, depending on the payload.
On Thingy:91, the LED turns red if the payload is ``1``.

Configuration
*************

|config|

Setup
=====

1. For the sample to work as intended, you must set up and configure an Azure IoT Hub instance.
2. generate your CA and device certificate with openssl or other tools, please refer below docs:
		https://docs.aws.amazon.com/iot/latest/developerguide/manage-your-CA-certs.html
3. register your CA and device certificate to your IoT Hub, please refer to azure docs 
4. copy and paste the Azure root certificate and your device certificate and private key to your ./certs/ directory.



See :ref:`configure_options_azure_iot` for information on the configuration options that you can use to create an Azure IoT Hub instance.
Also, for a successful TLS connection to the Azure IoT Hub instance, the device needs to have certificates provisioned.
See :ref:`prereq_connect_to_azure_iot_hub` for information on provisioning the certificates.

.. _configure_options_azure_iot:

Additional configuration
========================

Check and configure the following library options that are used by the sample:

* :kconfig:option:`CONFIG_AZURE_IOT_HUB_DEVICE_ID` - Sets the Azure IoT Hub device ID. Alternatively, the device ID can be provided at run time.
* :kconfig:option:`CONFIG_AZURE_IOT_HUB_HOSTNAME` - Sets the Azure IoT Hub host name. If DPS is used, the sample assumes that the IoT hub host name is unknown, and the configuration is ignored. The configuration can also be omitted and the hostname provided at run time.

If DPS is used, use the Kconfig fragment found in the :file:`overlay-dps.conf` file and change the desired configurations there.
As an example, the following compiles with DPS for nRF9160DK:

.. code-block:: console

	west build -p -b nrf7002dk_nrf5340_cpuapp

* :kconfig:option:`CONFIG_AZURE_IOT_HUB_DPS` - Enables Azure IoT Hub DPS.
* :kconfig:option:`CONFIG_AZURE_IOT_HUB_DPS_REG_ID` - Sets the Azure IoT Hub DPS registration ID. It can be provided at run time. By default, the sample uses the device ID as the registration ID and sets it at run time.
* :kconfig:option:`CONFIG_AZURE_IOT_HUB_DPS_ID_SCOPE` - Sets the DPS ID scope of the Azure IoT Hub. This can be provided at run time.

.. note::

   The sample sets the option :kconfig:option:`CONFIG_MQTT_KEEPALIVE` to the maximum allowed value, 1767 seconds (29.45 minutes) as specified by Azure IoT Hub.
   This is to limit the IP traffic between the device and the Azure IoT Hub message broker for supporting a low power sample.
   In certain LTE networks, the NAT timeout can be considerably lower than 1767 seconds.
   As a recommendation, and to prevent the likelihood of getting disconnected unexpectedly, set the option :kconfig:option:`CONFIG_MQTT_KEEPALIVE` to the lowest timeout limit (Maximum allowed MQTT keepalive and NAT timeout).

.. include:: /libraries/modem/nrf_modem_lib/nrf_modem_lib_trace.rst
   :start-after: modem_lib_sending_traces_UART_start
   :end-before: modem_lib_sending_traces_UART_end

Building and running
********************

.. |sample path| replace:: :file:`samples/cellular/azure_iot_hub`

.. include:: /includes/build_and_run_ns.txt

Testing
=======

Microsoft has created `Azure IoT Explorer`_ to interact and test devices connected to an Azure IoT Hub instance.
Optionally, follow the instructions at `Azure IoT Explorer`_ to install and configure the tool and use it as mentioned in the below instructions.

|test_sample|

1. |connect_kit|
#. |connect_terminal|
#. Reset the development kit.
#. Observe the log output and verify that it is similar to the :ref:`sampoutput_azure_iot`.
#. Use the `Azure IoT Explorer`_, or log in to the `Azure Portal`_.
#. Select the connected IoT hub and then your device.
#. Change the device twin's *desired* property ``telemetryInterval`` to a new value, for instance ``60``, and save the updated device twin.
   If it does not exist, you can add the *desired* property.
#. Observe that the device receives the updated ``telemetryInterval`` value, applies it, and starts sending new telemetry events every 10 seconds.
#. Verify that the ``reported`` object in the device twin now has a ``telemetryInterval`` property with the correct value reported back from the device.
#. In the `Azure IoT Explorer`_ or device page in `Azure Portal`_, navigate to the :guilabel:`Direct method` tab.
#. Enter ``led`` as the method name. In the **payload** field, enter the value ``1`` (or ``0``) and click :guilabel:`Invoke method`.
#. Observe that **LED 1** on the development kit lights up (or switches off if ``0`` is entered as the payload).
   If you are using `Azure IoT Explorer`_, you can observe a notification in the top right corner stating if the direct method was successfully invoked based on the report received from the device.
#. In the `Azure IoT Explorer`_, navigate to the :guilabel:`Telemetry` tab and click :guilabel:`start`.
#. Observe that the event messages from the device are displayed in the terminal within the specified telemetry interval.

.. _sampoutput_azure_iot:

Sample output
=============

When the sample runs, the device boots, and the sample displays the following output in the terminal over UART:

.. code-block:: console

[00:00:00.011,810] <inf> spi_nor: mx25r6435f@0: 8 MiBy flash
[00:00:00.097,595] <wrn> wifi_nrf: wifi_nrf_if_start_zep: Valid MAC address: F4:CE:36:00:1F:60

[00:00:00.224,914] <inf> fs_nvs: 2 Sectors of 4096 bytes
[00:00:00.224,914] <inf> fs_nvs: alloc wra: 0, fe8
[00:00:00.224,914] <inf> fs_nvs: data wra: 0, 0
*** Booting Zephyr OS build v3.3.99-ncs1-2817-geb2863268008 ***
[00:00:00.225,158] <inf> azure_iot_hub_sample: Azure IoT Hub sample started
[00:00:00.225,189] <inf> azure_iot_hub_sample: Device ID: F4CE36001F60
[00:00:00.225,250] <inf> azure_iot_hub_sample: Bringing network interface up and connecting to the network
[00:00:01.812,408] <dbg> azure_iot_hub: iot_hub_state_set: State transition: STATE_UNINIT --> STATE_DISCONNECTED
[00:00:01.812,438] <inf> azure_iot_hub_sample: Azure IoT Hub library initialized
[00:00:06.518,981] <inf> azure_iot_hub_sample: Network connectivity established
[00:00:11.519,073] <inf> azure_iot_hub_sample: Connecting to AWS IoT
[00:00:11.519,195] <dbg> azure_iot_hub: iot_hub_state_set: State transition: STATE_DISCONNECTED --> STATE_CONNECTING
[00:00:11.519,226] <inf> azure_iot_hub_sample: AZURE_IOT_HUB_EVT_CONNECTING
[00:00:11.519,317] <dbg> azure_iot_hub: azure_iot_hub_connect: User name: fwotahub.azure-devices.net/F4CE36001F60/?api-version=2020-09-30&DeviceClientType=azsdk-c%2F1.4.0-beta.2
[00:00:11.519,348] <dbg> azure_iot_hub: azure_iot_hub_connect: User name buffer size is 256, actual user name size is: 103
[00:00:21.260,070] <inf> azure_iot_hub_sample: Next connection retry in 30 seconds
[00:00:21.538,879] <dbg> azure_iot_hub: iot_hub_state_set: State transition: STATE_CONNECTING --> STATE_CONNECTED
[00:00:21.538,879] <dbg> azure_iot_hub: on_connack: MQTT mqtt_client connected
[00:00:21.542,694] <dbg> azure_iot_hub: topic_subscribe: Successfully subscribed to default topics
[00:00:21.542,724] <inf> azure_iot_hub_sample: AZURE_IOT_HUB_EVT_CONNECTED
[00:00:21.783,050] <inf> azure_iot_hub_sample: AZURE_IOT_HUB_EVT_READY
[00:00:21.783,142] <dbg> azure_iot_hub: request_id_create_and_get: Request ID not specified, using "217"
[00:00:21.783,905] <inf> azure_iot_hub_sample: Sending event:{"temperature":25.3,"timestamp":21783}
[00:00:21.786,132] <inf> azure_iot_hub_sample: Event was successfully sent
[00:00:21.786,132] <inf> azure_iot_hub_sample: Next event will be sent in 20 seconds



Dependencies
************

This sample uses the following |NCS| libraries and drivers:

* :ref:`lib_azure_iot_hub`


Note: if you get the errorcode -3b00 when you try to connect your Azure IoT Hub , please modify the file as following:
      C:\NCS_SDK\v2.4.0\nrf\subsys\nrf_security\Kconfig.legacy

config MBEDTLS_MPI_MAX_SIZE
	int
	default 256 if CRYPTOCELL_CC310_USABLE || !CRYPTOCELL_USABLE
	default 1024 if CRYPTOCELL_CC312_USABLE
	# default 384 if CRYPTOCELL_CC312_USABLE

