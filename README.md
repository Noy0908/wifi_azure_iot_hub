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

> [00:00:00.011,810] <inf> spi_nor: mx25r6435f@0: 8 MiBy flash
> [00:00:00.097,595] <wrn> wifi_nrf: wifi_nrf_if_start_zep: Valid MAC address: F4:CE:36:00:1F:60
>
> [00:00:00.224,914] <inf> fs_nvs: 2 Sectors of 4096 bytes
> [00:00:00.224,914] <inf> fs_nvs: alloc wra: 0, fe8
> [00:00:00.224,914] <inf> fs_nvs: data wra: 0, 0
> *** Booting Zephyr OS build v3.3.99-ncs1-2817-geb2863268008 ***
> [00:00:00.225,158] <inf> azure_iot_hub_sample: Azure IoT Hub sample started
> [00:00:00.225,189] <inf> azure_iot_hub_sample: Device ID: F4CE36001F60
> [00:00:00.225,250] <inf> azure_iot_hub_sample: Bringing network interface up and connecting to the network
> [00:00:01.812,408] <dbg> azure_iot_hub: iot_hub_state_set: State transition: STATE_UNINIT --> STATE_DISCONNECTED
> [00:00:01.812,438] <inf> azure_iot_hub_sample: Azure IoT Hub library initialized
> [00:00:06.518,981] <inf> azure_iot_hub_sample: Network connectivity established
> [00:00:11.519,073] <inf> azure_iot_hub_sample: Connecting to AWS IoT
> [00:00:11.519,195] <dbg> azure_iot_hub: iot_hub_state_set: State transition: STATE_DISCONNECTED --> STATE_CONNECTING
> [00:00:11.519,226] <inf> azure_iot_hub_sample: AZURE_IOT_HUB_EVT_CONNECTING
> [00:00:11.519,317] <dbg> azure_iot_hub: azure_iot_hub_connect: User name: fwotahub.azure-devices.net/F4CE36001F60/?api-version=2020-09-30&DeviceClientType=azsdk-c%2F1.4.0-beta.2
> [00:00:11.519,348] <dbg> azure_iot_hub: azure_iot_hub_connect: User name buffer size is 256, actual user name size is: 103
> [00:00:21.260,070] <inf> azure_iot_hub_sample: Next connection retry in 30 seconds
> [00:00:21.538,879] <dbg> azure_iot_hub: iot_hub_state_set: State transition: STATE_CONNECTING --> STATE_CONNECTED
> [00:00:21.538,879] <dbg> azure_iot_hub: on_connack: MQTT mqtt_client connected
> [00:00:21.542,694] <dbg> azure_iot_hub: topic_subscribe: Successfully subscribed to default topics
> [00:00:21.542,724] <inf> azure_iot_hub_sample: AZURE_IOT_HUB_EVT_CONNECTED
> [00:00:21.783,050] <inf> azure_iot_hub_sample: AZURE_IOT_HUB_EVT_READY
> [00:00:21.783,142] <dbg> azure_iot_hub: request_id_create_and_get: Request ID not specified, using "217"
> [00:00:21.783,905] <inf> azure_iot_hub_sample: Sending event:{"temperature":25.3,"timestamp":21783}
> [00:00:21.786,132] <inf> azure_iot_hub_sample: Event was successfully sent
> [00:00:21.786,132] <inf> azure_iot_hub_sample: Next event will be sent in 20 seconds



Dependencies
************

This sample uses the following |NCS| libraries and drivers:

* :ref:`lib_azure_iot_hub`

**Note**: **if you get the errorcode -3b00 when you try to connect your Azure IoT Hub , please modify the file as following:**
      **C:\NCS_SDK\v2.4.0\nrf\subsys\nrf_security\Kconfig.legacy**

```
config MBEDTLS_MPI_MAX_SIZE
	int
	default 256 if CRYPTOCELL_CC310_USABLE || !CRYPTOCELL_USABLE
	default 1024 if CRYPTOCELL_CC312_USABLE
	# default 384 if CRYPTOCELL_CC312_USABLE
```



**Note: The library default only support mutual TLS authentication, if you want to support one-way authentication, please modify the files as following:**

​			**C:\NCS_SDK\v2.4.0\nrf\include\net\mqtt_helper.h**

```
struct mqtt_helper_conn_params {

  /* The hostname must be null-terminated. */

  struct mqtt_helper_buf hostname;

  struct mqtt_helper_buf device_id;

  struct mqtt_helper_buf user_name;

  struct mqtt_helper_buf password;    

};
```



​         **C:\NCS_SDK\v2.4.0\nrf\subsys\net\lib\azure_iot_hub\src\azure_iot_hub.c**

```
#define MQTT_TEST_USERNAME		"AquaHub2.azure-devices.net/aquasensing_firmware_test"
#define MQTT_TEST_PASSWORD		"SharedAccessSignature sr=AquaHub2.azure-devices.net%2Fdevices%2Faquasensing_firmware_test&sig=JS1dJhOQtR3WREdhvPQABQ4Z%2FRIAyG2Hv2H7svdIq7Y%3D&se=2465357437"
int azure_iot_hub_connect(const struct azure_iot_hub_config *config)
{
	int err;
	char user_name_buf[CONFIG_AZURE_IOT_HUB_USER_NAME_BUF_SIZE];
	size_t user_name_len;
	az_span hostname_span;
	az_span device_id_span;
	struct mqtt_helper_conn_params conn_params = {
		.hostname.ptr = config ? config->hostname.ptr : NULL,
		.hostname.size = config ? config->hostname.size : 0,
		.device_id.ptr = config ? config->device_id.ptr : NULL,
		.device_id.size = config ? config->device_id.size : 0,
		.user_name = {
			.ptr = user_name_buf,
		},
	};
	struct mqtt_helper_cfg cfg = {
		.cb = {
			.on_connack = on_connack,
			.on_disconnect = on_disconnect,
			.on_publish = on_publish,
			.on_puback = on_puback,
			.on_suback = on_suback,
			.on_pingresp = on_pingresp,
			.on_error = on_error,
		},
	};
	struct azure_iot_hub_evt evt = {
		evt.type = AZURE_IOT_HUB_EVT_CONNECTING,
	};

	if (iot_hub_state_verify(STATE_CONNECTING)) {
		LOG_WRN("Azure IoT Hub connection establishment in progress");
		return -EINPROGRESS;
	}  else if (iot_hub_state_verify(STATE_CONNECTED)) {
		LOG_WRN("Azure IoT Hub is already connected");
		return -EALREADY;
	} else if (!iot_hub_state_verify(STATE_DISCONNECTED)) {
		LOG_WRN("Azure IoT Hub is not in initialized and disconnected state");
		return -ENOENT;
	}
	
	/* Use static IP if that is configured */
	if (sizeof(CONFIG_MQTT_HELPER_STATIC_IP_ADDRESS) > 1) {
		LOG_DBG("Using static IP address: %s", CONFIG_MQTT_HELPER_STATIC_IP_ADDRESS);
	
		conn_params.hostname.ptr = CONFIG_MQTT_HELPER_STATIC_IP_ADDRESS;
		conn_params.hostname.size = sizeof(CONFIG_MQTT_HELPER_STATIC_IP_ADDRESS) - 1;
	} else if ((conn_params.hostname.size == 0) && !IS_ENABLED(CONFIG_AZURE_IOT_HUB_DPS)) {
		/* Set hostname to Kconfig value if it was not provided and DPS is not enabled. */
		LOG_DBG("No hostname provided, using Kconfig value: %s",
			CONFIG_AZURE_IOT_HUB_HOSTNAME);
	
		conn_params.hostname.ptr = CONFIG_AZURE_IOT_HUB_HOSTNAME;
		conn_params.hostname.size = sizeof(CONFIG_AZURE_IOT_HUB_HOSTNAME) - 1;
	}
	
	/* Set device ID to Kconfig value if it was not provided and DPS is not enabled. */
	if ((conn_params.device_id.size == 0) && !IS_ENABLED(CONFIG_AZURE_IOT_HUB_DPS)) {
		LOG_DBG("No device ID provided, using Kconfig value: %s",
			CONFIG_AZURE_IOT_HUB_DEVICE_ID);
	
		conn_params.device_id.ptr = CONFIG_AZURE_IOT_HUB_DEVICE_ID;
		conn_params.device_id.size = sizeof(CONFIG_AZURE_IOT_HUB_DEVICE_ID) - 1;
	}
	conn_params.user_name.ptr = MQTT_TEST_USERNAME;
	conn_params.user_name.size = sizeof(MQTT_TEST_USERNAME) - 1;
	
	iot_hub_state_set(STATE_CONNECTING);
	
	/* Notify the application that the library is currently connecting to the IoT hub. */
	azure_iot_hub_notify_event(&evt);

#if IS_ENABLED(CONFIG_AZURE_IOT_HUB_DPS)
	if (config && config->use_dps) {
		struct azure_iot_hub_dps_config dps_cfg = {
			.handler = dps_handler,
			.reg_id.ptr = conn_params.device_id.ptr,
			.reg_id.size = conn_params.device_id.size,
			.id_scope = {
				.ptr = CONFIG_AZURE_IOT_HUB_DPS_ID_SCOPE,
				.size = sizeof(CONFIG_AZURE_IOT_HUB_DPS_ID_SCOPE) - 1,
			},
		};
		struct azure_iot_hub_buf hostname = {
			.ptr = conn_params.hostname.ptr,
			.size = conn_params.hostname.size,
		};
		struct azure_iot_hub_buf device_id = {
			.ptr = conn_params.device_id.ptr,
			.size = conn_params.device_id.size,
		};

		LOG_DBG("Starting DPS, timeout is %d seconds",
			CONFIG_AZURE_IOT_HUB_DPS_TIMEOUT_SEC);
	
		err = azure_iot_hub_dps_init(&dps_cfg);
		if (err) {
			LOG_ERR("azure_iot_hub_dps_init failed, error: %d", err);
			goto exit;
		}
	
		err = azure_iot_hub_dps_start();
		switch (err) {
		case 0:
			err = k_sem_take(&dps_sem, K_SECONDS(CONFIG_AZURE_IOT_HUB_DPS_TIMEOUT_SEC));
			if (err != 0) {
				LOG_ERR("DPS timed out, connection attempt terminated");
				err = -ETIMEDOUT;
				goto exit;
			}
	
			break;
		case -EALREADY:
			LOG_DBG("Already assigned to an IoT hub, skipping DPS");
			break;
		default:
			LOG_ERR("azure_iot_hub_dps_start failed, error: %d", err);
			goto exit;
		}
	
		err = azure_iot_hub_dps_hostname_get(&hostname);
		if (err) {
			LOG_ERR("Failed to get the stored hostname from DPS, error: %d", err);
			err = -EFAULT;
			goto exit;
		}
	
		conn_params.hostname.ptr = hostname.ptr;
		conn_params.hostname.size = hostname.size;
	
		LOG_DBG("Using the assigned hub (size: %d): %s",
			conn_params.hostname.size, conn_params.hostname.ptr);
	
		err = azure_iot_hub_dps_device_id_get(&device_id);
		if (err) {
			LOG_ERR("Failed to get the stored device ID from DPS, error: %d", err);
			err = -EFAULT;
			goto exit;
		}
	
		conn_params.device_id.ptr = device_id.ptr;
		conn_params.device_id.size = device_id.size;
	
		LOG_DBG("Using the assigned device ID: %.*s",
			conn_params.device_id.size,
			conn_params.device_id.ptr);
	}

#endif /* IS_ENABLED(CONFIG_AZURE_IOT_HUB_DPS) */

	err = mqtt_helper_init(&cfg);
	if (err) {
		LOG_ERR("mqtt_helper_init failed, error: %d", err);
		err = -EFAULT;
		goto exit;
	}
	
	hostname_span = az_span_create(conn_params.hostname.ptr, conn_params.hostname.size);
	device_id_span = az_span_create(conn_params.device_id.ptr, conn_params.device_id.size);
	
	/* Initialize Azure SDK client instance. */
	err = az_iot_hub_client_init(
		&iot_hub_client,
		hostname_span,
		device_id_span,
		NULL);
	if (az_result_failed(err)) {
		LOG_ERR("Failed to initialize IoT Hub mqtt_client, result code: %d", err);
		err = -EFAULT;
		goto exit;
	}

#if 0
	err = az_iot_hub_client_get_user_name(&iot_hub_client,
					      user_name_buf,
					      sizeof(user_name_buf),
					      &user_name_len);
	if (az_result_failed(err)) {
		LOG_ERR("Failed to get user name, az error: 0x%08x", err);
		err = -EFAULT;
		goto exit;
	}

	conn_params.user_name.size = user_name_len;
	
	LOG_DBG("User name: %.*s", conn_params.user_name.size, conn_params.user_name.ptr);
	LOG_DBG("User name buffer size is %d, actual user name size is: %d",
		sizeof(user_name_buf), user_name_len);

#else
	conn_params.password.ptr = MQTT_TEST_PASSWORD;
	conn_params.password.size = sizeof(MQTT_TEST_PASSWORD) - 1;

#endif

	err = mqtt_helper_connect(&conn_params);
	if (err) {
		LOG_ERR("mqtt_helper_connect failed, error: %d", err);
		goto exit;
	}
	
	return 0;

exit:
	iot_hub_state_set(STATE_DISCONNECTED);
	return err;
}
```



​        **C:\NCS_SDK\v2.4.0\nrf\subsys\net\lib\mqtt_helper\mqtt_helper.c**

```
static int client_connect(struct mqtt_helper_conn_params *conn_params)
{
	int err;
	struct mqtt_utf8 user_name = {
		.utf8 = conn_params->user_name.ptr,
		.size = conn_params->user_name.size,
	};
	

	struct mqtt_utf8 password = {
		.utf8 = conn_params->password.ptr,
		.size = conn_params->password.size,
	};
	
	mqtt_client_init(&mqtt_client);
	
	err = broker_init(&broker, conn_params);
	if (err) {
		return err;
	}
	
	mqtt_client.broker	        = &broker;
	mqtt_client.evt_cb	        = mqtt_evt_handler;
	mqtt_client.client_id.utf8      = conn_params->device_id.ptr;
	mqtt_client.client_id.size      = conn_params->device_id.size;
	// mqtt_client.password	        = NULL;
	mqtt_client.password	        = conn_params->password.size > 0 ? &password : NULL;
	
	mqtt_client.protocol_version    = MQTT_VERSION_3_1_1;
	mqtt_client.rx_buf	        = rx_buffer;
	mqtt_client.rx_buf_size	        = sizeof(rx_buffer);
	mqtt_client.tx_buf	        = tx_buffer;
	mqtt_client.tx_buf_size	        = sizeof(tx_buffer);

#if defined(CONFIG_MQTT_LIB_TLS)
	mqtt_client.transport.type      = MQTT_TRANSPORT_SECURE;
#else
	mqtt_client.transport.type	= MQTT_TRANSPORT_NON_SECURE;
#endif /* CONFIG_MQTT_LIB_TLS */
	mqtt_client.user_name	        = conn_params->user_name.size > 0 ? &user_name : NULL;
	

#if defined(CONFIG_MQTT_LIB_TLS)
	struct mqtt_sec_config *tls_cfg = &(mqtt_client.transport).tls.config;

	sec_tag_t sec_tag_list[] = {
		CONFIG_MQTT_HELPER_SEC_TAG,

#if CONFIG_MQTT_HELPER_SECONDARY_SEC_TAG > -1
		CONFIG_MQTT_HELPER_SECONDARY_SEC_TAG,
#endif
	};

	tls_cfg->peer_verify	        = TLS_PEER_VERIFY_REQUIRED;
	tls_cfg->cipher_count	        = 0;
	tls_cfg->cipher_list	        = NULL; /* Use default */
	tls_cfg->sec_tag_count	        = ARRAY_SIZE(sec_tag_list);
	tls_cfg->sec_tag_list	        = sec_tag_list;
	tls_cfg->session_cache	        = TLS_SESSION_CACHE_DISABLED;
	tls_cfg->hostname	        = conn_params->hostname.ptr;
	tls_cfg->set_native_tls		= IS_ENABLED(CONFIG_MQTT_HELPER_NATIVE_TLS);

#if defined(CONFIG_MQTT_HELPER_PROVISION_CERTIFICATES)
	err = certificates_provision();
	if (err) {
		LOG_ERR("Could not provision certificates, error: %d", err);
		return err;
	}
#endif /* defined(CONFIG_MQTT_HELPER_PROVISION_CERTIFICATES) */
#endif /* defined(CONFIG_MQTT_LIB_TLS) */

	mqtt_state_set(MQTT_STATE_TRANSPORT_CONNECTING);
	
	err = mqtt_connect(&mqtt_client);
	if (err) {
		LOG_ERR("mqtt_connect, error: %d", err);
		return err;
	}
	
	mqtt_state_set(MQTT_STATE_TRANSPORT_CONNECTED);
	
	mqtt_state_set(MQTT_STATE_CONNECTING);
	
	if (IS_ENABLED(CONFIG_MQTT_HELPER_SEND_TIMEOUT)) {
		struct timeval timeout = {
			.tv_sec = CONFIG_MQTT_HELPER_SEND_TIMEOUT_SEC
		};

#if defined(CONFIG_MQTT_LIB_TLS)
		int sock  = mqtt_client.transport.tls.sock;
#else
		int sock = mqtt_client.transport.tcp.sock;
#endif /* CONFIG_MQTT_LIB_TLS */

		err = setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
		if (err == -1) {
			LOG_WRN("Failed to set timeout, errno: %d", errno);
	
			/* Don't propagate this as an error. */
			err = 0;
		} else {
			LOG_DBG("Using send socket timeout of %d seconds",
				CONFIG_MQTT_HELPER_SEND_TIMEOUT_SEC);
		}
	}
	
	return 0;

}
```

