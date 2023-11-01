    /* CoAP server Example

    This example code is in the Public Domain (or CC0 licensed, at your option.)

    Unless required by applicable law or agreed to in writing, this
    software is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
    CONDITIONS OF ANY KIND, either express or implied.
    */

    /*
    * WARNING
    * libcoap is not multi-thread safe, so only this thread must make any coap_*()
    * calls.  Any external (to this thread) data transmitted in/out via libcoap
    * therefore has to be passed in/out by xQueue*() via this thread.
    */

    #include "mdns.h"

    #include <string.h>
    #include <sys/socket.h>

    #include "freertos/FreeRTOS.h"
    #include "freertos/task.h"
    #include "freertos/event_groups.h"

    #include "esp_log.h"
    #include "esp_wifi.h"
    #include "esp_event.h"

    #include "nvs_flash.h"

    #include "protocol_examples_common.h"

    #include "coap3/coap.h"

    #ifndef CONFIG_COAP_SERVER_SUPPORT
    #error COAP_SERVER_SUPPORT needs to be enabled
    #endif /* COAP_SERVER_SUPPORT */

    /* The examples use simple Pre-Shared-Key configuration that you can set via
    'idf.py menuconfig'.

    If you'd rather not, just change the below entries to strings with
    the config you want - ie #define EXAMPLE_COAP_PSK_KEY "some-agreed-preshared-key"

    Note: PSK will only be used if the URI is prefixed with coaps://
    instead of coap:// and the PSK must be one that the server supports
    (potentially associated with the IDENTITY)
    */
    #define EXAMPLE_COAP_PSK_KEY CONFIG_EXAMPLE_COAP_PSK_KEY

    /* The examples use CoAP Logging Level that
    you can set via 'idf.py menuconfig'.

    If you'd rather not, just change the below entry to a value
    that is between 0 and 7 with
    the config you want - ie #define EXAMPLE_COAP_LOG_DEFAULT_LEVEL 7
    */
    #define EXAMPLE_COAP_LOG_DEFAULT_LEVEL CONFIG_COAP_LOG_DEFAULT_LEVEL

    const static char *TAG = "CoAP_server";

    //carlosa variables
    static char light_state_0[100];
    static int light_state_0_len = 0;

    static char light_state_1[100];
    static int light_state_1_len = 0;

    static char turn_off_timer[100];
    static int turn_off_timer_len = 0;
    static int turn_off_timer_decimal = 0;

    static TaskHandle_t timer_task_handle = NULL;

    //carlosa defines
    #define COMMAND_INIT "0"
    #define TIMER_INIT "0"
    #define STATE_INIT "0"
    #define NUMBER_OF_LIGHTS 2
    #define MDNS_HOST_NAME "light-ctrl-host"
    #define MDNS_SERVICE_NAME "light-ctrl-service"

    //carlosa prototypes
    static void timer_task(void *param);
    static void turn_off_lights();

    #ifdef CONFIG_COAP_MBEDTLS_PKI
    /* CA cert, taken from coap_ca.pem
    Server cert, taken from coap_server.crt
    Server key, taken from coap_server.key

    The PEM, CRT and KEY file are examples taken from
    https://github.com/eclipse/californium/tree/master/demo-certs/src/main/resources
    as the Certificate test (by default) for the coap_client is against the
    californium server.

    To embed it in the app binary, the PEM, CRT and KEY file is named
    in the component.mk COMPONENT_EMBED_TXTFILES variable.
    */
    extern uint8_t ca_pem_start[] asm("_binary_coap_ca_pem_start");
    extern uint8_t ca_pem_end[]   asm("_binary_coap_ca_pem_end");
    extern uint8_t server_crt_start[] asm("_binary_coap_server_crt_start");
    extern uint8_t server_crt_end[]   asm("_binary_coap_server_crt_end");
    extern uint8_t server_key_start[] asm("_binary_coap_server_key_start");
    extern uint8_t server_key_end[]   asm("_binary_coap_server_key_end");
    #endif /* CONFIG_COAP_MBEDTLS_PKI */



    //carlosa: light_command_0 handlers
    static void
    light_command_0_put(coap_resource_t *resource,
                    coap_session_t *session,
                    const coap_pdu_t *request,
                    const coap_string_t *query,
                    coap_pdu_t *response)
    {
        size_t size;
        size_t offset;
        size_t total;
        const unsigned char *data;

        coap_resource_notify_observers(resource, NULL);
        if (strcmp (light_state_0, COMMAND_INIT) == 0) {
            coap_pdu_set_code(response, COAP_RESPONSE_CODE_CREATED);
        } else {
            coap_pdu_set_code(response, COAP_RESPONSE_CODE_CHANGED);
        }
        /* coap_get_data_large() sets size to 0 on error */
        (void)coap_get_data_large(request, &size, &data, &offset, &total);
        if (size == 0) {      /* re-init */
            snprintf(light_state_0, sizeof(light_state_0), COMMAND_INIT);
            light_state_0_len = strlen(light_state_0);
        } else {
            light_state_0_len = size > sizeof (light_state_0) ? sizeof (light_state_0) : size;
            memcpy (light_state_0, data, light_state_0_len);
        }

        if ( strcmp(light_state_0,"1") == 0 ){
            printf("Turning on light_0\n");
        }
        else if ( strcmp(light_state_0,"0") == 0 )
        {
            printf("Turning off light_0\n");
        }
        else{
            printf("Uknowned command\n");
        }
    }

    //carlosa: light_command_1 handlers
    static void
    light_command_1_put(coap_resource_t *resource,
                    coap_session_t *session,
                    const coap_pdu_t *request,
                    const coap_string_t *query,
                    coap_pdu_t *response)
    {
        size_t size;
        size_t offset;
        size_t total;
        const unsigned char *data;

        coap_resource_notify_observers(resource, NULL);
        if (strcmp (light_state_1, COMMAND_INIT) == 0) {
            coap_pdu_set_code(response, COAP_RESPONSE_CODE_CREATED);
        } else {
            coap_pdu_set_code(response, COAP_RESPONSE_CODE_CHANGED);
        }
        /* coap_get_data_large() sets size to 0 on error */
        (void)coap_get_data_large(request, &size, &data, &offset, &total);
        if (size == 0) {      /* re-init */
            snprintf(light_state_1, sizeof(light_state_1), COMMAND_INIT);
            light_state_1_len = strlen(light_state_1);
        } else {
            light_state_1_len = size > sizeof (light_state_1) ? sizeof (light_state_1) : size;
            memcpy (light_state_1, data, light_state_1_len);
        }

        if ( strcmp(light_state_1,"1") == 0 ){
            printf("Turning on light_1\n");
        }
        else if ( strcmp(light_state_1,"0") == 0 )
        {
            printf("Turning off light_1\n");
        }
        else{
            printf("Uknowned command\n");
        }
    }

    //carlosa light_state_0 handlers
    static void light_state_0_get(coap_resource_t *resource,
                    coap_session_t *session,
                    const coap_pdu_t *request,
                    const coap_string_t *query,
                    coap_pdu_t *response)
    {
        coap_pdu_set_code(response, COAP_RESPONSE_CODE_CONTENT);
        coap_add_data_large_response(resource, session, request, response,
                                    query, COAP_MEDIATYPE_TEXT_PLAIN, 60, 0,
                                    (size_t)light_state_0_len,
                                    (const u_char *)light_state_0,
                                    NULL, NULL);
    }

    //carlosa light_state_1 handlers
    static void light_state_1_get(coap_resource_t *resource,
                    coap_session_t *session,
                    const coap_pdu_t *request,
                    const coap_string_t *query,
                    coap_pdu_t *response)
    {
        coap_pdu_set_code(response, COAP_RESPONSE_CODE_CONTENT);
        coap_add_data_large_response(resource, session, request, response,
                                    query, COAP_MEDIATYPE_TEXT_PLAIN, 60, 0,
                                    (size_t)light_state_1_len,
                                    (const u_char *)light_state_1,
                                    NULL, NULL);
    }

    //carlosa turn_off_timer handlers
    static void
    turn_off_timer_put(coap_resource_t *resource,
                    coap_session_t *session,
                    const coap_pdu_t *request,
                    const coap_string_t *query,
                    coap_pdu_t *response)
    {
        size_t size;
        size_t offset;
        size_t total;
        const unsigned char *data;
        bool flag_format = 0;

        coap_resource_notify_observers(resource, NULL);
        if (strcmp (turn_off_timer, TIMER_INIT) == 0) {
            coap_pdu_set_code(response, COAP_RESPONSE_CODE_CREATED);
        } else {
            coap_pdu_set_code(response, COAP_RESPONSE_CODE_CHANGED);
        }
        /* coap_get_data_large() sets size to 0 on error */
        (void)coap_get_data_large(request, &size, &data, &offset, &total);
        if (size == 0) {      /* re-init */
            snprintf(turn_off_timer, sizeof(turn_off_timer), COMMAND_INIT);
            turn_off_timer_len = strlen(turn_off_timer);
        } else {
            turn_off_timer_len = size > sizeof (turn_off_timer) ? sizeof (turn_off_timer) : size;
            memcpy (turn_off_timer, data, turn_off_timer_len);
        }

        //ascii to decimal
        turn_off_timer_decimal = 0;
        for (int i = 0; i < turn_off_timer_len; i++) {
            if (turn_off_timer[i] >= '0' && turn_off_timer[i] <= '9') {
                turn_off_timer_decimal = turn_off_timer_decimal * 10 + (turn_off_timer[i] - '0');
            } else {
                flag_format = 1;
                printf("Invalid character: %c\n", turn_off_timer[i]);
            }
        }

        if (!flag_format){
            // Create and start the timer task
            xTaskCreate(timer_task, "timer_task", 2048, NULL, 5, &timer_task_handle);
        }
        else{
            printf("uknowned command");
        }
    }

    //carlosa timer task
    static void timer_task(void *param) {
        printf("Turning lights off in %d seconds\n",turn_off_timer_decimal);
        vTaskDelay(turn_off_timer_decimal*100);
        turn_off_lights();
    }

    //carlosa turning off lights function
    static void turn_off_lights(){
        memcpy (light_state_0, "0", light_state_0_len);
        memcpy (light_state_1, "0", light_state_1_len);
        printf("Lights are OFF\n");
        vTaskDelete(timer_task_handle);
    }

    #ifdef CONFIG_COAP_MBEDTLS_PKI

    static int
    verify_cn_callback(const char *cn,
                    const uint8_t *asn1_public_cert,
                    size_t asn1_length,
                    coap_session_t *session,
                    unsigned depth,
                    int validated,
                    void *arg
                    )
    {
        coap_log(LOG_INFO, "CN '%s' presented by server (%s)\n",
                cn, depth ? "CA" : "Certificate");
        return 1;
    }
    #endif /* CONFIG_COAP_MBEDTLS_PKI */

    static void
    coap_log_handler (coap_log_t level, const char *message)
    {
        uint32_t esp_level = ESP_LOG_INFO;
        char *cp = strchr(message, '\n');

        if (cp)
            ESP_LOG_LEVEL(esp_level, TAG, "%.*s", (int)(cp-message), message);
        else
            ESP_LOG_LEVEL(esp_level, TAG, "%s", message);
    }

    static void coap_example_server(void *p)
    {

        coap_context_t *ctx = NULL;
        coap_address_t serv_addr;

        //carlosa mdns
        esp_err_t err = mdns_init();
        if (err) {
            ESP_LOGE(TAG, "MDNS Init failed: %s\n", esp_err_to_name(err));
        } else {
            err = mdns_hostname_set(MDNS_HOST_NAME);
            if (err){
                ESP_LOGE(TAG, "MDNS host name set failed: %s\n", esp_err_to_name(err));
            }
            else{
                printf("adding service %s\n",MDNS_SERVICE_NAME);
                err = mdns_service_add(MDNS_SERVICE_NAME, "_coap", "_udp", COAP_DEFAULT_PORT, NULL, 0);
                if (err){
                    ESP_LOGE(TAG, "MDNS service creation FAILED: %s\n", esp_err_to_name(err));
                }
                else{
                    ESP_LOGI(TAG, "MDNS service registered: %s\n", MDNS_SERVICE_NAME);
                }
            }
        }

        //carlosa: resources declaration
        coap_resource_t *light_command_resources [NUMBER_OF_LIGHTS];
        coap_resource_t *light_state_resources [NUMBER_OF_LIGHTS];
        coap_resource_t *turn_off_timer_resource = NULL;

        for (int i = 0; i < NUMBER_OF_LIGHTS; i++) {
            light_command_resources[i] = NULL;
            light_state_resources[i] = NULL;
        }

        //carlosa formating
        snprintf(light_state_0, sizeof(light_state_0), COMMAND_INIT);
        light_state_0_len = strlen(light_state_0);

        snprintf(light_state_1, sizeof(light_state_1), COMMAND_INIT);
        light_state_1_len = strlen(light_state_1);

        snprintf(turn_off_timer, sizeof(turn_off_timer), TIMER_INIT);
        turn_off_timer_len = strlen(turn_off_timer);


        coap_set_log_handler(coap_log_handler);
        coap_set_log_level(EXAMPLE_COAP_LOG_DEFAULT_LEVEL);

        while (1) {
            coap_endpoint_t *ep = NULL;
            unsigned wait_ms;
            int have_dtls = 0;

            /* Prepare the CoAP server socket */
            coap_address_init(&serv_addr);
            serv_addr.addr.sin6.sin6_family = AF_INET6;
            serv_addr.addr.sin6.sin6_port   = htons(COAP_DEFAULT_PORT);

            ctx = coap_new_context(NULL);
            if (!ctx) {
                ESP_LOGE(TAG, "coap_new_context() failed");
                continue;
            }

            coap_context_set_block_mode(ctx,
                                        COAP_BLOCK_USE_LIBCOAP|COAP_BLOCK_SINGLE_BODY);
    #ifdef CONFIG_COAP_MBEDTLS_PSK
            /* Need PSK setup before we set up endpoints */
            coap_context_set_psk(ctx, "CoAP",
                                (const uint8_t *)EXAMPLE_COAP_PSK_KEY,
                                sizeof(EXAMPLE_COAP_PSK_KEY) - 1);
    #endif /* CONFIG_COAP_MBEDTLS_PSK */

    #ifdef CONFIG_COAP_MBEDTLS_PKI
            /* Need PKI setup before we set up endpoints */
            unsigned int ca_pem_bytes = ca_pem_end - ca_pem_start;
            unsigned int server_crt_bytes = server_crt_end - server_crt_start;
            unsigned int server_key_bytes = server_key_end - server_key_start;
            coap_dtls_pki_t dtls_pki;

            memset (&dtls_pki, 0, sizeof(dtls_pki));
            dtls_pki.version = COAP_DTLS_PKI_SETUP_VERSION;
            if (ca_pem_bytes) {
                /*
                * Add in additional certificate checking.
                * This list of enabled can be tuned for the specific
                * requirements - see 'man coap_encryption'.
                *
                * Note: A list of root ca file can be setup separately using
                * coap_context_set_pki_root_cas(), but the below is used to
                * define what checking actually takes place.
                */
                dtls_pki.verify_peer_cert        = 1;
                dtls_pki.check_common_ca         = 1;
                dtls_pki.allow_self_signed       = 1;
                dtls_pki.allow_expired_certs     = 1;
                dtls_pki.cert_chain_validation   = 1;
                dtls_pki.cert_chain_verify_depth = 2;
                dtls_pki.check_cert_revocation   = 1;
                dtls_pki.allow_no_crl            = 1;
                dtls_pki.allow_expired_crl       = 1;
                dtls_pki.allow_bad_md_hash       = 1;
                dtls_pki.allow_short_rsa_length  = 1;
                dtls_pki.validate_cn_call_back   = verify_cn_callback;
                dtls_pki.cn_call_back_arg        = NULL;
                dtls_pki.validate_sni_call_back  = NULL;
                dtls_pki.sni_call_back_arg       = NULL;
            }
            dtls_pki.pki_key.key_type = COAP_PKI_KEY_PEM_BUF;
            dtls_pki.pki_key.key.pem_buf.public_cert = server_crt_start;
            dtls_pki.pki_key.key.pem_buf.public_cert_len = server_crt_bytes;
            dtls_pki.pki_key.key.pem_buf.private_key = server_key_start;
            dtls_pki.pki_key.key.pem_buf.private_key_len = server_key_bytes;
            dtls_pki.pki_key.key.pem_buf.ca_cert = ca_pem_start;
            dtls_pki.pki_key.key.pem_buf.ca_cert_len = ca_pem_bytes;

            coap_context_set_pki(ctx, &dtls_pki);
    #endif /* CONFIG_COAP_MBEDTLS_PKI */

            ep = coap_new_endpoint(ctx, &serv_addr, COAP_PROTO_UDP);
            if (!ep) {
                ESP_LOGE(TAG, "udp: coap_new_endpoint() failed");
                goto clean_up;
            }
            if (coap_tcp_is_supported()) {
                ep = coap_new_endpoint(ctx, &serv_addr, COAP_PROTO_TCP);
                if (!ep) {
                    ESP_LOGE(TAG, "tcp: coap_new_endpoint() failed");
                    goto clean_up;
                }
            }
    #if defined(CONFIG_COAP_MBEDTLS_PSK) || defined(CONFIG_COAP_MBEDTLS_PKI)
            if (coap_dtls_is_supported()) {
    #ifndef CONFIG_MBEDTLS_TLS_SERVER
                /* This is not critical as unencrypted support is still available */
                ESP_LOGI(TAG, "MbedTLS DTLS Server Mode not configured");
    #else /* CONFIG_MBEDTLS_TLS_SERVER */
                serv_addr.addr.sin6.sin6_port = htons(COAPS_DEFAULT_PORT);
                ep = coap_new_endpoint(ctx, &serv_addr, COAP_PROTO_DTLS);
                if (!ep) {
                    ESP_LOGE(TAG, "dtls: coap_new_endpoint() failed");
                    goto clean_up;
                }
                have_dtls = 1;
    #endif /* CONFIG_MBEDTLS_TLS_SERVER */
            }
            if (coap_tls_is_supported()) {
    #ifndef CONFIG_MBEDTLS_TLS_SERVER
                /* This is not critical as unencrypted support is still available */
                ESP_LOGI(TAG, "MbedTLS TLS Server Mode not configured");
    #else /* CONFIG_MBEDTLS_TLS_SERVER */
                serv_addr.addr.sin6.sin6_port = htons(COAPS_DEFAULT_PORT);
                ep = coap_new_endpoint(ctx, &serv_addr, COAP_PROTO_TLS);
                if (!ep) {
                    ESP_LOGE(TAG, "tls: coap_new_endpoint() failed");
                    goto clean_up;
                }
    #endif /* CONFIG_MBEDTLS_TLS_SERVER */
            }
            if (!have_dtls) {
                /* This is not critical as unencrypted support is still available */
                ESP_LOGI(TAG, "MbedTLS (D)TLS Server Mode not configured");
            }
    #endif /* CONFIG_COAP_MBEDTLS_PSK || CONFIG_COAP_MBEDTLS_PKI */

            //carlosa: initialization of resources
            char resource_name[64];
            for (int i=0; i < NUMBER_OF_LIGHTS; i++){
                //command resources
                snprintf(resource_name, sizeof(resource_name), "light_command_%d", i);
                printf("Init resource: %s\n",resource_name);
                light_command_resources[i] = coap_resource_init(coap_make_str_const(resource_name), 0);
                if (!light_command_resources[i]) {
                    ESP_LOGE(TAG, "coap_resource_init() failed");
                    goto clean_up;
                }
                //state resources
                snprintf(resource_name, sizeof(resource_name), "light_state_%d", i);
                printf("Init resource: %s\n",resource_name);
                light_state_resources[i] = coap_resource_init(coap_make_str_const(resource_name), 0);
                if (!light_state_resources[i]) {
                    ESP_LOGE(TAG, "coap_resource_init() failed");
                    goto clean_up;
                }
            }
            //timer resource
            printf("Init resource: turn_off_timer_resource\n");
            turn_off_timer_resource = coap_resource_init(coap_make_str_const("turn_off_timer"), 0);
                if (!turn_off_timer_resource) {
                    ESP_LOGE(TAG, "coap_resource_init() failed");
                    goto clean_up;
                }

            //carlosa: light_command_0 handler
            coap_register_handler(light_command_resources[0], COAP_REQUEST_PUT, light_command_0_put);
            
            //carlosa: light_command_1 handler
            coap_register_handler(light_command_resources[1], COAP_REQUEST_PUT, light_command_1_put);

            //carlosa: light_state_0 handler
            coap_register_handler(light_state_resources[0], COAP_REQUEST_GET, light_state_0_get);

            //carlosa: light_state_1 handdler
            coap_register_handler(light_state_resources[1], COAP_REQUEST_GET, light_state_1_get);

            //carlosa: Turn_off_timer handler
            coap_register_handler(turn_off_timer_resource, COAP_REQUEST_PUT, turn_off_timer_put);


            /* We possibly want to Observe the GETs */
            coap_resource_set_get_observable(light_command_resources[0], 1);


            //carlosa resource adition
            for (int i=0; i < NUMBER_OF_LIGHTS; i++){
                coap_add_resource(ctx, light_command_resources[i]);
                coap_add_resource(ctx, light_state_resources[i]);
            }

            coap_add_resource(ctx, turn_off_timer_resource);

    #if defined(CONFIG_EXAMPLE_COAP_MCAST_IPV4) || defined(CONFIG_EXAMPLE_COAP_MCAST_IPV6)
            esp_netif_t *netif = NULL;
            for (int i = 0; i < esp_netif_get_nr_of_ifs(); ++i) {
                char buf[8];
                netif = esp_netif_next(netif);
                esp_netif_get_netif_impl_name(netif, buf);
    #if defined(CONFIG_EXAMPLE_COAP_MCAST_IPV4)
                coap_join_mcast_group_intf(ctx, CONFIG_EXAMPLE_COAP_MULTICAST_IPV4_ADDR, buf);
    #endif /* CONFIG_EXAMPLE_COAP_MCAST_IPV4 */
    #if defined(CONFIG_EXAMPLE_COAP_MCAST_IPV6)
                /* When adding IPV6 esp-idf requires ifname param to be filled in */
                coap_join_mcast_group_intf(ctx, CONFIG_EXAMPLE_COAP_MULTICAST_IPV6_ADDR, buf);
    #endif /* CONFIG_EXAMPLE_COAP_MCAST_IPV6 */
            }
    #endif /* CONFIG_EXAMPLE_COAP_MCAST_IPV4 || CONFIG_EXAMPLE_COAP_MCAST_IPV6 */

            wait_ms = COAP_RESOURCE_CHECK_TIME * 1000;

            while (1) {
                int result = coap_io_process(ctx, wait_ms);
                if (result < 0) {
                    break;
                } else if (result && (unsigned)result < wait_ms) {
                    /* decrement if there is a result wait time returned */
                    wait_ms -= result;
                }
                if (result) {
                    /* result must have been >= wait_ms, so reset wait_ms */
                    wait_ms = COAP_RESOURCE_CHECK_TIME * 1000;
                }
            }
            mdns_free();
        }
    clean_up:
        coap_free_context(ctx);
        coap_cleanup();

        vTaskDelete(NULL);
    }

    void app_main(void)
    {
        ESP_ERROR_CHECK( nvs_flash_init() );
        ESP_ERROR_CHECK(esp_netif_init());
        ESP_ERROR_CHECK(esp_event_loop_create_default());

        /* This helper function configures Wi-Fi or Ethernet, as selected in menuconfig.
        * Read "Establishing Wi-Fi or Ethernet Connection" section in
        * examples/protocols/README.md for more information about this function.
        */
        ESP_ERROR_CHECK(example_connect());

        xTaskCreate(coap_example_server, "coap", 8 * 1024, NULL, 5, NULL);
    }
