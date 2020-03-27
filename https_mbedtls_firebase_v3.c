/* HTTPS GET Example using plain mbedTLS sockets
 *
 * Contacts the howsmyssl.com API via TLS v1.2 and reads a JSON
 * response.
 *
 * Adapted from the ssl_client1 example in mbedtls.
 *
 * Original Copyright (C) 2006-2016, ARM Limited, All Rights Reserved, Apache 2.0 License.
 * Additions Copyright (C) Copyright 2015-2016 Espressif Systems (Shanghai) PTE LTD, Apache 2.0 License.
 *
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include <string.h>
#include <stdlib.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_system.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "esp_event.h"
#include "protocol_examples_common.h"
#include "nvs.h"
#include "nvs_flash.h"

#include <netdb.h>
#include <sys/socket.h>

#include "mbedtls/platform.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/esp_debug.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/error.h"
#include "mbedtls/certs.h"

#include "driver/uart.h"

/* Constants that aren't configurable in menuconfig */
#define WEB_SERVER "eletronica-ab6b1.firebaseio.com"
#define WEB_PORT "443"
#define WEB_URL "/January.json?auth=DZSQwLoNWAneWA9BcEfAgnelmY9"   //it is not the original value here...

static const char *TAG = "example";

char monitorREQUEST[2048];
char writeREQUEST[2048];
mbedtls_ssl_config conf;
mbedtls_entropy_context entropy;
mbedtls_ctr_drbg_context ctr_drbg;
mbedtls_x509_crt cacert;



/* Root cert for howsmyssl.com, taken from server_root_cert.pem

   The PEM file was extracted from the output of this command:
   openssl s_client -showcerts -connect www.howsmyssl.com:443 </dev/null

   The CA root cert is the last cert given in the chain of certs.

   To embed it in the app binary, the PEM file is named
   in the component.mk COMPONENT_EMBED_TXTFILES variable.
*/
extern const uint8_t server_root_cert_pem_start[] asm("_binary_server_root_cert_pem_start");
extern const uint8_t server_root_cert_pem_end[]   asm("_binary_server_root_cert_pem_end");
char buff[1024];
SemaphoreHandle_t bSemMonitor, bSemWrite;
//-----------------------------------------------------------------------------




//-----------------------------------------------------------------------------
static void https_monitor_task (void *pvParameters)
{
    char buf[512];
    int ret, flags, len;


    ///////////
    strcpy (monitorREQUEST, "GET "WEB_URL" HTTP/1.0\r\n");
    strcat (monitorREQUEST, "Host: "WEB_SERVER"\r\n");
    strcat (monitorREQUEST, "User-Agent: esp-idf/1.0 esp32\r\n");
    strcat (monitorREQUEST, "Accept: text/event-stream\r\n");   //to keep socket open monitoring for changes
    strcat (monitorREQUEST, "\r\n");
    ///////////



    //mbedtls_entropy_context entropy;
    //mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ssl_context ssl;
    //mbedtls_x509_crt cacert;
    //mbedtls_ssl_config conf;
    mbedtls_net_context server_fd;

    
    mbedtls_ssl_init(&ssl);
    /*
    mbedtls_x509_crt_init(&cacert);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    */

    //ESP_LOGI(TAG, "Seeding the random number generator");

    //mbedtls_ssl_config_init(&conf);

    /*
    mbedtls_entropy_init(&entropy);
    if((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0)) != 0)
    {
        //ESP_LOGE(TAG, "mbedtls_ctr_drbg_seed returned %d", ret);
        abort();
    }
    */

    //ESP_LOGI(TAG, "Loading the CA root certificate...");


    /*
    ret = mbedtls_x509_crt_parse(&cacert, server_root_cert_pem_start, server_root_cert_pem_end-server_root_cert_pem_start);

    if(ret < 0)
    {
        //ESP_LOGE(TAG, "mbedtls_x509_crt_parse returned -0x%x\n\n", -ret);
        abort();
    }
    */

    //ESP_LOGI(TAG, "Setting hostname for TLS session...");

     /* Hostname set here should match CN in server certificate */
    if((ret = mbedtls_ssl_set_hostname(&ssl, WEB_SERVER)) != 0)
    {
        //ESP_LOGE(TAG, "mbedtls_ssl_set_hostname returned -0x%x", -ret);
        abort();
    }

    //ESP_LOGI(TAG, "Setting up the SSL/TLS structure...");

    /*
    if((ret = mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT)) != 0)
    {
        //ESP_LOGE(TAG, "mbedtls_ssl_config_defaults returned %d", ret);
        goto exit;
    }
    */

    /* MBEDTLS_SSL_VERIFY_OPTIONAL is bad for security, in this example it will print
       a warning if CA verification fails but it will continue to connect.

       You should consider using MBEDTLS_SSL_VERIFY_REQUIRED in your own code.
    */

    /*
    mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_OPTIONAL);
    mbedtls_ssl_conf_ca_chain(&conf, &cacert, NULL);
    mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);
    */

    //#ifdef CONFIG_MBEDTLS_DEBUG
    //mbedtls_esp_enable_debug_log(&conf, 4);
    //#endif

    if ((ret = mbedtls_ssl_setup(&ssl, &conf)) != 0)
    {
        //ESP_LOGE(TAG, "mbedtls_ssl_setup returned -0x%x\n\n", -ret);
        goto exit;
    }

    while(1)
    {
        mbedtls_net_init(&server_fd);

        //ESP_LOGI(TAG, "Connecting to %s:%s...", WEB_SERVER, WEB_PORT);

        if ((ret = mbedtls_net_connect(&server_fd, WEB_SERVER, WEB_PORT, MBEDTLS_NET_PROTO_TCP)) != 0)
        {
            //ESP_LOGE(TAG, "mbedtls_net_connect returned -%x", -ret);
            goto exit;
        }

        //ESP_LOGI(TAG, "Connected.");

        mbedtls_ssl_set_bio(&ssl, &server_fd, mbedtls_net_send, mbedtls_net_recv, NULL);

        //ESP_LOGI(TAG, "Performing the SSL/TLS handshake...");

        while ((ret = mbedtls_ssl_handshake(&ssl)) != 0)
        {
            if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE)
            {
                //ESP_LOGE(TAG, "mbedtls_ssl_handshake returned -0x%x", -ret);
                goto exit;
            }
        }

        //ESP_LOGI(TAG, "Verifying peer X.509 certificate...");

        if ((flags = mbedtls_ssl_get_verify_result(&ssl)) != 0)
        {
            /* In real life, we probably want to close connection if ret != 0 */
            //ESP_LOGW(TAG, "Failed to verify peer certificate!");
            bzero(buf, sizeof(buf));
            mbedtls_x509_crt_verify_info(buf, sizeof(buf), "  ! ", flags);
            //ESP_LOGW(TAG, "verification info: %s", buf);
        }

        else 
        {
            //ESP_LOGI(TAG, "Certificate verified.");
        }

        //ESP_LOGI(TAG, "Cipher suite is %s", mbedtls_ssl_get_ciphersuite(&ssl));

        //ESP_LOGI(TAG, "Writing HTTP request...");

        size_t written_bytes = 0;
        do 
        {
            ret = mbedtls_ssl_write(&ssl, (const unsigned char *)monitorREQUEST + written_bytes, strlen(monitorREQUEST) - written_bytes);
            
            if (ret >= 0) 
            {
                //ESP_LOGI(TAG, "%d bytes written", ret);
                written_bytes += ret;
            } 
            
            else if (ret != MBEDTLS_ERR_SSL_WANT_WRITE && ret != MBEDTLS_ERR_SSL_WANT_READ) 
            {
                //ESP_LOGE(TAG, "mbedtls_ssl_write returned -0x%x", -ret);
                goto exit;
            }

        } while(written_bytes < strlen(monitorREQUEST));

        ESP_LOGI(TAG, "Reading HTTP response...");

        do
        {
            sprintf(buff, "##### AAA ##### ");
            uart_write_bytes(0, (const char*) buff, (size_t) strlen(buff));

            len = sizeof(buf) - 1;
            bzero(buf, sizeof(buf));
            ret = mbedtls_ssl_read(&ssl, (unsigned char *)buf, len);

            if(ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE)
                continue;

            if(ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) 
            {
                ESP_LOGI(TAG, "#### PEER CLOSE NOTIFY ####");
                ret = 0;
                break;
            }

            if(ret < 0)
            {
                ESP_LOGE(TAG, "mbedtls_ssl_read returned -0x%x", -ret);
                break;
            }

            if(ret == 0)
            {
                ESP_LOGI(TAG, "connection closed");
                break;
            }

            len = ret;
            ESP_LOGD(TAG, "%d bytes read", len);

            /* Print response directly to stdout as it is read */
            for(int i = 0; i < len; i++) 
            {
                putchar(buf[i]);
            }

        } while(1);

        mbedtls_ssl_close_notify(&ssl);

        exit:
        mbedtls_ssl_session_reset(&ssl);
        mbedtls_net_free(&server_fd);

        if(ret != 0)
        {
            mbedtls_strerror(ret, buf, 100);
            ESP_LOGE(TAG, "Last error was: -0x%x - %s", -ret, buf);
            //nao tenho certeza sobre o que esta abaixo, TESTAR NOVAMENTE
            //0x52 pode significar que esta sem conexao de internet
            //nesse caso, buf = "UNKNOWN ERROR CODE (0502)"
            //TESTE
            //ret = -82d quando nao tem conexao com a internet
        }

        putchar('\n'); // JSON output doesn't have a newline at end

        static int request_count;
        ESP_LOGI(TAG, "Completed %d requests", ++request_count);

        for(int countdown = 5; countdown >= 0; countdown--)
        {
            ESP_LOGI(TAG, "%d...", countdown);
            vTaskDelay(1000 / portTICK_PERIOD_MS);
        }
        ESP_LOGI(TAG, "Starting again!");
    }
}
//-----------------------------------------------------------------------------


//-----------------------------------------------------------------------------
static void https_write_task (void *pvParameters)
{
    char buf[512];
    int ret, flags, len;

    ///////////
    char msg[128];
    int msg_len;
    static uint16_t numero = 1;
    char content_length_string[128];
    ///////////
    sprintf (msg, "{\"valor\":\"%d\"}", numero++);
    msg_len = strlen(msg);
    sprintf (content_length_string, "Content-Length: %d\r\n", msg_len);
    /////////// 
    strcpy (writeREQUEST, "PUT "WEB_URL" HTTP/1.0\r\n");
    strcat (writeREQUEST, "Host: "WEB_SERVER"\r\n");
    strcat (writeREQUEST, "User-Agent: esp-idf/1.0 esp32\r\n");
    strcat (writeREQUEST, "Content-Type: application/json\r\n");
    strcat (writeREQUEST, content_length_string);
    strcat (writeREQUEST, "\r\n");
    strcat (writeREQUEST, msg);
    ///////////


    //mbedtls_entropy_context entropy;
    //mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ssl_context ssl;
    //mbedtls_x509_crt cacert;
    //mbedtls_ssl_config conf;
    mbedtls_net_context server_fd;

    mbedtls_ssl_init(&ssl);
    //mbedtls_x509_crt_init(&cacert);
    //mbedtls_ctr_drbg_init(&ctr_drbg);
    //ESP_LOGI(TAG, "Seeding the random number generator");

    //mbedtls_ssl_config_init(&conf);

    /*
    mbedtls_entropy_init(&entropy);
    if((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0)) != 0)
    {
        //ESP_LOGE(TAG, "mbedtls_ctr_drbg_seed returned %d", ret);
        abort();
    }
    */

    //ESP_LOGI(TAG, "Loading the CA root certificate...");

    /*
    ret = mbedtls_x509_crt_parse(&cacert, server_root_cert_pem_start, server_root_cert_pem_end-server_root_cert_pem_start);

    if(ret < 0)
    {
        //ESP_LOGE(TAG, "mbedtls_x509_crt_parse returned -0x%x\n\n", -ret);
        abort();
    }
    */

    //ESP_LOGI(TAG, "Setting hostname for TLS session...");

     /* Hostname set here should match CN in server certificate */
    if((ret = mbedtls_ssl_set_hostname(&ssl, WEB_SERVER)) != 0)
    {
        //ESP_LOGE(TAG, "mbedtls_ssl_set_hostname returned -0x%x", -ret);
        abort();
    }

    //ESP_LOGI(TAG, "Setting up the SSL/TLS structure...");

    /*
    if((ret = mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT)) != 0)
    {
        //ESP_LOGE(TAG, "mbedtls_ssl_config_defaults returned %d", ret);
        goto exit;
    }
    */

    /* MBEDTLS_SSL_VERIFY_OPTIONAL is bad for security, in this example it will print
       a warning if CA verification fails but it will continue to connect.

       You should consider using MBEDTLS_SSL_VERIFY_REQUIRED in your own code.
    */

   /*
    mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_OPTIONAL);
    mbedtls_ssl_conf_ca_chain(&conf, &cacert, NULL);
    mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);
    */


    //#ifdef CONFIG_MBEDTLS_DEBUG
    //mbedtls_esp_enable_debug_log(&conf, 4);
    //#endif

    if ((ret = mbedtls_ssl_setup(&ssl, &conf)) != 0)
    {
        //ESP_LOGE(TAG, "mbedtls_ssl_setup returned -0x%x\n\n", -ret);
        goto exit;
    }

    while(1)
    {
        mbedtls_net_init(&server_fd);

        //ESP_LOGI(TAG, "Connecting to %s:%s...", WEB_SERVER, WEB_PORT);

        if ((ret = mbedtls_net_connect(&server_fd, WEB_SERVER, WEB_PORT, MBEDTLS_NET_PROTO_TCP)) != 0)
        {
            //ESP_LOGE(TAG, "mbedtls_net_connect returned -%x", -ret);
            goto exit;
        }

        //ESP_LOGI(TAG, "Connected.");

        mbedtls_ssl_set_bio(&ssl, &server_fd, mbedtls_net_send, mbedtls_net_recv, NULL);

        //ESP_LOGI(TAG, "Performing the SSL/TLS handshake...");

        while ((ret = mbedtls_ssl_handshake(&ssl)) != 0)
        {
            if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE)
            {
                //ESP_LOGE(TAG, "mbedtls_ssl_handshake returned -0x%x", -ret);
                goto exit;
            }
        }

        //ESP_LOGI(TAG, "Verifying peer X.509 certificate...");

        if ((flags = mbedtls_ssl_get_verify_result(&ssl)) != 0)
        {
            /* In real life, we probably want to close connection if ret != 0 */
            //ESP_LOGW(TAG, "Failed to verify peer certificate!");
            bzero(buf, sizeof(buf));
            mbedtls_x509_crt_verify_info(buf, sizeof(buf), "  ! ", flags);
            //ESP_LOGW(TAG, "verification info: %s", buf);
        }

        else 
        {
            //ESP_LOGI(TAG, "Certificate verified.");
        }

        //ESP_LOGI(TAG, "Cipher suite is %s", mbedtls_ssl_get_ciphersuite(&ssl));

        //ESP_LOGI(TAG, "Writing HTTP request...");

        size_t written_bytes = 0;
        do 
        {
            ret = mbedtls_ssl_write(&ssl, (const unsigned char *)writeREQUEST + written_bytes, strlen(writeREQUEST) - written_bytes);
            
            if (ret >= 0) 
            {
                //ESP_LOGI(TAG, "%d bytes written", ret);
                written_bytes += ret;
            } 
            
            else if (ret != MBEDTLS_ERR_SSL_WANT_WRITE && ret != MBEDTLS_ERR_SSL_WANT_READ) 
            {
                //ESP_LOGE(TAG, "mbedtls_ssl_write returned -0x%x", -ret);
                goto exit;
            }

        } while(written_bytes < strlen(writeREQUEST));

        ESP_LOGI(TAG, "Reading HTTP response...");

        do
        {
            len = sizeof(buf) - 1;
            bzero(buf, sizeof(buf));
            ret = mbedtls_ssl_read(&ssl, (unsigned char *)buf, len);

            if(ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE)
                continue;

            if(ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) 
            {
                ESP_LOGI(TAG, "#### PEER CLOSE NOTIFY ####");
                ret = 0;
                break;
            }

            if(ret < 0)
            {
                ESP_LOGE(TAG, "mbedtls_ssl_read returned -0x%x", -ret);
                break;
            }

            if(ret == 0)
            {
                ESP_LOGI(TAG, "connection closed");
                break;
            }

            len = ret;
            ESP_LOGD(TAG, "%d bytes read", len);

            /* Print response directly to stdout as it is read */
            for(int i = 0; i < len; i++) 
            {
                putchar(buf[i]);
            }

        } while(1);

        mbedtls_ssl_close_notify(&ssl);

    exit:
        mbedtls_ssl_session_reset(&ssl);
        mbedtls_net_free(&server_fd);

        if(ret != 0)
        {
            mbedtls_strerror(ret, buf, 100);
            ESP_LOGE(TAG, "Last error was: -0x%x - %s", -ret, buf);
            //nao tenho certeza sobre o que esta abaixo, TESTAR NOVAMENTE
            //0x52 pode significar que esta sem conexao de internet
            //nesse caso, buf = "UNKNOWN ERROR CODE (0502)"
            //TESTE
            //ret = -82d quando nao tem conexao com a internet
        }

        putchar('\n'); // JSON output doesn't have a newline at end

        static int request_count;
        ESP_LOGI(TAG, "Completed %d requests", ++request_count);

        for(int countdown = 5; countdown >= 0; countdown--)
        {
            ESP_LOGI(TAG, "%d...", countdown);
            vTaskDelay(1000 / portTICK_PERIOD_MS);
        }
        ESP_LOGI(TAG, "Starting again!");

        ///////////
        sprintf (msg, "{\"valor\":\"%d\"}", numero++);
        msg_len = strlen(msg);
        sprintf (content_length_string, "Content-Length: %d\r\n", msg_len);
        /////////// 
        strcpy (writeREQUEST, "PUT " WEB_URL " HTTP/1.0\r\n");
        strcat (writeREQUEST, "Host: "WEB_SERVER"\r\n");
        strcat (writeREQUEST, "User-Agent: esp-idf/1.0 esp32\r\n");
        strcat (writeREQUEST, "Content-Type: application/json\r\n");
        strcat (writeREQUEST, content_length_string);
        strcat (writeREQUEST, "\r\n");
        strcat (writeREQUEST, msg);
        ///////////


    }
}
//-----------------------------------------------------------------------------


//-----------------------------------------------------------------------------
void app_main(void)
{
    int ret;

    uart_set_baudrate(0, 115200);
    uart_driver_install(0, 2048, 2048, 0, NULL, 0); 

    ESP_ERROR_CHECK(nvs_flash_init());
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    ESP_ERROR_CHECK(example_connect());

    //bSemMonitor = xSemaphoreCreateBinary();
    //bSemWrite = xSemaphoreCreateBinary();

    mbedtls_x509_crt_init(&cacert);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_ssl_config_init(&conf);

    mbedtls_entropy_init(&entropy);
    if((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0)) != 0)
    {
        ESP_LOGE(TAG, "mbedtls_ctr_drbg_seed returned %d", ret);
        abort();
    }

    ret = mbedtls_x509_crt_parse(&cacert, server_root_cert_pem_start, server_root_cert_pem_end-server_root_cert_pem_start);
    if(ret < 0)
    {
        ESP_LOGE(TAG, "mbedtls_x509_crt_parse returned -0x%x\n\n", -ret);
        abort();
    }

    if((ret = mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT)) != 0)
    {
        ESP_LOGE(TAG, "mbedtls_ssl_config_defaults returned %d", ret);
        abort();
    }

    mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_OPTIONAL);
    mbedtls_ssl_conf_ca_chain(&conf, &cacert, NULL);
    mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);

    xTaskCreate(https_monitor_task, "https_monitor_task", 8192, NULL, 6, NULL);
    xTaskCreate(https_write_task, "https_write_task", 8192, NULL, 5, NULL);


    for(;;)
    {
        static uint16_t index = 0;
        uint8_t byteRead;

        if ( uart_read_bytes(0, (uint8_t*) &buff[index], 1, 0) > 0 ) 
        {
            byteRead = buff[index];

            //buffer circular
            if (++index == sizeof(buff)) 
            {
                index = 0;
            }

            uart_write_bytes(0, (const char*) &byteRead, 1);

            if (byteRead == 0x55) 
            {

            }

        }
        
        vTaskDelay(100/portTICK_PERIOD_MS);
    }
}
//-----------------------------------------------------------------------------
