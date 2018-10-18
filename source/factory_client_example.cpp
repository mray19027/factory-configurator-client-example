// ----------------------------------------------------------------------------
// Copyright 2016-2017 ARM Ltd.
//  
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//  
//     http://www.apache.org/licenses/LICENSE-2.0
//  
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
// ----------------------------------------------------------------------------

// Note: this macro is needed on armcc to get the the PRI*32 macros
// from inttypes.h in a C++ code.
#ifndef __STDC_FORMAT_MACROS
#define __STDC_FORMAT_MACROS
#endif

#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>

#include "mcc_common_setup.h"
#include "factory_configurator_client.h"
#include "ftcd_comm_base.h"
#include "fce_common_helper.h"
#include "mbed-trace/mbed_trace.h"
#include "mbed-trace-helper.h"
#include "fcc_malloc.h"
#include "fcc_stats.h"
#include "fcc_bundle_handler.h"

#include <key_config_manager.h>
#include <mbedtls/sha256.h>
#include "mbed-cloud-client/MbedCloudClient.h"

#include "mbed.h"

DigitalIn  reset_pin(SW2); // change this to the button on your board
DigitalIn  debug_pin(SW3); // change this to the button on your board

#define TRACE_GROUP     "fce"  // Maximum 4 characters

static int factory_example_success = EXIT_FAILURE;


static void print_sha256(uint8_t *sha)
{
    for (size_t i = 0; i < 32; ++i) {
        printf("%02x", sha[i]);
    }
}

static void print_hex(uint8_t *buf, size_t len)
{
    for (size_t i = 0; i < len;) {
        printf("%02x ", buf[i]);
        if (++i % 16 == 0)
            printf("\n");
    }
}

static void print_fcc()
{
    uint8_t *buf;
    size_t real_size = 0;
    const size_t buf_size = 2048;
    uint8_t sha[32]; /* SHA256 outputs 32 bytes */

    buf = (uint8_t *)malloc(buf_size);
    if (buf == NULL) {
        printf("ERROR: failed to allocate tmp buffer\n");
        return;
    }

#define PRINT_CONFIG_ITEM(x)                                                   \
    do {                                                                       \
        memset(buf, 0, buf_size);                                              \
        kcm_status_e kcm_status =                                              \
            kcm_item_get_data((const uint8_t *)x, strlen(x), KCM_CONFIG_ITEM,  \
                              buf, buf_size, &real_size);                      \
        if (kcm_status == 0) {                                                 \
            printf("%s: %s\n", x, buf);                                        \
        } else {                                                               \
            printf("%s: FAIL (%d)\n", x, kcm_status);                          \
        }                                                                      \
    } while (false);

#define PRINT_CONFIG_CERT(x)                                                   \
    do {                                                                       \
        memset(buf, 0, buf_size);                                              \
        kcm_status_e kcm_status = kcm_item_get_data(                           \
            (const uint8_t *)x, strlen(x), KCM_CERTIFICATE_ITEM, buf,          \
            buf_size, &real_size);                                             \
        if (kcm_status == 0) {                                                 \
            printf("%s: \n", x);                                               \
            printf("sha=");                                                    \
            mbedtls_sha256(buf, std::min(real_size, buf_size), sha, 0);        \
            print_sha256(sha);                                                 \
            printf("\n");                                                      \
            print_hex(buf, std::min(real_size, buf_size));                     \
            printf("\n");                                                      \
        } else {                                                               \
            printf("%s: FAIL (%d)\n", x, kcm_status);                          \
        }                                                                      \
    } while (false)

#define PRINT_CONFIG_KEY(x)                                                    \
    do {                                                                       \
        memset(buf, 0, buf_size);                                              \
        kcm_status_e kcm_status = kcm_item_get_data(                           \
            (const uint8_t *)x, strlen(x), KCM_PRIVATE_KEY_ITEM, buf,          \
            buf_size, &real_size);                                             \
        if (kcm_status == 0) {                                                 \
            printf("%s: \n", x);                                               \
            printf("sha=");                                                    \
            mbedtls_sha256(buf, std::min(real_size, buf_size), sha, 0);        \
            print_sha256(sha);                                                 \
            printf("\n");                                                      \
            print_hex(buf, std::min(real_size, buf_size));                     \
            printf("\n");                                                      \
        } else {                                                               \
            printf("%s: FAIL (%d)\n", x, kcm_status);                          \
        }                                                                      \
    } while (false)

    /**
     * Device general info
     */
    PRINT_CONFIG_ITEM(g_fcc_use_bootstrap_parameter_name);
    PRINT_CONFIG_ITEM(g_fcc_endpoint_parameter_name);
    PRINT_CONFIG_ITEM(KEY_INTERNAL_ENDPOINT); /*"mbed.InternalEndpoint"*/
    PRINT_CONFIG_ITEM(KEY_ACCOUNT_ID);        /* "mbed.AccountID" */

    /**
     * Device meta data
     */
    PRINT_CONFIG_ITEM(g_fcc_manufacturer_parameter_name);
    PRINT_CONFIG_ITEM(g_fcc_model_number_parameter_name);
    PRINT_CONFIG_ITEM(g_fcc_device_type_parameter_name);
    PRINT_CONFIG_ITEM(g_fcc_hardware_version_parameter_name);
    PRINT_CONFIG_ITEM(g_fcc_memory_size_parameter_name);
    PRINT_CONFIG_ITEM(g_fcc_device_serial_number_parameter_name);
    PRINT_CONFIG_ITEM(KEY_DEVICE_SOFTWAREVERSION); /* "mbed.SoftwareVersion" */

    /**
     * Time Synchronization
     */
    PRINT_CONFIG_ITEM(g_fcc_current_time_parameter_name);
    PRINT_CONFIG_ITEM(g_fcc_device_time_zone_parameter_name);
    PRINT_CONFIG_ITEM(g_fcc_offset_from_utc_parameter_name);

    /**
     * Bootstrap configuration
     */
    PRINT_CONFIG_CERT(g_fcc_bootstrap_server_ca_certificate_name);
    PRINT_CONFIG_ITEM(g_fcc_bootstrap_server_crl_name);
    PRINT_CONFIG_ITEM(g_fcc_bootstrap_server_uri_name);
    PRINT_CONFIG_CERT(g_fcc_bootstrap_device_certificate_name);
    PRINT_CONFIG_CERT(g_fcc_bootstrap_device_private_key_name);

    /**
     * LWm2m configuration
     */
    PRINT_CONFIG_CERT(g_fcc_lwm2m_server_ca_certificate_name);
    PRINT_CONFIG_ITEM(g_fcc_lwm2m_server_crl_name);
    PRINT_CONFIG_ITEM(g_fcc_lwm2m_server_uri_name);
    PRINT_CONFIG_CERT(g_fcc_lwm2m_device_certificate_name);
    PRINT_CONFIG_KEY(g_fcc_lwm2m_device_private_key_name);

    /**
     * Firmware update
     */
    PRINT_CONFIG_CERT(g_fcc_update_authentication_certificate_name);

    free(buf);
}

/**
* Device factory flow
* - Runs in a task of its own
*/
static void factory_flow_task()
{
    bool success;
    fcc_status_e fcc_status = FCC_STATUS_SUCCESS;

    FtcdCommBase *ftcd_comm = NULL;
    ftcd_comm_status_e ftcd_comm_status = FTCD_COMM_STATUS_SUCCESS;
    ftcd_comm_status_e ftcd_comm_status_first_err = FTCD_COMM_STATUS_SUCCESS;
    uint8_t *input_message = NULL;
    uint32_t input_message_size = 0;
    uint8_t *response_message = NULL;
    size_t response_message_size = 0;

    mcc_platform_sw_build_info();

    // Initialize storage
    success = mcc_platform_storage_init() == 0;
    if (success != true) {
        tr_error("Failed initializing mcc platform storage\n");
        return;
    }

    fcc_status = fcc_init();
    if (fcc_status != FCC_STATUS_SUCCESS) {
        tr_error("Failed initializing factory configurator client\n");
        return;
    }

    setvbuf(stdout, (char *)NULL, _IONBF, 0); /* Avoid buffering on test output */

    // Create communication interface object
    ftcd_comm = fce_create_comm_interface();
    if (ftcd_comm == NULL) {
        tr_error("Failed creating communication object\n");
        goto out1;
    }

    //init ftcd_comm object
    success = ftcd_comm->init();
    if (success != true) {
        tr_error("Failed instantiating communication object\n");
        goto out2;
    }

    mbed_tracef(TRACE_LEVEL_CMD, TRACE_GROUP, "Factory flow begins...");

    if (!reset_pin) { 
    	fcc_status = fcc_storage_delete();
    	if (fcc_status != FCC_STATUS_SUCCESS) {
    		tr_error("Failed to reset storage\n");
    		goto out2;
    	}
    }

    if (!debug_pin) {
        print_fcc();
    }

    while (true) {
        // wait for message from communication layer
        ftcd_comm_status = ftcd_comm->wait_for_message(&input_message, &input_message_size);
        if (ftcd_comm_status == FTCD_COMM_STATUS_SUCCESS) {
            // process request and get back response
            fcc_status = fcc_bundle_handler(input_message, input_message_size, &response_message, &response_message_size);
            if ((fcc_status == FCC_STATUS_BUNDLE_RESPONSE_ERROR) || (response_message == NULL) || (response_message_size == 0)) {
                ftcd_comm_status = FTCD_COMM_FAILED_TO_PROCESS_DATA;
                mbed_tracef(TRACE_LEVEL_CMD, TRACE_GROUP, "Failed to process data");
            }
        } else {
            tr_error("Failed getting factory message");
        }

        ftcd_comm_status_first_err = ftcd_comm_status;
        ftcd_comm_status = ftcd_comm->send_response(response_message, response_message_size, ftcd_comm_status);
        if (ftcd_comm_status != FTCD_COMM_STATUS_SUCCESS) {
            ftcd_comm->send_response(NULL, 0, ftcd_comm_status);
            if (ftcd_comm_status_first_err == FTCD_COMM_STATUS_SUCCESS) {
                ftcd_comm_status_first_err = ftcd_comm_status;
            }
        }

        if (input_message) {
            fcc_free(input_message);
        }
        if (response_message) {
            fcc_free(response_message);
        }

        if (ftcd_comm_status_first_err == FTCD_COMM_STATUS_SUCCESS) {
            // Success
            mbed_tracef(TRACE_LEVEL_CMD, TRACE_GROUP, "Successfully processed comm message");
            factory_example_success = EXIT_SUCCESS;
        }

        if (fcc_is_session_finished()) {
            break;
        }
    }

out2:
    ftcd_comm->finish();
    delete ftcd_comm;
    fce_destroy_comm_interface();

out1:

    fcc_status = fcc_finalize();
    if (fcc_status != FCC_STATUS_SUCCESS) {
        tr_error("Failed finalizing factory client\n");
    } else {
        mbed_tracef(TRACE_LEVEL_CMD, TRACE_GROUP, "Successfully completed factory flow");
    }

    mbed_trace_helper_finish();

    fflush(stdout);
}

/**
* Example main
*/
int main(int argc, char * argv[])
{
    bool success = false;

    // careful, mbed-trace initialization may happen at this point if and only if we 
    // do NOT use mutex by passing "true" at the second param for this functions.
    // In case mutex is used, this function MUST be moved *after* pal_init()
    success = mbed_trace_helper_init(TRACE_ACTIVE_LEVEL_ALL | TRACE_MODE_COLOR, false);
    if (!success) {
        // Nothing much can be done here, trace module should be initialized before file system
        // and if failed - no tr_* print is eligible.
        return EXIT_FAILURE;
    }

    success = false;

    success = (mcc_platform_init() == 0);
    if (success) {
        // setvbuf(stdout, (char *)NULL, _IONBF, 0); /* Avoid buffering on test output */
        success = mcc_platform_run_program(&factory_flow_task);
    }

    // Print dynamic RAM statistics in case ENABLE_RAM_PROFILING cflag introduced
    fcc_stats_print_summary();

    return success ? factory_example_success : EXIT_FAILURE;
}
