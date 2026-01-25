#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mosquitto.h>
#include <mosquitto_plugin.h>

int mosquitto_plugin_version(void)
{
    return MOSQ_PLUGIN_VERSION;
}

int mosquitto_plugin_init(
    mosquitto_plugin_id_t *identifier,
    void **user_data,
    struct mosquitto_opt *options,
    int option_count)
{
    // saying the compiler its there for future use but not used yet
    (void)identifier;
    (void)user_data;
    (void)options;
    (void)option_count;

    mosquitto_log_printf(MOSQ_LOG_INFO,
                         "[SECURE-BROKER] Plugin initialized");

    mosquitto_callback_register(
        identifier,
        MOSQ_EVT_MESSAGE,
        mosquitto_plugin_callback_message,
        NULL,
        NULL);

    return MOSQ_ERR_SUCCESS;
}

int mosquitto_plugin_cleanup(
    void *user_data,
    struct mosquitto_opt *options,
    int option_count)
{
    (void)user_data;
    (void)options;
    (void)option_count;

    mosquitto_log_printf(MOSQ_LOG_INFO,
                         "[SECURE-BROKER] Plugin cleaned up");

    return MOSQ_ERR_SUCCESS;
}

// everytime a client connects
int mosquitto_plugin_callback_connect(
    void *user_data,
    struct mosquitto *client,
    int reason_code)
{
    (void)user_data;
    (void)reason_code;

    const char *client_id = mosquitto_client_id(client);

    mosquitto_log_printf(MOSQ_LOG_INFO,
                         "[SECURE-BROKER] Client connected: %s",
                         client_id ? client_id : "(unknown)");

    return MOSQ_ERR_SUCCESS;
}

int mosquitto_plugin_callback_disconnect(
    void *user_data,
    struct mosquitto *client,
    int reason_code)
{
    (void)user_data;
    (void)reason_code;

    const char *client_id = mosquitto_client_id(client);

    mosquitto_log_printf(MOSQ_LOG_INFO,
                         "[SECURE-BROKER] Client disconnected: %s",
                         client_id ? client_id : "(unknown)");

    return MOSQ_ERR_SUCCESS;
}

int mosquitto_plugin_callback_message(
    void *user_data,
    struct mosquitto *client,
    const struct mosquitto_message *msg)
{
    (void)user_data;

    const char *client_id = mosquitto_client_id(client);

    mosquitto_log_printf(
        MOSQ_LOG_INFO,
        "[SECURE-BROKER] MESSAGE | client=%s | topic=%s | len=%d",
        client_id ? client_id : "(unknown)",
        msg->topic,
        msg->payloadlen
    );

    return MOSQ_ERR_SUCCESS;
}
