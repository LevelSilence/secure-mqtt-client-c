#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <fcntl.h>

// replacement for entire AMQTT adapters stack
#include <sys/socket.h>
#include <arpa/inet.h>

#include <libwebsockets.h>

#include <mosquitto.h> // MQTT library replacement for entire AMQTT stack

#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/bn.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "ascon.h" // ASCON encryption/decryption

// replacement for logging macros
// c doesnt have loggers,log levels,modules etc.
#define LOG_INFO(fmt, ...) fprintf(stdout, "[INFO] " fmt "\n", ##__VA_ARGS__)
#define LOG_DEBUG(fmt, ...) fprintf(stdout, "[DEBUG] " fmt "\n", ##__VA_ARGS__)
#define LOG_ERROR(fmt, ...) fprintf(stderr, "[ERROR] " fmt "\n", ##__VA_ARGS__)
#define LOG_WARN(fmt, ...) fprintf(stderr, "[WARN] " fmt "\n", ##__VA_ARGS__)

// replacement for REQUIRE_CONNECTED macro(no decorators in C)
#define REQUIRE_CONNECTED(client)          \
    if (!(client)->connected)              \
    {                                      \
        LOG_ERROR("Client not connected"); \
        return CLIENT_ERROR_CONNECT;       \
    }

struct node
{
    void *data;
    struct node *next;
};

// default MQTT configuration
typedef struct
{
    int keep_alive;
    int ping_delay;
    int default_qos;
    bool default_retain;
    bool auto_reconnect;
    int reconnect_max_interval;
    int reconnect_retries;
} MQTTConfig;

MQTTConfig default_config = {
    .keep_alive = 10,
    .ping_delay = 1,
    .default_qos = 0,
    .default_retain = false,
    .auto_reconnect = true,
    .reconnect_max_interval = 10,
    .reconnect_retries = 2};

typedef enum
{
    CLIENT_OK = 0,
    CLIENT_ERROR_GENERIC,
    CLIENT_ERROR_CONNECT,
    CLIENT_ERROR_TIMEOUT,
    CLIENT_ERROR_INVALID_URI,
    CLIENT_ERROR_SSL,
    CLIENT_ERROR_MQTT
} ClientError;

const char *client_error_string(ClientError err)
{
    switch (err)
    {
    case CLIENT_OK:
        return "No error";
    case CLIENT_ERROR_GENERIC:
        return "Generic error";
    case CLIENT_ERROR_CONNECT:
        return "Connection error";
    case CLIENT_ERROR_TIMEOUT:
        return "Timeout occurred";
    case CLIENT_ERROR_INVALID_URI:
        return "Invalid URI";
    case CLIENT_ERROR_SSL:
        return "SSL/TLS error";
    case CLIENT_ERROR_MQTT:
        return "MQTT protocol error";
    default:
        return "Unknown error";
    }
}

// replacement for the classes and inheritances
typedef struct
{
    MQTTConfig *config;
} ClientContext;

// structure representing the client
typedef struct
{
    char client_id[64];
    bool is_broker_client;

    bool connected;           // connection state flag
    bool no_more_connections; // reconnection possible or not

    bool waiting_for_key;

    MQTTConfig config; // configuration for MQTT operations

    struct
    {
        char topic[128];
        unsigned long key;
    } channel_keys[20]; // client can subscribe to max 20 channels

    int channel_key_count;
    int reconnect_attempts;

    unsigned long perma_key; // decrypted from broker
    RSA *private_key;        // client's RSA private key
    RSA *public_key;         // client's RSA public key

    struct mosquitto *mosq; // mosquitto MQTT handle (internally created)
} Client;

void on_message(
    struct mosquitto *mosq,
    void *userdata,
    const struct mosquitto_message *msg);

void on_disconnect(
    struct mosquitto *mosq,
    void *userdata,
    int reason_code);

// function to generate RSA keypair for the client
ClientError client_generate_rsa_keys(Client *c)
{
    int ret = 0; // for the return values form OpenSSL functions
    RSA *rsa = NULL;
    BIGNUM *bn = NULL;

    // Create RSA and BIGNUM objects
    rsa = RSA_new();
    if (!rsa)
    {
        LOG_ERROR("RSA_new failed");
        return CLIENT_ERROR_GENERIC;
    }

    bn = BN_new();
    if (!bn)
    {
        LOG_ERROR("BN_new failed");
        RSA_free(rsa);
        return CLIENT_ERROR_GENERIC;
    }

    // Set public exponent (RSA_F4 = 65537)
    if (!BN_set_word(bn, RSA_F4))
    {
        LOG_ERROR("BN_set_word failed");
        BN_free(bn);
        RSA_free(rsa);
        return CLIENT_ERROR_GENERIC;
    }

    // Generate 512-bit RSA keypair
    ret = RSA_generate_key_ex(rsa, 512, bn, NULL);
    if (ret != 1)
    {
        LOG_ERROR("RSA_generate_key_ex failed");
        BN_free(bn);
        RSA_free(rsa);
        return CLIENT_ERROR_GENERIC;
    }

    // Store keys in client
    c->private_key = RSAPrivateKey_dup(rsa);
    c->public_key = RSAPublicKey_dup(rsa);

    if (!c->private_key || !c->public_key)
    {
        LOG_ERROR("RSA key duplication failed");
        if (c->private_key)
            RSA_free(c->private_key);
        if (c->public_key)
            RSA_free(c->public_key);
        BN_free(bn);
        RSA_free(rsa);
        return CLIENT_ERROR_GENERIC;
    }

    // Cleanup temporary objects
    BN_free(bn);
    RSA_free(rsa);

    LOG_INFO("RSA keypair generated successfully");
    return CLIENT_OK;
}

// for dynamic allocation and initialization of Client structure
Client *client_create(const char *id)
{
    Client *c = malloc(sizeof(Client));
    if (!c)
    {
        LOG_ERROR("Memory allocation failed");
        return NULL;
    }

    strcpy(c->client_id, id); // autogenerate not set yet
    c->is_broker_client = false;
    c->waiting_for_key = false;
    // Generate RSA keys for perma-key exchange (normal clients only)
    if (!c->is_broker_client)
    {
        if (client_generate_rsa_keys(c) != CLIENT_OK)
        {
            LOG_ERROR("RSA key generation failed");
            client_destroy(c);
            return NULL;
        }
    }

    c->connected = false;
    c->no_more_connections = false;

    c->config = default_config;
    c->channel_key_count = 0;
    c->perma_key = 0;
    c->reconnect_attempts = 0;

    c->mosq = mosquitto_new(id, true, NULL);
    if (!c->mosq)
    {
        LOG_ERROR("mosquitto_new failed");
        client_destroy(c);
        return NULL;
    }

    mosquitto_reconnect_delay_set(
        c->mosq,
        1, // initial delay (seconds)
        c->config.reconnect_max_interval,
        true // exponential backoff
    );
    return c;
}

// for cleanup and deallocation of Client structure
void client_destroy(Client *c)
{
    if (c->mosq)
        mosquitto_destroy(c->mosq);
    if (c->private_key)
        RSA_free(c->private_key);
    if (c->public_key)
        RSA_free(c->public_key);
    free(c);
}

// connection function
ClientError client_connect(Client *c, const char *host, int port)
{
    /* 1. attach client object to mosquitto */
    mosquitto_user_data_set(c->mosq, c);

    /* 2. register message callback */
    mosquitto_message_callback_set(c->mosq, on_message);

    mosquitto_disconnect_callback_set(c->mosq, on_disconnect);

    /* 3. connect to broker */
    int rc = mosquitto_connect(c->mosq, host, port, c->config.keep_alive);
    if (rc != MOSQ_ERR_SUCCESS)
    {
        LOG_ERROR("Connect failed: %s", mosquitto_strerror(rc));
        return CLIENT_ERROR_CONNECT;
    }

    /* 4. start network loop */
    mosquitto_loop_start(c->mosq);

    /* Convert public key to PEM string */
    BIO *bio = BIO_new(BIO_s_mem());
    if (!bio)
    {
        LOG_ERROR("BIO_new failed");
        return CLIENT_ERROR_GENERIC;
    }

    if (!PEM_write_bio_RSAPublicKey(bio, c->public_key))
    {
        LOG_ERROR("PEM_write_bio_RSAPublicKey failed");
        BIO_free(bio);
        return CLIENT_ERROR_GENERIC;
    }

    char pem[2048];
    memset(pem, 0, sizeof(pem));
    BIO_read(bio, pem, sizeof(pem) - 1);
    BIO_free(bio);

    mosquitto_subscribe(c->mosq, NULL, "KEYDIS", 1);

    char req[4096];
    snprintf(req, sizeof(req), "||1||%s||%s||", c->client_id, pem);

    mosquitto_publish(
        c->mosq,
        NULL,
        "KEYDIS",
        strlen(req),
        req,
        1,
        false);

    c->connected = true;
    c->reconnect_attempts = 0;
    c->waiting_for_key = true;

    return CLIENT_OK;
}

// ASCON decryption function
int decrypt_message(
    unsigned long key_value,
    const unsigned char *ciphertext,
    size_t ciphertext_len,
    unsigned char *plaintext)
{
    unsigned char key[16];
    unsigned char nonce[16];
    unsigned char associated_data[] = "ASCON";

    // Convert key_value to string
    char key_str[32];
    snprintf(key_str, sizeof(key_str), "%lu", key_value);

    // Copy first 16 bytes into key and nonce
    memset(key, 0, 16);
    memset(nonce, 0, 16);

    memcpy(key, key_str, strlen(key_str) > 16 ? 16 : strlen(key_str));
    memcpy(nonce, key_str, strlen(key_str) > 16 ? 16 : strlen(key_str));

    // ASCON decryption
    ascon_decrypt(
        key,
        nonce,
        associated_data,
        sizeof(associated_data) - 1,
        ciphertext,
        ciphertext_len,
        plaintext);
    return 0;
}

int decrypt_key(
    unsigned long key_value,
    const unsigned char *ciphertext,
    size_t ciphertext_len,
    unsigned char *plaintext)
{
    unsigned char key[16];
    unsigned char nonce[16];
    unsigned char associated_data[] = "ASCON";

    // BIG-endian key
    for (int i = 0; i < 16; i++)
    {
        key[15 - i] = (key_value >> (8 * i)) & 0xFF;
    }

    // LITTLE-endian nonce
    for (int i = 0; i < 16; i++)
    {
        nonce[i] = (key_value >> (8 * i)) & 0xFF;
    }

    // ASCON decrypt
    ascon_decrypt(
        key,
        nonce,
        associated_data,
        sizeof(associated_data) - 1,
        ciphertext,
        ciphertext_len,
        plaintext);

    return 0;
}

// encrypt data
int encrypt_data(unsigned long key_value, const unsigned char *plaintext, size_t plaintext_len, unsigned char *ciphertext)
{
    unsigned char key[16];
    unsigned char nonce[16];
    unsigned char associated_data[] = "ASCON"; // it is just the authentication data not encrypted

    // key_value to string
    char key_str[32];
    snprintf(key_str, sizeof(key_str), "%lu", key_value);

    // clear buffers
    memset(key, 0, 16);
    memset(nonce, 0, 16);

    memcpy(key, key_str, strlen(key_str) > 16 ? 16 : strlen(key_str));
    memcpy(nonce, key_str, strlen(key_str) > 16 ? 16 : strlen(key_str));

    ascon_encrypt(
        key,
        nonce,
        associated_data,
        sizeof(associated_data) - 1,
        plaintext,
        plaintext_len,
        ciphertext);

    return 0;
}

void on_message(
    struct mosquitto *mosq,
    void *userdata,
    const struct mosquitto_message *msg)
{
    Client *client = (Client *)userdata;

    /* Step 1: only process KEYDIS if waiting */
    if (!client->waiting_for_key)
        return;

    /* Step 2: check topic */
    if (strcmp(msg->topic, "KEYDIS") != 0)
        return;

    /* Step 3: copy payload to string */
    char payload[1024];
    memset(payload, 0, sizeof(payload));
    size_t len = msg->payloadlen < sizeof(payload) - 1
                     ? msg->payloadlen
                     : sizeof(payload) - 1;
    memcpy(payload, msg->payload, len);
    payload[len] = '\0';

    /* Step 4: split by || */
    char *parts[5];
    int count = 0;

    char *parts[5] = {0};
    int count = 0;

    char *p = payload;
    while (count < 5)
    {
        char *next = strstr(p, "||");
        if (!next)
            break;
        *next = '\0';
        parts[count++] = p;
        p = next + 2;
    }

    /* Step 5: basic validation */
    if (count < 4)
        return;

    /* parts[1] should be "2" */
    if (strcmp(parts[1], "2") != 0)
        return;

    /* parts[2] should be my client_id */
    if (strcmp(parts[2], client->client_id) != 0)
        return;

    /* If we reach here → valid KEYDIS response */
    LOG_INFO("Valid KEYDIS response received for client %s", client->client_id);

    unsigned char encrypted_key[256];
    int encrypted_len = hex_to_bytes(
        parts[3],
        encrypted_key,
        sizeof(encrypted_key));

    if (encrypted_len < 0)
    {
        LOG_ERROR("Invalid encrypted key hex");
        return;
    }

    // RSA decryption
    unsigned char decrypted[256];
    int decrypted_len = RSA_private_decrypt(
        encrypted_len,
        encrypted_key,
        decrypted,
        client->private_key,
        RSA_PKCS1_PADDING);

    if (decrypted_len <= 0)
    {
        LOG_ERROR("RSA decryption failed");
        return;
    }

    /* make it a string */
    decrypted[decrypted_len] = '\0';

    client->perma_key = strtoul((char *)decrypted, NULL, 10);

    LOG_INFO("Permanent key received and stored");

    // reset waiting flag and unsubscribe
    client->waiting_for_key = false;
    mosquitto_unsubscribe(mosq, NULL, "KEYDIS");
}

int hex_to_bytes(const char *hex, unsigned char *out, size_t max_len)
{
    size_t len = strlen(hex);
    if (len % 2 != 0)
        return -1;

    size_t bytes = len / 2;
    if (bytes > max_len)
        return -1;

    for (size_t i = 0; i < bytes; i++)
    {
        sscanf(hex + 2 * i, "%2hhx", &out[i]);
    }
    return (int)bytes;
}

ClientError client_disconnect(Client *c)
{
    if (!c)
        return CLIENT_ERROR_GENERIC;

    if (!c->connected)
    {
        LOG_DEBUG("Client not connected, ignoring disconnect");
        return CLIENT_OK;
    }

    mosquitto_disconnect(c->mosq);

    mosquitto_loop_stop(c->mosq, false);

    for (int i = 0; i < c->channel_key_count; i++)
    {
        mosquitto_unsubscribe(c->mosq, NULL, c->channel_keys[i].topic);
    }

    c->channel_key_count = 0;

    c->perma_key = 0;

    c->connected = false;
    c->waiting_for_key = false;
    c->no_more_connections = true;

    LOG_INFO("Client disconnected cleanly");
    return CLIENT_OK;
}

void on_disconnect(
    struct mosquitto *mosq,
    void *userdata,
    int reason_code)
{
    Client *c = (Client *)userdata;

    c->connected = false;
    c->reconnect_attempts++;

    LOG_WARN("Disconnected (reason=%d), attempt %d",
             reason_code, c->reconnect_attempts);

    if (c->config.reconnect_retries >= 0 &&
        c->reconnect_attempts > c->config.reconnect_retries)
    {

        LOG_ERROR("Reconnect attempts exceeded limit");
        c->no_more_connections = true;

        mosquitto_loop_stop(mosq, false);
    }
}


//REPLACEMENT for wait for vaulue function(pending)
// unsigned long wait_for_channel_key(Client *c, const char *topic)
// {
//     while (1) {
//         for (int i = 0; i < c->channel_key_count; i++) {
//             if (strcmp(c->channel_keys[i].topic, topic) == 0) {
//                 return c->channel_keys[i].key;
//             }
//         }
//         sleep(2);  // same as asyncio.sleep(2)
//     }
// }
