#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <fcntl.h>

//replacement for entire AMQTT adapters stack
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

//replacement for logging macros
//c doesnt have loggers,log levels,modules etc.
#define LOG_INFO(fmt, ...)   fprintf(stdout, "[INFO] " fmt "\n", ##__VA_ARGS__)
#define LOG_DEBUG(fmt, ...)  fprintf(stdout, "[DEBUG] " fmt "\n", ##__VA_ARGS__)
#define LOG_ERROR(fmt, ...)  fprintf(stderr, "[ERROR] " fmt "\n", ##__VA_ARGS__)


//replacement for REQUIRE_CONNECTED macro(no decorators in C)
#define REQUIRE_CONNECTED(client)         \
    if (!(client)->connected) {           \
        LOG_ERROR("Client not connected"); \
        return CLIENT_ERROR_CONNECT;      \
    }

struct node {
    void *data;
    struct node *next;
};

//default MQTT configuration
typedef struct {
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
    .reconnect_retries = 2
};

typedef enum {
    CLIENT_OK = 0,
    CLIENT_ERROR_GENERIC,
    CLIENT_ERROR_CONNECT,
    CLIENT_ERROR_TIMEOUT,
    CLIENT_ERROR_INVALID_URI,
    CLIENT_ERROR_SSL,
    CLIENT_ERROR_MQTT
} ClientError;

const char* client_error_string(ClientError err) {
    switch (err) {
        case CLIENT_OK: return "No error";
        case CLIENT_ERROR_GENERIC: return "Generic error";
        case CLIENT_ERROR_CONNECT: return "Connection error";
        case CLIENT_ERROR_TIMEOUT: return "Timeout occurred";
        case CLIENT_ERROR_INVALID_URI: return "Invalid URI";
        case CLIENT_ERROR_SSL: return "SSL/TLS error";
        case CLIENT_ERROR_MQTT: return "MQTT protocol error";
        default: return "Unknown error";
    }
}

//replacement for the classes and inheritances 
typedef struct {
    MQTTConfig *config;
} ClientContext;

//structure representing the client
typedef struct {
    char client_id[64];
    bool is_broker_client;

    bool connected;              // connection state flag
    bool no_more_connections;    // reconnection possible or not

    MQTTConfig config;           // configuration for MQTT operations

    struct {
        char topic[128];
        unsigned long key;
    } channel_keys[20]; //client can subscribe to max 20 channels

    int channel_key_count;

    unsigned long perma_key;     // decrypted from broker
    RSA *private_key;            // client's RSA private key
    RSA *public_key;             // client's RSA public key

    struct mosquitto *mosq;      // mosquitto MQTT handle (internally created)
} Client;

//function to generate RSA keypair for the client
ClientError client_generate_rsa_keys(Client *c) {
    int ret = 0;//for the return values form OpenSSL functions
    RSA *rsa = NULL;
    BIGNUM *bn = NULL;

    // Create RSA and BIGNUM objects
    rsa = RSA_new();
    if (!rsa) {
        LOG_ERROR("RSA_new failed");
        return CLIENT_ERROR_GENERIC;
    }

    bn = BN_new();
    if (!bn) {
        LOG_ERROR("BN_new failed");
        RSA_free(rsa);
        return CLIENT_ERROR_GENERIC;
    }

    // Set public exponent (RSA_F4 = 65537)
    if (!BN_set_word(bn, RSA_F4)) {
        LOG_ERROR("BN_set_word failed");
        BN_free(bn);
        RSA_free(rsa);
        return CLIENT_ERROR_GENERIC;
    }

    // Generate 512-bit RSA keypair
    ret = RSA_generate_key_ex(rsa, 512, bn, NULL);
    if (ret != 1) {
        LOG_ERROR("RSA_generate_key_ex failed");
        BN_free(bn);
        RSA_free(rsa);
        return CLIENT_ERROR_GENERIC;
    }

    // Store keys in client
    c->private_key = RSAPrivateKey_dup(rsa);
    c->public_key  = RSAPublicKey_dup(rsa);

    if (!c->private_key || !c->public_key) {
        LOG_ERROR("RSA key duplication failed");
        if (c->private_key) RSA_free(c->private_key);
        if (c->public_key) RSA_free(c->public_key);
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


//for dynamic allocation and initialization of Client structure
Client* client_create(const char *id) {
    Client *c = malloc(sizeof(Client));
    if (!c) {
        LOG_ERROR("Memory allocation failed");
        return NULL;
    }

    strcpy(c->client_id, id);//autogenerate not set yet
    c->is_broker_client = false;
    // Generate RSA keys for perma-key exchange (normal clients only)
    if (!c->is_broker_client) {
        if (client_generate_rsa_keys(c) != CLIENT_OK) {
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

    c->private_key = NULL;
    c->public_key = NULL;

    c->mosq = mosquitto_new(id, true, NULL);

    return c;
}

//for cleanup and deallocation of Client structure
void client_destroy(Client *c) {
    if (c->mosq) mosquitto_destroy(c->mosq);
    if (c->private_key) RSA_free(c->private_key);
    if (c->public_key) RSA_free(c->public_key);
    free(c);
}

//ASCON decryption function
int decrypt_message(
    unsigned long key_value,
    const unsigned char *ciphertext,
    size_t ciphertext_len,
    unsigned char *plaintext
) {
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
        plaintext
    );
    return 0;
}


int decrypt_key(
    unsigned long key_value,
    const unsigned char *ciphertext,
    size_t ciphertext_len,
    unsigned char *plaintext
) {
    unsigned char key[16];
    unsigned char nonce[16];
    unsigned char associated_data[] = "ASCON";

    // BIG-endian key
    for (int i = 0; i < 16; i++) {
        key[15 - i] = (key_value >> (8 * i)) & 0xFF;
    }

    // LITTLE-endian nonce
    for (int i = 0; i < 16; i++) {
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
        plaintext
    );

    return 0;
}


//encrypt data 
int encrypt_data(unsigned long key_value,const unsigned char *plaintext,size_t plaintext_len,unsigned char *ciphertext){
    unsigned char key[16];
    unsigned char nonce[16];
    unsigned char associated_data[] = "ASCON";//it is just the authentication data not encrypted

    //key_value to string
    char key_str[32];
    snprintf(key_str, sizeof(key_str), "%lu", key_value);

    //clear buffers
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
        ciphertext
    );

    return 0;
}

