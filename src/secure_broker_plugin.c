#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <mosquitto.h>
#include <mosquitto/broker.h>
#include <mosquitto/broker_plugin.h>

#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#define MAX_PAYLOAD 8192

static mosquitto_plugin_id_t *plugin_id = NULL;

/* Convert bytes to hex string */
void bytes_to_hex(const unsigned char *in, int len, char *out)
{
    for (int i = 0; i < len; i++)
        sprintf(out + (i * 2), "%02x", in[i]);
}

/* Extract between delimiters */
int extract_field(const char *src, int index, char *out, int max_len)
{
    int count = 0;
    const char *p = src;

    if (strncmp(p, "||", 2) == 0)
        p += 2;

    while (count < index)
    {
        char *sep = strstr(p, "||");
        if (!sep) return -1;
        p = sep + 2;
        count++;
    }

    char *end = strstr(p, "||");
    if (!end) return -1;

    int len = end - p;
    if (len >= max_len) len = max_len - 1;

    strncpy(out, p, len);
    out[len] = '\0';

    return 0;
}

#define MAX_CLIENTS 100

typedef struct {
    char client_id[128];
    unsigned long perma_key;
} PermaKeyEntry;

static PermaKeyEntry perma_table[MAX_CLIENTS];
static int perma_count = 0;


#define MAX_TOPICS 100
#define MAX_TOPIC_CLIENTS 50

typedef struct {
    char topic[128];
    char clients[MAX_TOPIC_CLIENTS][128];
    int client_count;
} SubscriptionEntry;

static SubscriptionEntry subscription_table[MAX_TOPICS];
static int subscription_count = 0;

#define MAX_CHANNEL_KEYS 100

typedef struct {
    char topic[128];
    unsigned long channel_key;
} ChannelKeyEntry;

static ChannelKeyEntry channel_key_table[MAX_CHANNEL_KEYS];
static int channel_key_count = 0;

void perform_rekey(const char *topic);
unsigned long get_channel_key(const char *topic);

void store_perma_key(const char *client_id, unsigned long key)
{
    for (int i = 0; i < perma_count; i++) {
        if (strcmp(perma_table[i].client_id, client_id) == 0) {
            perma_table[i].perma_key = key;
            return;
        }
    }

    if (perma_count < MAX_CLIENTS) {
        strncpy(perma_table[perma_count].client_id,
                client_id,
                sizeof(perma_table[perma_count].client_id) - 1);

        perma_table[perma_count].client_id[
            sizeof(perma_table[perma_count].client_id) - 1
        ] = '\0';

        perma_table[perma_count].perma_key = key;
        perma_count++;
    }
}

int get_perma_key(const char *client_id, unsigned long *out_key)
{
    for (int i = 0; i < perma_count; i++) {
        if (strcmp(perma_table[i].client_id, client_id) == 0) {
            *out_key = perma_table[i].perma_key;
            return 1;
        }
    }
    return 0;
}

//for disconnect
void remove_perma_key(const char *client_id)
{
    for (int i = 0; i < perma_count; i++) {
        if (strcmp(perma_table[i].client_id, client_id) == 0) {
            for (int j = i; j < perma_count - 1; j++) {
                perma_table[j] = perma_table[j + 1];
            }
            perma_count--;
            return;
        }
    }
}
int on_message(int event, void *event_data, void *userdata)
{
    struct mosquitto_evt_message *ed =
        (struct mosquitto_evt_message *)event_data;

    if (!ed || !ed->payload || !ed->topic)
        return MOSQ_ERR_SUCCESS;

    /* HANDLE HANDSHAKE FIRST */
    if (strcmp(ed->topic, "KEYDIS") == 0) {

        char payload[MAX_PAYLOAD];
        memset(payload, 0, sizeof(payload));
        memcpy(payload, ed->payload,
               ed->payloadlen < MAX_PAYLOAD - 1 ?
               ed->payloadlen : MAX_PAYLOAD - 1);

        if (strncmp(payload, "||1||", 5) != 0)
            return MOSQ_ERR_SUCCESS;

        char client_id[128];
        char public_pem[4096];

        if (extract_field(payload, 1, client_id, sizeof(client_id)) != 0)
            return MOSQ_ERR_SUCCESS;

        if (extract_field(payload, 2, public_pem, sizeof(public_pem)) != 0)
            return MOSQ_ERR_SUCCESS;

        BIO *bio = BIO_new_mem_buf(public_pem, -1);
        if (!bio) return MOSQ_ERR_SUCCESS;

        RSA *rsa = PEM_read_bio_RSAPublicKey(bio, NULL, NULL, NULL);
        BIO_free(bio);

        if (!rsa)
            return MOSQ_ERR_SUCCESS;

            unsigned long perma_key;
            RAND_bytes((unsigned char*)&perma_key, sizeof(perma_key));
        store_perma_key(client_id, perma_key);

        char key_str[64];
        snprintf(key_str, sizeof(key_str), "%lu", perma_key);

        unsigned char encrypted[512];
        int enc_len = RSA_public_encrypt(
            strlen(key_str),
            (unsigned char *)key_str,
            encrypted,
            rsa,
            RSA_PKCS1_PADDING
        );

        RSA_free(rsa);

        if (enc_len <= 0)
            return MOSQ_ERR_SUCCESS;

        char hex[1024];
        memset(hex, 0, sizeof(hex));
        bytes_to_hex(encrypted, enc_len, hex);

        char temp[2048];
	snprintf(temp, sizeof(temp),
         	"||2||%s||%s||",
         	client_id,
        	 hex);

	char *response = strdup(temp);

	mosquitto_broker_publish(
    	NULL,
    	"KEYDIS",
    	strlen(response),
    	response,
    	1,
    	false,
    	NULL
	);
        printf("[BROKER] Handshake completed for %s\n", client_id);
        return MOSQ_ERR_SUCCESS;
    }

    /* HANDLE NORMAL TOPICS */
    /* Broker does not encrypt — clients already handle encryption */
    return MOSQ_ERR_SUCCESS;

}
/* Required functions */

int mosquitto_plugin_version(int supported_version_count,
                             const int *supported_versions)
{
    return MOSQ_PLUGIN_VERSION;
}

int on_subscribe(int event, void *event_data, void *userdata);
int on_unsubscribe(int event, void *event_data, void *userdata);
int on_disconnect(int event, void *event_data, void *userdata);

int mosquitto_plugin_init(mosquitto_plugin_id_t *identifier,
                          void **userdata,
                          struct mosquitto_opt *options,
                          int option_count)
{
    plugin_id = identifier;
    srand(time(NULL));

    mosquitto_callback_register(
        identifier,
        MOSQ_EVT_MESSAGE,
        on_message,
        NULL,
        NULL
    );

    mosquitto_callback_register(
        identifier,
        MOSQ_EVT_SUBSCRIBE,
        on_subscribe,
        NULL,
        NULL
    );
    
    mosquitto_callback_register(
        identifier,
        MOSQ_EVT_UNSUBSCRIBE,
        on_unsubscribe,
        NULL,
        NULL
    );

    mosquitto_callback_register(
        identifier,
        MOSQ_EVT_DISCONNECT,
        on_disconnect,
        NULL,
        NULL
    );

    printf("[BROKER] Secure broker plugin loaded\n");

    return MOSQ_ERR_SUCCESS;
}

int mosquitto_plugin_cleanup(void *userdata,
                             struct mosquitto_opt *options,
                             int option_count)
{
    printf("[BROKER] Secure broker plugin unloaded\n");
    return MOSQ_ERR_SUCCESS;
}

int find_topic_index(const char *topic)
{
    for (int i = 0; i < subscription_count; i++) {
        if (strcmp(subscription_table[i].topic, topic) == 0)
            return i;
    }
    return -1;
}

int find_channel_key_index(const char *topic)
{
    for (int i = 0; i < channel_key_count; i++) {
        if (strcmp(channel_key_table[i].topic, topic) == 0)
            return i;
    }
    return -1;
}

void store_channel_key(const char *topic, unsigned long key)
{
    int idx = find_channel_key_index(topic);

    if (idx != -1) {
        channel_key_table[idx].channel_key = key;
        return;
    }

    if (channel_key_count < MAX_CHANNEL_KEYS) {
        strncpy(channel_key_table[channel_key_count].topic,
                topic,
                127);
        channel_key_table[channel_key_count].topic[127] = '\0';

        channel_key_table[channel_key_count].channel_key = key;
        channel_key_count++;
    }
}

unsigned long get_channel_key(const char *topic)
{
    int idx = find_channel_key_index(topic);
    if (idx == -1)
        return 0;

    return channel_key_table[idx].channel_key;
}

void perform_rekey(const char *topic)
{
    int sub_idx = find_topic_index(topic);
    if (sub_idx == -1)
        return;

    if (subscription_table[sub_idx].client_count == 0)
        return;

    unsigned long xor_result = 0;

    /* XOR all perma keys */
    for (int i = 0; i < subscription_table[sub_idx].client_count; i++) {

        unsigned long key;
        if (get_perma_key(subscription_table[sub_idx].clients[i], &key)) {
            xor_result ^= key;
        }
    }

    /* Add random component */
    unsigned long random_part;
    RAND_bytes((unsigned char*)&random_part, sizeof(random_part));
    xor_result ^= random_part;

    /* Store channel key */
    store_channel_key(topic, xor_result);

    /* Build rekey message */
    char message[4096];
    memset(message, 0, sizeof(message));

    strcat(message, "||");
    strcat(message, topic);
    strcat(message, "||");

    for (int i = 0; i < subscription_table[sub_idx].client_count; i++) {

        unsigned long key;
        if (!get_perma_key(subscription_table[sub_idx].clients[i], &key))
            continue;

        unsigned long partial = xor_result ^ key;

        strcat(message, subscription_table[sub_idx].clients[i]);
        strcat(message, "||");

        char num[64];
        snprintf(num, sizeof(num), "%lu", partial);
        strcat(message, num);
        strcat(message, "||");
    }

    char *heap_msg = strdup(message);

mosquitto_broker_publish(
    NULL,
    topic,
    strlen(heap_msg),
    heap_msg,
    1,
    false,
    NULL
);
    printf("[BROKER] Rekeyed topic %s\n", topic);
}
void add_subscription_entry(const char *client_id, const char *topic)
{
    if (strcmp(topic, "KEYDIS") == 0)
        return;

    int idx = find_topic_index(topic);
    int added = 0;

    if (idx == -1) {
        if (subscription_count >= MAX_TOPICS)
            return;

        idx = subscription_count++;
        strncpy(subscription_table[idx].topic, topic, 127);
        subscription_table[idx].topic[127] = '\0';
        subscription_table[idx].client_count = 0;
    }

    for (int i = 0; i < subscription_table[idx].client_count; i++) {
        if (strcmp(subscription_table[idx].clients[i], client_id) == 0)
            return;  // already subscribed → no rekey
    }

    if (subscription_table[idx].client_count < MAX_TOPIC_CLIENTS) {
        strncpy(subscription_table[idx].clients[
                    subscription_table[idx].client_count++],
                client_id,
                127);
        added = 1;
    }

    if (added) {
        printf("[BROKER] %s subscribed to %s\n", client_id, topic);
        perform_rekey(topic);
    }
}
void remove_subscription_entry(const char *client_id, const char *topic)
{
    int idx = find_topic_index(topic);
    if (idx == -1)
        return;

    int removed = 0;

    for (int i = 0; i < subscription_table[idx].client_count; i++) {
        if (strcmp(subscription_table[idx].clients[i], client_id) == 0) {

            for (int j = i;
                 j < subscription_table[idx].client_count - 1;
                 j++) {
                strcpy(subscription_table[idx].clients[j],
                       subscription_table[idx].clients[j + 1]);
            }

            subscription_table[idx].client_count--;
            removed = 1;
            break;
        }
    }

    if (removed) {

        if (subscription_table[idx].client_count == 0) {
            for (int i = idx; i < subscription_count - 1; i++)
                subscription_table[i] = subscription_table[i + 1];

            subscription_count--;
        }

        printf("[BROKER] %s unsubscribed from %s\n", client_id, topic);
        perform_rekey(topic);
    }
}

int on_subscribe(int event, void *event_data, void *userdata)
{
    struct mosquitto_evt_subscribe *ed =
        (struct mosquitto_evt_subscribe *)event_data;

    if (!ed || !ed->client || !ed->data.topic_filter)
        return MOSQ_ERR_SUCCESS;

    const char *client_id =
        mosquitto_client_id(ed->client);

    add_subscription_entry(client_id, ed->data.topic_filter);

    return MOSQ_ERR_SUCCESS;
}

int on_unsubscribe(int event, void *event_data, void *userdata)
{
    struct mosquitto_evt_unsubscribe *ed =
        (struct mosquitto_evt_unsubscribe *)event_data;

    if (!ed || !ed->client || !ed->data.topic_filter)
        return MOSQ_ERR_SUCCESS;

    const char *client_id =
        mosquitto_client_id(ed->client);

    remove_subscription_entry(client_id, ed->data.topic_filter);

    return MOSQ_ERR_SUCCESS;
}


int on_disconnect(int event, void *event_data, void *userdata)
{
    struct mosquitto_evt_disconnect *ed =
        (struct mosquitto_evt_disconnect *)event_data;

    if (!ed || !ed->client)
        return MOSQ_ERR_SUCCESS;

    const char *client_id =
        mosquitto_client_id(ed->client);

    printf("[BROKER] %s disconnected\n", client_id);

    /* Remove from all subscriptions */
    for (int i = 0; i < subscription_count; i++) {

        int topic_changed = 0;

        for (int j = 0; j < subscription_table[i].client_count; j++) {

            if (strcmp(subscription_table[i].clients[j], client_id) == 0) {

                for (int k = j;
                     k < subscription_table[i].client_count - 1;
                     k++) {

                    strcpy(subscription_table[i].clients[k],
                           subscription_table[i].clients[k + 1]);
                }

                subscription_table[i].client_count--;
                topic_changed = 1;
                break;
            }
        }

        if (topic_changed) {
            perform_rekey(subscription_table[i].topic);
        }
    }

    /* Remove perma key */
    remove_perma_key(client_id);

    return MOSQ_ERR_SUCCESS;
}
