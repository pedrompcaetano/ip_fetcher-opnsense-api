#include <sys/types.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <curl/curl.h>
#include <cjson/cJSON.h>
#include <microhttpd.h>
#include <signal.h>
#include <unistd.h>

#define MAX_RESPONSE_SIZE (1024 * 1024)
#define MAX_HOST_SCAN 64
#define PORT 8000

typedef struct {
    int id;
    char *ip;
    char *key;
    char *sec;
    char *iface;
    char json_key[64];
} OpnsenseHost;

struct AppConfig {
    char auth_header[512];
    OpnsenseHost *hosts;
    size_t host_count;
};

static struct AppConfig app_config;

/* Used to keep the daemon running until SIGTERM/SIGINT */
volatile sig_atomic_t keep_running = 1;

void handle_signal(int sig) {
    keep_running = 0;
}

struct MemoryStruct {
    char *memory;
    size_t size;
};

static size_t curl_write_cb(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    struct MemoryStruct *mem = (struct MemoryStruct *)userp;

    if (mem->size + realsize > MAX_RESPONSE_SIZE) return 0;

    char *ptr = realloc(mem->memory, mem->size + realsize + 1);
    if (ptr == NULL) return 0;

    mem->memory = ptr;
    memcpy(&(mem->memory[mem->size]), contents, realsize);
    mem->size += realsize;
    mem->memory[mem->size] = 0;

    return realsize;
}

/* Extracts the IP directly from message -> ipv4 -> value -> [0] -> ipaddr */
static void extract_ip_from_json(const char *json_str, char *output, size_t out_len) {
    snprintf(output, out_len, "Not Found");
    cJSON *json = cJSON_Parse(json_str);
    if (!json) return;

    cJSON *msg = cJSON_GetObjectItemCaseSensitive(json, "message");
    if (msg) {
        cJSON *ipv4_obj = cJSON_GetObjectItemCaseSensitive(msg, "ipv4");
        if (ipv4_obj) {
            cJSON *val = cJSON_GetObjectItemCaseSensitive(ipv4_obj, "value");
            if (val && cJSON_IsArray(val)) {
                cJSON *elem = cJSON_GetArrayItem(val, 0);
                if (elem) {
                    cJSON *ipaddr = cJSON_GetObjectItemCaseSensitive(elem, "ipaddr");
                    if (ipaddr && cJSON_IsString(ipaddr) && ipaddr->valuestring) {
                        /* Strip CIDR suffix (e.g., /27) */
                        const char *slash = strchr(ipaddr->valuestring, '/');
                        if (slash) {
                            size_t len = slash - ipaddr->valuestring;
                            if (len >= out_len) len = out_len - 1;
                            strncpy(output, ipaddr->valuestring, len);
                            output[len] = '\0';
                        } else {
                            snprintf(output, out_len, "%s", ipaddr->valuestring);
                        }
                    }
                }
            }
        }
    }

    cJSON_Delete(json);
}

static void fetch_opnsense_ip(const char* target_ip, const char* api_key, const char* api_sec, const char* iface, char *ip_buffer, size_t buf_len) {
    if (!target_ip || !api_key || !api_sec || !iface) {
        snprintf(ip_buffer, buf_len, "Unconfigured");
        return;
    }

    CURL *curl = curl_easy_init();
    if (!curl) {
        snprintf(ip_buffer, buf_len, "CURL Error");
        return;
    }

    struct MemoryStruct chunk = { NULL, 0 };
    char url[256], userpwd[256];
    
    snprintf(url, sizeof(url), "https://%s/api/interfaces/overview/getInterface/%s", target_ip, iface);
    snprintf(userpwd, sizeof(userpwd), "%s:%s", api_key, api_sec);

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_HTTPAUTH, CURLAUTH_BASIC);
    curl_easy_setopt(curl, CURLOPT_USERPWD, userpwd);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 5L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);

    if (curl_easy_perform(curl) == CURLE_OK && chunk.memory) {
        extract_ip_from_json(chunk.memory, ip_buffer, buf_len);
    } else {
        snprintf(ip_buffer, buf_len, "Unreachable");
    }

    free(chunk.memory);
    curl_easy_cleanup(curl);
}

/* Helper to send static text responses for errors */
static enum MHD_Result send_text_response(struct MHD_Connection *connection, int status_code, const char *text) {
    struct MHD_Response *response = MHD_create_response_from_buffer(strlen(text), (void *)text, MHD_RESPMEM_PERSISTENT);
    MHD_add_response_header(response, "Content-Type", "text/plain");
    enum MHD_Result ret = MHD_queue_response(connection, status_code, response);
    MHD_destroy_response(response);
    return ret;
}

/* Main Request Router */
static enum MHD_Result answer_to_connection(void *cls, struct MHD_Connection *connection,
                                           const char *url, const char *method,
                                           const char *version, const char *upload_data,
                                           size_t *upload_data_size, void **con_cls) {
    
    if (NULL == *con_cls) {
        *con_cls = (void *)1;  
        return MHD_YES;
    }
    *con_cls = NULL;

    /* 1. Strict Path Enforcement */
    if (strcmp(url, "/api/ips") != 0) {
        return send_text_response(connection, MHD_HTTP_NOT_FOUND, "Not Found\n");
    }

    /* 2. Strict Method Enforcement */
    if (strcmp(method, "GET") != 0) {
        return send_text_response(connection, MHD_HTTP_METHOD_NOT_ALLOWED, "Method Not Allowed\n");
    }

    /* 3. Bearer Token Authentication */
    const char *auth_header = MHD_lookup_connection_value(connection, MHD_HEADER_KIND, "Authorization");
    if (!auth_header || strcmp(auth_header, app_config.auth_header) != 0) {
        return send_text_response(connection, MHD_HTTP_UNAUTHORIZED, "Unauthorized\n");
    }

    /* 4. Parse X-Forwarded-For */
    const char *xff = MHD_lookup_connection_value(connection, MHD_HEADER_KIND, "X-Forwarded-For");
    if (!xff) xff = "Unknown";

    /* 5. Generate JSON Response */
    cJSON *res_json = cJSON_CreateObject();
    
    /* 6. Iterate through all configured dynamic hosts */
    for (size_t i = 0; i < app_config.host_count; i++) {
        OpnsenseHost *h = &app_config.hosts[i];
        char fetched_ip[64];
        fetch_opnsense_ip(h->ip, h->key, h->sec, h->iface, fetched_ip, sizeof(fetched_ip));
        cJSON_AddStringToObject(res_json, h->json_key, fetched_ip);
    }

    char *json_str = cJSON_PrintUnformatted(res_json);
    cJSON_Delete(res_json);

    struct MHD_Response *response = MHD_create_response_from_buffer(strlen(json_str), (void *)json_str, MHD_RESPMEM_MUST_COPY);
    MHD_add_response_header(response, "Content-Type", "application/json");
    enum MHD_Result ret = MHD_queue_response(connection, MHD_HTTP_OK, response);
    
    MHD_destroy_response(response);
    cJSON_free(json_str);

    return ret;
}

int main(void) {
    signal(SIGTERM, handle_signal);
    signal(SIGINT, handle_signal);

    curl_global_init(CURL_GLOBAL_DEFAULT);

    /* Load Configuration Once at Startup */
    const char *token = getenv("API_TOKEN");
    if (!token) {
        fprintf(stderr, "FATAL: API_TOKEN environment variable is required.\n");
        return EXIT_FAILURE;
    }
    snprintf(app_config.auth_header, sizeof(app_config.auth_header), "Bearer %s", token);

    /* Dynamically discover OPNSENSE<N>_ environment variables */
    app_config.hosts = NULL;
    app_config.host_count = 0;

    for (int i = 1; i <= MAX_HOST_SCAN; i++) {
        char env_ip[64], env_key[64], env_sec[64], env_int[64];
        snprintf(env_ip, sizeof(env_ip), "OPNSENSE%d_IP", i);
        snprintf(env_key, sizeof(env_key), "OPNSENSE%d_KEY", i);
        snprintf(env_sec, sizeof(env_sec), "OPNSENSE%d_SECRET", i);
        snprintf(env_int, sizeof(env_int), "OPNSENSE%d_INT", i);

        const char *ip = getenv(env_ip);
        const char *key = getenv(env_key);
        const char *sec = getenv(env_sec);
        const char *iface = getenv(env_int);

        if (ip && key && sec) {
            app_config.hosts = realloc(app_config.hosts, (app_config.host_count + 1) * sizeof(OpnsenseHost));
            OpnsenseHost *host = &app_config.hosts[app_config.host_count];
            
            host->id = i;
            host->ip = strdup(ip);
            host->key = strdup(key);
            host->sec = strdup(sec);
            host->iface = strdup(iface ? iface : "vmx0");
            snprintf(host->json_key, sizeof(host->json_key), "fw%d_public_ip", i);

            app_config.host_count++;
        }
    }

    printf("Loaded %zu OPNsense host configuration(s).\n", app_config.host_count);

    /* Start the HTTP Daemon */
    struct MHD_Daemon *daemon = MHD_start_daemon(
        MHD_USE_INTERNAL_POLLING_THREAD | MHD_USE_ERROR_LOG,  
        PORT, NULL, NULL,  
        &answer_to_connection, NULL,  
        MHD_OPTION_END
    );

    if (NULL == daemon) {
        fprintf(stderr, "FATAL: Failed to start libmicrohttpd server.\n");
        return EXIT_FAILURE;
    }
    
    printf("Server listening on port %d...\n", PORT);

    while (keep_running) {
        pause();  
    }

    printf("\nShutting down server gracefully...\n");
    MHD_stop_daemon(daemon);
    curl_global_cleanup();

    /* Clean up allocated host memory */
    for (size_t i = 0; i < app_config.host_count; i++) {
        free(app_config.hosts[i].ip);
        free(app_config.hosts[i].key);
        free(app_config.hosts[i].sec);
        free(app_config.hosts[i].iface);
    }
    free(app_config.hosts);

    return EXIT_SUCCESS;
}
