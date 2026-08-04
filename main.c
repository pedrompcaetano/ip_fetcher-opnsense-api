#include <sys/types.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <curl/curl.h>
#include <cjson/cJSON.h>
#include <microhttpd.h>
#include <signal.h>
#include <unistd.h>

#define MAX_RESPONSE_SIZE (1024 * 1024)
#define PORT 8000

/* Global application configuration */
struct AppConfig {
    char auth_header[512];
    const char *fw1_ip;
    const char *fw1_key;
    const char *fw1_sec;
    const char *fw2_ip;
    const char *fw2_key;
    const char *fw2_sec;
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

static int is_public_ipv4(const char *ip_str) {
    struct in_addr addr;
    if (inet_pton(AF_INET, ip_str, &addr) != 1) return 0;

    uint32_t ip = ntohl(addr.s_addr);
    if ((ip & 0xFF000000) == 0x0A000000) return 0;
    if ((ip & 0xFFF00000) == 0xAC100000) return 0;
    if ((ip & 0xFFFF0000) == 0xC0A80000) return 0;
    if ((ip & 0xFFC00000) == 0x64400000) return 0;
    if ((ip & 0xFF000000) == 0x7F000000) return 0;
    if ((ip & 0xFFFF0000) == 0xA9FE0000) return 0;

    return 1;
}

static void extract_public_ip_from_json(const char *json_str, char *output, size_t out_len) {
    snprintf(output, out_len, "Not Found");
    cJSON *json = cJSON_Parse(json_str);
    if (!json) return;

    if (cJSON_IsObject(json)) {
        cJSON *interface = NULL;
        cJSON_ArrayForEach(interface, json) {
            cJSON *ip_item = cJSON_GetObjectItemCaseSensitive(interface, "ipaddr");
            if (cJSON_IsString(ip_item) && (ip_item->valuestring != NULL)) {
                if (is_public_ipv4(ip_item->valuestring)) {
                    snprintf(output, out_len, "%s", ip_item->valuestring);
                    cJSON_Delete(json);
                    return;
                }
            }
        }
    }
    cJSON_Delete(json);
}

static void fetch_opnsense_ip(const char* target_ip, const char* api_key, const char* api_sec, char *ip_buffer, size_t buf_len) {
    if (!target_ip || !api_key || !api_sec) {
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
    
    snprintf(url, sizeof(url), "https://%s/api/diagnostics/interface/getInterfaceConfig", target_ip);
    snprintf(userpwd, sizeof(userpwd), "%s:%s", api_key, api_sec);

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_USERPWD, userpwd);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 5L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);

    if (curl_easy_perform(curl) == CURLE_OK && chunk.memory) {
        extract_public_ip_from_json(chunk.memory, ip_buffer, buf_len);
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
    
    /* libmicrohttpd calls this twice per request (headers, then body). 
       Since we strictly expect GET (no body), we acknowledge the first call and process on the second. */
    if (NULL == *con_cls) {
        *con_cls = (void *)1; 
        return MHD_YES;
    }
    *con_cls = NULL; /* reset for next request */

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

    /* 5. Fetch IPs */
    char fw1_ip[64], fw2_ip[64];
    fetch_opnsense_ip(app_config.fw1_ip, app_config.fw1_key, app_config.fw1_sec, fw1_ip, sizeof(fw1_ip));
    fetch_opnsense_ip(app_config.fw2_ip, app_config.fw2_key, app_config.fw2_sec, fw2_ip, sizeof(fw2_ip));

    /* 6. Generate JSON Response */
    cJSON *res_json = cJSON_CreateObject();
    cJSON_AddStringToObject(res_json, "source_ip", xff);
    cJSON_AddStringToObject(res_json, "fw1_public_ip", fw1_ip);
    cJSON_AddStringToObject(res_json, "fw2_public_ip", fw2_ip);
    
    char *json_str = cJSON_PrintUnformatted(res_json);
    cJSON_Delete(res_json);

    struct MHD_Response *response = MHD_create_response_from_buffer(strlen(json_str), (void *)json_str, MHD_RESPMEM_MUST_COPY);
    MHD_add_response_header(response, "Content-Type", "application/json");
    enum MHD_Result ret = MHD_queue_response(connection, MHD_HTTP_OK, response);
    
    MHD_destroy_response(response);
    cJSON_free(json_str); /* Clean up the string generated by cJSON */

    return ret;
}

int main(void) {
    /* Handle container stop signals gracefully */
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
    
    app_config.fw1_ip = getenv("OPNSENSE1_IP");
    app_config.fw1_key = getenv("OPNSENSE1_KEY");
    app_config.fw1_sec = getenv("OPNSENSE1_SECRET");
    app_config.fw2_ip = getenv("OPNSENSE2_IP");
    app_config.fw2_key = getenv("OPNSENSE2_KEY");
    app_config.fw2_sec = getenv("OPNSENSE2_SECRET");

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

    /* Suspend main thread until signal is received */
    while (keep_running) {
        pause(); 
    }

    printf("\nShutting down server gracefully...\n");
    MHD_stop_daemon(daemon);
    curl_global_cleanup();

    return EXIT_SUCCESS;
}
