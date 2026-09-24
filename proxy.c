#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/event.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <pthread.h>
#include <fcntl.h>
#include <time.h>

#define BACKLOG 32
#define BUFFER_SIZE 8192
#define MAX_CACHE_SIZE 5
#define CACHE_TTL 60
#define POOL_TIMEOUT 30 // Seconds idle before closing pooled socket

// Rate Limiting Constants
#define MAX_TOKENS 10.0
#define REFILL_RATE 2.0 // Tokens per second

// Global Metrics Trackers
long total_requests = 0;
long cache_hits = 0;
long blocked_requests = 0;
long rate_limited_requests = 0;
long total_bytes_proxied = 0;
long pooled_connections_reused = 0;
pthread_mutex_t metrics_lock = PTHREAD_MUTEX_INITIALIZER;

// Rate Limit Node Structure
typedef struct RateLimitNode {
    char ip[INET_ADDRSTRLEN];
    double tokens;
    time_t last_update;
    struct RateLimitNode *next;
} RateLimitNode;

RateLimitNode *rl_head = NULL;
pthread_mutex_t rl_lock = PTHREAD_MUTEX_INITIALIZER;

// Connection Pool Node Structure
typedef struct PoolNode {
    char host[256];
    int port;
    int sock_fd;
    time_t timestamp;
    struct PoolNode *next;
} PoolNode;

PoolNode *pool_head = NULL;
pthread_mutex_t pool_lock = PTHREAD_MUTEX_INITIALIZER;

// Cache Node Structure
typedef struct CacheNode {
    char url[512];
    char *response;
    size_t response_len;
    time_t timestamp;
    struct CacheNode *next;
} CacheNode;

CacheNode *cache_head = NULL;
pthread_mutex_t cache_lock = PTHREAD_MUTEX_INITIALIZER;

// Blacklist structure
#define MAX_BLACKLIST 100
char blacklist[MAX_BLACKLIST][256];
int blacklist_count = 0;
pthread_mutex_t blacklist_lock = PTHREAD_MUTEX_INITIALIZER;

void load_blacklist() {
    FILE *f = fopen("blacklist.txt", "r");
    if (!f) {
        f = fopen("blacklist.txt", "w");
        if (f) {
            fprintf(f, "malicious-site.com\nads.example.com\n");
            fclose(f);
            f = fopen("blacklist.txt", "r");
        }
    }
    if (f) {
        pthread_mutex_lock(&blacklist_lock);
        while (fscanf(f, "%255s", blacklist[blacklist_count]) == 1) {
            blacklist_count++;
            if (blacklist_count >= MAX_BLACKLIST) break;
        }
        pthread_mutex_unlock(&blacklist_lock);
        fclose(f);
        printf("[INFO] Loaded %d blacklisted domains from blacklist.txt\n", blacklist_count);
    }
}

int is_blacklisted(const char *host) {
    pthread_mutex_lock(&blacklist_lock);
    for (int i = 0; i < blacklist_count; i++) {
        if (strcasecmp(blacklist[i], host) == 0) {
            pthread_mutex_unlock(&blacklist_lock);
            return 1;
        }
    }
    pthread_mutex_unlock(&blacklist_lock);
    return 0;
}

// Token Bucket Rate Limiting Check
int check_rate_limit(const char *ip) {
    pthread_mutex_lock(&rl_lock);
    time_t now = time(NULL);
    RateLimitNode *curr = rl_head;

    while (curr != NULL) {
        if (strcmp(curr->ip, ip) == 0) {
            double elapsed = difftime(now, curr->last_update);
            curr->tokens += elapsed * REFILL_RATE;
            if (curr->tokens > MAX_TOKENS) curr->tokens = MAX_TOKENS;
            curr->last_update = now;

            if (curr->tokens >= 1.0) {
                curr->tokens -= 1.0;
                pthread_mutex_unlock(&rl_lock);
                return 1; // Allowed
            } else {
                pthread_mutex_unlock(&rl_lock);
                return 0; // Rate limited (429)
            }
        }
        curr = curr->next;
    }

    // New IP entry
    RateLimitNode *new_node = malloc(sizeof(RateLimitNode));
    snprintf(new_node->ip, sizeof(new_node->ip), "%s", ip);
    new_node->tokens = MAX_TOKENS - 1.0;
    new_node->last_update = now;
    new_node->next = rl_head;
    rl_head = new_node;
    pthread_mutex_unlock(&rl_lock);
    return 1;
}

// Connection Pool Management
int pool_get(const char *host, int port) {
    pthread_mutex_lock(&pool_lock);
    PoolNode *curr = pool_head;
    PoolNode *prev = NULL;
    time_t now = time(NULL);

    while (curr != NULL) {
        if (curr->port == port && strcmp(curr->host, host) == 0) {
            char test_buf;
            int alive = (recv(curr->sock_fd, &test_buf, 1, MSG_PEEK | MSG_DONTWAIT) != 0);
            if (!alive || difftime(now, curr->timestamp) > POOL_TIMEOUT) {
                close(curr->sock_fd);
                if (prev) prev->next = curr->next;
                else pool_head = curr->next;
                PoolNode *temp = curr;
                curr = curr->next;
                free(temp);
                continue;
            }

            int fd = curr->sock_fd;
            if (prev) prev->next = curr->next;
            else pool_head = curr->next;
            free(curr);
            pthread_mutex_unlock(&pool_lock);
            
            pthread_mutex_lock(&metrics_lock);
            pooled_connections_reused++;
            pthread_mutex_unlock(&metrics_lock);

            return fd;
        }
        prev = curr;
        curr = curr->next;
    }
    pthread_mutex_unlock(&pool_lock);
    return -1;
}

void pool_put(const char *host, int port, int sock_fd) {
    pthread_mutex_lock(&pool_lock);
    PoolNode *new_node = malloc(sizeof(PoolNode));
    strncpy(new_node->host, host, sizeof(new_node->host) - 1);
    new_node->host[sizeof(new_node->host) - 1] = '\0';
    new_node->port = port;
    new_node->sock_fd = sock_fd;
    new_node->timestamp = time(NULL);
    new_node->next = pool_head;
    pool_head = new_node;
    pthread_mutex_unlock(&pool_lock);
}

int cache_get(const char *url, char **response, size_t *response_len) {
    pthread_mutex_lock(&cache_lock);
    CacheNode *curr = cache_head;
    CacheNode *prev = NULL;
    time_t now = time(NULL);

    while (curr != NULL) {
        if (strcmp(curr->url, url) == 0) {
            if (difftime(now, curr->timestamp) > CACHE_TTL) {
                if (prev) prev->next = curr->next;
                else cache_head = curr->next;
                free(curr->response);
                free(curr);
                pthread_mutex_unlock(&cache_lock);
                return 0;
            }

            if (prev != NULL) {
                prev->next = curr->next;
                curr->next = cache_head;
                cache_head = curr;
            }

            *response = malloc(curr->response_len);
            memcpy(*response, curr->response, curr->response_len);
            *response_len = curr->response_len;
            pthread_mutex_unlock(&cache_lock);
            return 1;
        }
        prev = curr;
        curr = curr->next;
    }
    pthread_mutex_unlock(&cache_lock);
    return 0;
}

void cache_put(const char *url, const char *response, size_t response_len) {
    pthread_mutex_lock(&cache_lock);
    int count = 0;
    CacheNode *curr = cache_head;
    CacheNode *prev = NULL;
    while (curr != NULL) {
        count++;
        if (count >= MAX_CACHE_SIZE) {
            CacheNode *temp = curr;
            if (prev) prev->next = NULL;
            else cache_head = NULL;
            free(temp->response);
            free(temp);
            break;
        }
        prev = curr;
        curr = curr->next;
    }

    CacheNode *new_node = malloc(sizeof(CacheNode));
    snprintf(new_node->url, sizeof(new_node->url), "%s", url);
    new_node->response = malloc(response_len);
    memcpy(new_node->response, response, response_len);
    new_node->response_len = response_len;
    new_node->timestamp = time(NULL);
    new_node->next = cache_head;
    cache_head = new_node;
    pthread_mutex_unlock(&cache_lock);
}

void *handle_client(void *client_socket_ptr) {
    int client_socket = *(int *)client_socket_ptr;
    free(client_socket_ptr);
    pthread_detach(pthread_self());

    // Extract client IP address for Rate Limiting
    struct sockaddr_in peer_addr;
    socklen_t peer_len = sizeof(peer_addr);
    getpeername(client_socket, (struct sockaddr *)&peer_addr, &peer_len);
    char client_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(peer_addr.sin_addr), client_ip, INET_ADDRSTRLEN);

    // Enforce Token Bucket Rate Limit
    if (!check_rate_limit(client_ip)) {
        pthread_mutex_lock(&metrics_lock);
        rate_limited_requests++;
        pthread_mutex_unlock(&metrics_lock);

        char *rate_err = "HTTP/1.1 429 Too Many Requests\r\nContent-Length: 46\r\n\r\n<html><body><h1>429 Rate Limited</h1></body></html>";
        write(client_socket, rate_err, strlen(rate_err));
        close(client_socket);
        return NULL;
    }

    pthread_mutex_lock(&metrics_lock);
    total_requests++;
    pthread_mutex_unlock(&metrics_lock);

    char buffer[BUFFER_SIZE];
    memset(buffer, 0, BUFFER_SIZE);

    ssize_t bytes_received = read(client_socket, buffer, BUFFER_SIZE - 1);
    if (bytes_received <= 0) {
        close(client_socket);
        return NULL;
    }

    // Check for internal /stats endpoint request
    if (strstr(buffer, "GET /stats") != NULL) {
        pthread_mutex_lock(&metrics_lock);
        char stats_body[512];
        int body_len = snprintf(stats_body, sizeof(stats_body),
            "{\n  \"total_requests\": %ld,\n  \"cache_hits\": %ld,\n  \"blocked_requests\": %ld,\n  \"rate_limited_requests\": %ld,\n  \"pooled_connections_reused\": %ld,\n  \"total_bytes_proxied\": %ld\n}\n",
            total_requests, cache_hits, blocked_requests, rate_limited_requests, pooled_connections_reused, total_bytes_proxied);
        pthread_mutex_unlock(&metrics_lock);

        char header[256];
        int header_len = snprintf(header, sizeof(header),
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n", body_len);

        write(client_socket, header, header_len);
        write(client_socket, stats_body, body_len);
        close(client_socket);
        return NULL;
    }

    // Parse Host header and port
    char target_host[256] = "example.com";
    int target_port = 80;
    char *host_line = strstr(buffer, "Host: ");
    if (host_line != NULL) {
        host_line += 6;
        char *end = strchr(host_line, '\r');
        if (end == NULL) end = strchr(host_line, '\n');
        if (end != NULL) {
            size_t len = end - host_line;
            if (len < sizeof(target_host)) {
                strncpy(target_host, host_line, len);
                target_host[len] = '\0';
                char *colon = strchr(target_host, ':');
                if (colon != NULL) {
                    *colon = '\0';
                    target_port = atoi(colon + 1);
                }
            }
        }
    }

    // Check Blacklist
    if (is_blacklisted(target_host)) {
        pthread_mutex_lock(&metrics_lock);
        blocked_requests++;
        pthread_mutex_unlock(&metrics_lock);

        char *forbidden = "HTTP/1.1 403 Forbidden\r\nContent-Length: 43\r\n\r\n<html><body><h1>403 Forbidden</h1></body></html>";
        write(client_socket, forbidden, strlen(forbidden));
        close(client_socket);
        return NULL;
    }

    // Handle HTTPS CONNECT Tunnel
    if (strncmp(buffer, "CONNECT", 7) == 0) {
        int https_port = 443;
        sscanf(buffer, "CONNECT %255[^:]:%d", target_host, &https_port);

        struct addrinfo hints, *res;
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        char port_str[16];
        snprintf(port_str, sizeof(port_str), "%d", https_port);

        if (getaddrinfo(target_host, port_str, &hints, &res) != 0) {
            char *err = "HTTP/1.1 502 Bad Gateway\r\n\r\n";
            write(client_socket, err, strlen(err));
            close(client_socket);
            return NULL;
        }

        int remote_socket = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
        if (remote_socket < 0 || connect(remote_socket, res->ai_addr, res->ai_addrlen) < 0) {
            char *err = "HTTP/1.1 502 Bad Gateway\r\n\r\n";
            write(client_socket, err, strlen(err));
            if (remote_socket >= 0) close(remote_socket);
            freeaddrinfo(res);
            close(client_socket);
            return NULL;
        }
        freeaddrinfo(res);

        char *ok_msg = "HTTP/1.1 200 Connection Established\r\n\r\n";
        write(client_socket, ok_msg, strlen(ok_msg));

        int kq = kqueue();
        struct kevent ev[2];
        EV_SET(&ev[0], client_socket, EVFILT_READ, EV_ADD, 0, 0, NULL);
        EV_SET(&ev[1], remote_socket, EVFILT_READ, EV_ADD, 0, 0, NULL);
        kevent(kq, ev, 2, NULL, 0, NULL);

        struct kevent events[2];
        while (1) {
            int nev = kevent(kq, NULL, 0, events, 2, NULL);
            if (nev < 0) break;
            for (int i = 0; i < nev; i++) {
                int fd = (int)events[i].ident;
                if (fd == client_socket) {
                    int n = read(client_socket, buffer, BUFFER_SIZE);
                    if (n <= 0) goto tunnel_end;
                    write(remote_socket, buffer, n);
                } else if (fd == remote_socket) {
                    int n = read(remote_socket, buffer, BUFFER_SIZE);
                    if (n <= 0) goto tunnel_end;
                    write(client_socket, buffer, n);
                }
            }
        }
    tunnel_end:
        close(kq);
        close(remote_socket);
        close(client_socket);
        return NULL;
    }

    // Check Cache
    char *cached_response = NULL;
    size_t cached_len = 0;
    if (cache_get(target_host, &cached_response, &cached_len)) {
        pthread_mutex_lock(&metrics_lock);
        cache_hits++;
        pthread_mutex_unlock(&metrics_lock);

        write(client_socket, cached_response, cached_len);
        free(cached_response);
        close(client_socket);
        return NULL;
    }

    // Retrieve socket from connection pool or establish new connection
    int remote_socket = pool_get(target_host, target_port);
    if (remote_socket < 0) {
        struct addrinfo hints, *res;
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        char port_str[16];
        snprintf(port_str, sizeof(port_str), "%d", target_port);

        if (getaddrinfo(target_host, port_str, &hints, &res) != 0) {
            char *err = "HTTP/1.1 502 Bad Gateway\r\n\r\n";
            write(client_socket, err, strlen(err));
            close(client_socket);
            return NULL;
        }

        remote_socket = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
        if (remote_socket < 0 || connect(remote_socket, res->ai_addr, res->ai_addrlen) < 0) {
            char *err = "HTTP/1.1 502 Bad Gateway\r\n\r\n";
            write(client_socket, err, strlen(err));
            if (remote_socket >= 0) close(remote_socket);
            freeaddrinfo(res);
            close(client_socket);
            return NULL;
        }
        freeaddrinfo(res);
    }

    // Header Injection
    char modified_buffer[BUFFER_SIZE];
    memset(modified_buffer, 0, BUFFER_SIZE);
    char *header_end = strstr(buffer, "\r\n\r\n");
    if (header_end != NULL) {
        size_t headers_len = header_end - buffer;
        snprintf(modified_buffer, headers_len + 1, "%s", buffer);
        strcat(modified_buffer, "X-Proxied-By: CustomCProxy-RateLimited\r\n");
        strcat(modified_buffer, header_end);
        write(remote_socket, modified_buffer, strlen(modified_buffer));
    } else {
        write(remote_socket, buffer, bytes_received);
    }

    size_t total_resp_len = 0;
    char *full_response = NULL;
    ssize_t bytes_read;

    while ((bytes_read = read(remote_socket, buffer, BUFFER_SIZE)) > 0) {
        write(client_socket, buffer, bytes_read);
        full_response = realloc(full_response, total_resp_len + bytes_read);
        memcpy(full_response + total_resp_len, buffer, bytes_read);
        total_resp_len += bytes_read;
    }

    if (total_resp_len > 0) {
        cache_put(target_host, full_response, total_resp_len);
        free(full_response);
        
        pthread_mutex_lock(&metrics_lock);
        total_bytes_proxied += total_resp_len;
        pthread_mutex_unlock(&metrics_lock);
    }

    // Return socket to pool for reuse
    pool_put(target_host, target_port, remote_socket);

    close(client_socket);
    return NULL;
}

int main(int argc, char *argv[]) {
    int port = 8080;
    if (argc > 1) {
        port = atoi(argv[1]);
    }

    load_blacklist();

    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("Socket failed");
        exit(EXIT_FAILURE);
    }

    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in address;
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(port);

    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("Bind failed");
        exit(EXIT_FAILURE);
    }

    if (listen(server_fd, BACKLOG) < 0) {
        perror("Listen failed");
        exit(EXIT_FAILURE);
    }

    int kq = kqueue();
    if (kq < 0) {
        perror("kqueue failed");
        exit(EXIT_FAILURE);
    }

    struct kevent change;
    EV_SET(&change, server_fd, EVFILT_READ, EV_ADD, 0, 0, NULL);
    kevent(kq, &change, 1, NULL, 0, NULL);

    printf("Enterprise Rate-Limited Proxy Server listening on port %d...\n", port);

    struct kevent event;
    while (1) {
        int nev = kevent(kq, NULL, 0, &event, 1, NULL);
        if (nev < 0) continue;

        if ((int)event.ident == server_fd) {
            int *client_socket = malloc(sizeof(int));
            if ((*client_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&address)) < 0) {
                free(client_socket);
                continue;
            }

            pthread_t thread_id;
            if (pthread_create(&thread_id, NULL, handle_client, (void *)client_socket) < 0) {
                free(client_socket);
                close(*client_socket);
            }
        }
    }

    close(server_fd);
    close(kq);
    return 0;
}
