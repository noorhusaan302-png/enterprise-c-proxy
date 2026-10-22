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
#include <signal.h>
#include <strings.h>

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
    char url[1024];
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

// Write the whole buffer, retrying on short writes
static int write_all(int fd, const char *buf, size_t len) {
    while (len > 0) {
        ssize_t n = write(fd, buf, len);
        if (n <= 0) return -1;
        buf += n;
        len -= (size_t)n;
    }
    return 0;
}

// Send a small HTML error page with a correct Content-Length
static void send_simple_response(int fd, const char *status, const char *body) {
    char header[256];
    int hlen = snprintf(header, sizeof(header),
        "HTTP/1.1 %s\r\nContent-Type: text/html\r\nContent-Length: %zu\r\nConnection: close\r\n\r\n",
        status, strlen(body));
    write_all(fd, header, (size_t)hlen);
    write_all(fd, body, strlen(body));
}

// Open a new TCP connection to the upstream server, or return -1
static int connect_upstream(const char *host, int port) {
    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    char port_str[16];
    snprintf(port_str, sizeof(port_str), "%d", port);

    if (getaddrinfo(host, port_str, &hints, &res) != 0) return -1;
    int fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (fd >= 0 && connect(fd, res->ai_addr, res->ai_addrlen) < 0) {
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);
    return fd;
}

// Find a header (case-insensitive) in the header block; returns a pointer to its value
static const char *find_header(const char *resp, size_t header_len, const char *name) {
    size_t nlen = strlen(name);
    const char *p = resp;
    const char *end = resp + header_len;
    while (p < end) {
        const char *line_end = strstr(p, "\r\n");
        if (line_end == NULL || line_end >= end) break;
        if ((size_t)(line_end - p) > nlen && strncasecmp(p, name, nlen) == 0) {
            p += nlen;
            while (*p == ' ' || *p == '\t') p++;
            return p;
        }
        p = line_end + 2;
    }
    return NULL;
}

// Stream the upstream response to the client and keep a copy for the cache.
// Stops at the end of the body when Content-Length is known, so the upstream
// socket can go back to the pool. Otherwise reads until the server closes it.
static size_t relay_response(int remote, int client, int is_head,
                             char **out, int *status_out, int *reusable) {
    char buf[BUFFER_SIZE];
    char *resp = NULL;
    size_t total = 0, header_len = 0;
    long body_expected = -1; // -1 = unknown length
    int headers_done = 0, status = 0, keep_alive = 1;

    *reusable = 0;
    while (1) {
        ssize_t n = read(remote, buf, sizeof(buf));
        if (n <= 0) break; // EOF or error: this connection can't be reused

        write_all(client, buf, (size_t)n);
        char *tmp = realloc(resp, total + (size_t)n + 1);
        if (tmp == NULL) break;
        resp = tmp;
        memcpy(resp + total, buf, (size_t)n);
        total += (size_t)n;
        resp[total] = '\0';

        if (!headers_done) {
            char *end = strstr(resp, "\r\n\r\n");
            if (end != NULL) {
                headers_done = 1;
                header_len = (size_t)(end - resp) + 4;
                sscanf(resp, "HTTP/%*s %d", &status);
                const char *cl = find_header(resp, header_len, "Content-Length:");
                const char *te = find_header(resp, header_len, "Transfer-Encoding:");
                const char *conn = find_header(resp, header_len, "Connection:");
                if (conn != NULL && strncasecmp(conn, "close", 5) == 0) keep_alive = 0;
                if (is_head || status == 204 || status == 304) body_expected = 0;
                else if (cl != NULL && te == NULL) body_expected = atol(cl);
            }
        }

        if (headers_done && body_expected >= 0 &&
            total >= header_len + (size_t)body_expected) {
            *reusable = keep_alive && (total == header_len + (size_t)body_expected);
            break;
        }
    }

    *out = resp;
    *status_out = status;
    return total;
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

    char buffer[BUFFER_SIZE];
    memset(buffer, 0, BUFFER_SIZE);

    ssize_t bytes_received = read(client_socket, buffer, BUFFER_SIZE - 1);
    if (bytes_received <= 0) {
        close(client_socket);
        return NULL;
    }

    // Enforce Token Bucket Rate Limit
    if (!check_rate_limit(client_ip)) {
        pthread_mutex_lock(&metrics_lock);
        rate_limited_requests++;
        pthread_mutex_unlock(&metrics_lock);

        send_simple_response(client_socket, "429 Too Many Requests",
                             "<html><body><h1>429 Rate Limited</h1></body></html>");
        close(client_socket);
        return NULL;
    }

    pthread_mutex_lock(&metrics_lock);
    total_requests++;
    pthread_mutex_unlock(&metrics_lock);

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

        send_simple_response(client_socket, "403 Forbidden",
                             "<html><body><h1>403 Forbidden</h1></body></html>");
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

    // Cache key = host:port + request path, so different pages are cached separately
    char method[16] = "";
    char path[1024] = "/";
    sscanf(buffer, "%15s %1023s", method, path);
    char cache_key[1024];
    snprintf(cache_key, sizeof(cache_key), "%s:%d%s", target_host, target_port, path);
    int cacheable = (strcmp(method, "GET") == 0);

    // Check Cache
    char *cached_response = NULL;
    size_t cached_len = 0;
    if (cacheable && cache_get(cache_key, &cached_response, &cached_len)) {
        pthread_mutex_lock(&metrics_lock);
        cache_hits++;
        pthread_mutex_unlock(&metrics_lock);

        write_all(client_socket, cached_response, cached_len);
        free(cached_response);
        close(client_socket);
        return NULL;
    }

    // Header Injection: add X-Proxied-By as its own header line
    const char *inject = "\r\nX-Proxied-By: CustomCProxy-RateLimited";
    size_t inject_len = strlen(inject);
    char modified_buffer[BUFFER_SIZE + 64];
    size_t out_len;
    char *header_end = strstr(buffer, "\r\n\r\n");
    if (header_end != NULL) {
        size_t headers_len = (size_t)(header_end - buffer);
        size_t rest = (size_t)bytes_received - headers_len;
        memcpy(modified_buffer, buffer, headers_len);
        memcpy(modified_buffer + headers_len, inject, inject_len);
        memcpy(modified_buffer + headers_len + inject_len, header_end, rest);
        out_len = headers_len + inject_len + rest;
    } else {
        memcpy(modified_buffer, buffer, (size_t)bytes_received);
        out_len = (size_t)bytes_received;
    }

    // Try a pooled upstream socket first; if it turns out to be stale,
    // retry once on a fresh connection
    int remote_socket = -1;
    int reusable = 0, status = 0;
    char *full_response = NULL;
    size_t total_resp_len = 0;
    for (int attempt = 0; attempt < 2; attempt++) {
        int from_pool = 0;
        remote_socket = (attempt == 0) ? pool_get(target_host, target_port) : -1;
        if (remote_socket >= 0) from_pool = 1;
        else remote_socket = connect_upstream(target_host, target_port);
        if (remote_socket < 0) break;

        if (write_all(remote_socket, modified_buffer, out_len) == 0) {
            total_resp_len = relay_response(remote_socket, client_socket,
                                            strcmp(method, "HEAD") == 0,
                                            &full_response, &status, &reusable);
        }
        if (total_resp_len > 0) break;

        close(remote_socket);
        remote_socket = -1;
        free(full_response);
        full_response = NULL;
        if (!from_pool) break;
    }

    if (total_resp_len == 0) {
        if (remote_socket >= 0) close(remote_socket);
        send_simple_response(client_socket, "502 Bad Gateway",
                             "<html><body><h1>502 Bad Gateway</h1></body></html>");
        close(client_socket);
        return NULL;
    }

    // Only cache complete, successful GET responses
    if (cacheable && status == 200) {
        cache_put(cache_key, full_response, total_resp_len);
    }
    free(full_response);

    pthread_mutex_lock(&metrics_lock);
    total_bytes_proxied += total_resp_len;
    pthread_mutex_unlock(&metrics_lock);

    // Return the socket to the pool only if the full response was read
    // and the server kept the connection open
    if (reusable) pool_put(target_host, target_port, remote_socket);
    else close(remote_socket);

    close(client_socket);
    return NULL;
}

int main(int argc, char *argv[]) {
    int port = 8080;
    if (argc > 1) {
        port = atoi(argv[1]);
    }

    signal(SIGPIPE, SIG_IGN); // a closed peer must not kill the whole proxy
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
            struct sockaddr_in client_addr;
            socklen_t client_len = sizeof(client_addr);
            int *client_socket = malloc(sizeof(int));
            if ((*client_socket = accept(server_fd, (struct sockaddr *)&client_addr, &client_len)) < 0) {
                free(client_socket);
                continue;
            }

            pthread_t thread_id;
            if (pthread_create(&thread_id, NULL, handle_client, (void *)client_socket) != 0) {
                close(*client_socket);
                free(client_socket);
            }
        }
    }

    close(server_fd);
    close(kq);
    return 0;
}
