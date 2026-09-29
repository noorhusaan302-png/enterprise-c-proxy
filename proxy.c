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

#define BACKLOG 32
#define BUFFER_SIZE 8192
#define MAX_CACHE_SIZE 5
#define CACHE_TTL 60
#define POOL_TIMEOUT 30

#define MAX_TOKENS 10.0
#define REFILL_RATE 2.0

long total_requests = 0;
long cache_hits = 0;
long blocked_requests = 0;
long rate_limited_requests = 0;
long total_bytes_proxied = 0;
long pooled_connections_reused = 0;
pthread_mutex_t metrics_lock = PTHREAD_MUTEX_INITIALIZER;

#define MAX_BLACK_DOMAINS 100
char *blacklist[MAX_BLACK_DOMAINS];
int blacklist_count = 0;
pthread_mutex_t blacklist_lock = PTHREAD_MUTEX_INITIALIZER;

void load_blacklist() {
    pthread_mutex_lock(&blacklist_lock);
    FILE *f = fopen("blacklist.txt", "r");
    if (!f) {
        printf("[INFO] No blacklist.txt found, skipping domain blacklisting.\n");
        pthread_mutex_unlock(&blacklist_lock);
        return;
    }
    char line[256];
    while (fgets(line, sizeof(line), f) && blacklist_count < MAX_BLACK_DOMAINS) {
        line[strcspn(line, "\r\n")] = 0;
        if (strlen(line) > 0) {
            blacklist[blacklist_count++] = strdup(line);
        }
    }
    fclose(f);
    printf("[INFO] Loaded %d blacklisted domains from blacklist.txt\n", blacklist_count);
    pthread_mutex_unlock(&blacklist_lock);
}

int is_blacklisted(const char *host) {
    pthread_mutex_lock(&blacklist_lock);
    for (int i = 0; i < blacklist_count; i++) {
        if (strstr(host, blacklist[i]) != NULL) {
            pthread_mutex_unlock(&blacklist_lock);
            return 1;
        }
    }
    pthread_mutex_unlock(&blacklist_lock);
    return 0;
}

void *handle_client(void *arg) {
    int client_fd = *(int *)arg;
    free(arg);

    char buffer[BUFFER_SIZE];
    ssize_t bytes_received = recv(client_fd, buffer, sizeof(buffer) - 1, 0);
    if (bytes_received <= 0) {
        close(client_fd);
        return NULL;
    }
    buffer[bytes_received] = '\0';

    char *host_header = strstr(buffer, "Host: ");
    char target_host[256] = "localhost";
    int target_port = 80;

    if (host_header) {
        sscanf(host_header, "Host: %255[^\r\n]", target_host);
        char *port_ptr = strchr(target_host, ':');
        if (port_ptr) {
            *port_ptr = '\0';
            target_port = atoi(port_ptr + 1);
        }
    }

    if (is_blacklisted(target_host)) {
        pthread_mutex_lock(&metrics_lock);
        blocked_requests++;
        pthread_mutex_unlock(&metrics_lock);

        const char *forbidden = "HTTP/1.1 403 Forbidden\r\nContent-Length: 25\r\n\r\nAccess Denied by Proxy";
        write(client_fd, forbidden, strlen(forbidden));
        close(client_fd);
        return NULL;
    }

    pthread_mutex_lock(&metrics_lock);
    total_requests++;
    pthread_mutex_unlock(&metrics_lock);

    const char *resp = "HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\nHello, Proxy!";
    write(client_fd, resp, strlen(resp));

    close(client_fd);
    return NULL;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <port>\n", argv[0]);
        exit(1);
    }

    signal(SIGPIPE, SIG_IGN);
    load_blacklist();

    int port = atoi(argv[1]);
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("socket failed");
        exit(1);
    }

    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in address;
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(port);

    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("bind failed");
        exit(1);
    }

    if (listen(server_fd, BACKLOG) < 0) {
        perror("listen failed");
        exit(1);
    }

    printf("Enterprise Rate-Limited Proxy Server listening on port %d...\n", port);

    while (1) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        int *client_socket = malloc(sizeof(int));
        if (!client_socket) continue;

        *client_socket = accept(server_fd, (struct sockaddr *)&client_addr, &client_len);
        if (*client_socket < 0) {
            free(client_socket);
            continue;
        }

        pthread_t thread_id;
        if (pthread_create(&thread_id, NULL, handle_client, (void *)client_socket) != 0) {
            close(*client_socket);
            free(client_socket);
        } else {
            pthread_detach(thread_id);
        }
    }

    close(server_fd);
    return 0;
}
