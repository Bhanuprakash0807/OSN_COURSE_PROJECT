#include "../common.h"
#include "nameserver.h"
#include <sys/time.h>
#include <signal.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <netinet/tcp.h>
#include <unistd.h>

// Global state
StorageServerInfo storage_servers[MAX_SS];
int num_ss = 0;
pthread_mutex_t ss_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t ss_cond = PTHREAD_COND_INITIALIZER; // For signaling SS status changes

ClientInfo clients[MAX_CLIENTS];
int num_clients = 0;
pthread_mutex_t client_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t client_cond = PTHREAD_COND_INITIALIZER; // For client list changes

// Persistent user list
char known_users[MAX_CLIENTS][MAX_USERNAME];
int num_known_users = 0;
pthread_mutex_t users_mutex = PTHREAD_MUTEX_INITIALIZER;

// Format a time_t into YYYY-MM-DD HH:MM:SS; returns malloc'd string
char *format_time(time_t t)
{
    char *buf = (char *)malloc(64);
    if (!buf)
        return strdup("-");
    struct tm tmv;
    localtime_r(&t, &tmv);
    strftime(buf, 64, "%Y-%m-%d %H:%M:%S", &tmv);
    return buf;
}


void *cache_cleanup_thread(void *arg)
{
    while (1)
    {
        sleep(300); // Run every 5 minutes
        pthread_mutex_lock(&cache_mutex);
        cleanup_cache_locked();
        pthread_mutex_unlock(&cache_mutex);
    }
    return NULL;
}

int main(int argc, char *argv[])
{
    if (argc != 2)
    {
        printf("Usage: %s <port>\n", argv[0]);
        return 1;
    }

    nm_port = atoi(argv[1]);
    file_trie_root = create_trie_node();
    cache_last_cleanup = time(NULL);

    // Load persisted metadata (owner/ACL) before SS reconciliation
    // Load persisted user list first, then metadata
    load_users();
    load_metadata();
    // Mark persisted entries as unverified: don't expose files until an SS confirms
    // This avoids showing stale files that may have been removed from storage
    pthread_mutex_lock(&file_mutex);
    for (int i = 0; i < num_files; i++)
    {
        files[i].ss_index = -1; // unknown until SS reports
        // remove from trie so lookups won't return stale locations
        pthread_mutex_lock(&trie_mutex);
        trie_delete(file_trie_root, files[i].metadata.filename);
        pthread_mutex_unlock(&trie_mutex);
    }
    pthread_mutex_unlock(&file_mutex);
    cache_clear();

    int server_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (server_sock < 0)
    {
        perror("socket");
        return 1;
    }

    // Allow socket reuse
    int opt = 1;
    if (setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0)
    {
        perror("setsockopt reuse");
        return 1;
    }

    // Enable keep-alive
    if (setsockopt(server_sock, SOL_SOCKET, SO_KEEPALIVE, &opt, sizeof(opt)) < 0)
    {
        perror("setsockopt keepalive");
        return 1;
    }

    // Set TCP keepalive parameters
    int keepalive_time = 10;  // Start sending keepalive after 10 seconds of idle
    int keepalive_intvl = 5;  // Send keepalive every 5 seconds
    int keepalive_probes = 3; // Drop connection after 3 failed probes

    if (setsockopt(server_sock, IPPROTO_TCP, TCP_KEEPIDLE, &keepalive_time, sizeof(keepalive_time)) < 0 ||
        setsockopt(server_sock, IPPROTO_TCP, TCP_KEEPINTVL, &keepalive_intvl, sizeof(keepalive_intvl)) < 0 ||
        setsockopt(server_sock, IPPROTO_TCP, TCP_KEEPCNT, &keepalive_probes, sizeof(keepalive_probes)) < 0)
    {
        perror("setsockopt TCP keepalive");
        return 1;
    }

    // Set socket timeout
    struct timeval tv;
    tv.tv_sec = 30; // 30 second timeout
    tv.tv_usec = 0;
    if (setsockopt(server_sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0 ||
        setsockopt(server_sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) < 0)
    {
        perror("setsockopt timeout");
        return 1;
    }

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(nm_port);

    if (bind(server_sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
    {
        perror("bind");
        return 1;
    }

    if (listen(server_sock, 50) < 0)
    {
        perror("listen");
        return 1;
    }

    char log_buf[MAX_BUFFER];
    snprintf(log_buf, sizeof(log_buf), "Name Server started on port %d", nm_port);
    log_message("NM", log_buf);

    // Set up thread attributes for better concurrency
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

    // Start background cache cleanup thread
    pthread_t cleanup_tid;
    if (pthread_create(&cleanup_tid, &attr, cache_cleanup_thread, NULL) != 0)
    {
        log_error("NM", "pthread_create", ERR_INTERNAL_ERROR, "Failed to create cache cleanup thread");
    }

    while (1)
    {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        int *client_sock = malloc(sizeof(int));
        if (!client_sock)
        {
            log_error("NM", "malloc", ERR_MEMORY_ERROR, "Failed to allocate client socket");
            continue;
        }

        *client_sock = accept(server_sock, (struct sockaddr *)&client_addr, &client_len);
        if (*client_sock < 0)
        {
            if (errno == EINTR)
            {
                free(client_sock);
                continue; // interrupted by signal, retry accept
            }
            if (errno == EAGAIN || errno == EWOULDBLOCK)
            {
                // If the socket was set non-blocking elsewhere, yield and retry
                free(client_sock);
                usleep(10000);
                continue;
            }
            perror("accept");
            free(client_sock);
            continue;
        }

        pthread_t tid;
        if (pthread_create(&tid, &attr, handle_client, client_sock) != 0)
        {
            log_error("NM", "pthread_create", ERR_INTERNAL_ERROR, "Failed to create thread");
            close(*client_sock);
            free(client_sock);
            continue;
        }
    }

    close(server_sock);
    return 0;
}