#include "../common.h"
#include "storageserver.h"
#include <signal.h>
#include <dirent.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <netinet/tcp.h>
#include <limits.h>
#include <unistd.h>

#define LOCK_TIMEOUT 300 // 5 minutes in seconds
#define MAX_RETRIES 3    // Maximum connection retries

FileData files[MAX_FILES];
int num_files = 0;
pthread_mutex_t files_mutex = PTHREAD_MUTEX_INITIALIZER;

char storage_path[MAX_PATH];
int nm_port, client_port;
char nm_ip[INET_ADDRSTRLEN];

void handle_error(int client_sock, Message *response, int error_code, const char *msg)
{
    response->error_code = error_code;
    snprintf(response->data, MAX_BUFFER, "%s", msg);
    send_message(client_sock, response);
}

// Function to clean up write operation resources
void cleanup_write_resources(FileData *file, int sent_num, const char *username, int client_sock)
{
    // Ensure we unlock the sentence
    if (file)
    {
        unlock_sentence(file, sent_num, username);
        pthread_mutex_unlock(&file->lock);
    }

    // Always close the socket
    if (client_sock >= 0)
    {
        close(client_sock);
    }

    char log_buf[MAX_BUFFER];
    snprintf(log_buf, sizeof(log_buf),
             "Cleaned up write resources for file %s, sentence %d, user %s",
             file ? file->filename : "unknown", sent_num, username);
    log_message("SS", log_buf);
}

void *cleanup_locks_thread(void *arg)
{
    while (1)
    {
        sleep(60); // Check every minute

        pthread_mutex_lock(&files_mutex);
        time_t now = time(NULL);

        for (int i = 0; i < num_files; i++)
        {
            FileData *file = &files[i];
            pthread_mutex_lock(&file->lock);

            // Check for inactive users and clean up their locks
            for (int j = 0; j < file->num_sentences; j++)
            {
                pthread_mutex_lock(&file->sentence_locks[j].mutex);

                if (file->sentence_locks[j].locked)
                {
                    time_t lock_age = now - file->sentence_locks[j].lock_time;

                    // Handle different timeout scenarios
                    if (lock_age > LOCK_TIMEOUT)
                    {
                        // Force unlock if timed out
                        file->sentence_locks[j].locked = 0;
                        file->sentence_locks[j].owner[0] = '\0';
                        pthread_cond_broadcast(&file->sentence_locks[j].cond);

                        char log_buf[MAX_BUFFER];
                        snprintf(log_buf, sizeof(log_buf),
                                 "Forced unlock of sentence %d in file %s due to timeout (age: %ld seconds, owner: %s)",
                                 j, file->filename, lock_age, file->sentence_locks[j].owner);
                        log_message("SS", log_buf);
                    }
                    else if (lock_age > LOCK_TIMEOUT / 2)
                    {
                        // Log warning for locks that are getting old
                        char log_buf[MAX_BUFFER];
                        snprintf(log_buf, sizeof(log_buf),
                                 "Warning: Lock on sentence %d in file %s is aging (age: %ld seconds, owner: %s)",
                                 j, file->filename, lock_age, file->sentence_locks[j].owner);
                        log_message("SS", log_buf);
                    }
                }

                pthread_mutex_unlock(&file->sentence_locks[j].mutex);
            }

            // Clean up any stale write operations
            if (file->is_modified)
            {
                time_t mod_age = now - file->last_modified;
                if (mod_age > LOCK_TIMEOUT)
                {
                    char log_buf[MAX_BUFFER];
                    snprintf(log_buf, sizeof(log_buf),
                             "Warning: File %s has unsaved changes for %ld seconds (last modifier: %s)",
                             file->filename, mod_age, file->last_modifier);
                    log_message("SS", log_buf);
                }
            }

            pthread_mutex_unlock(&file->lock);
        }

        pthread_mutex_unlock(&files_mutex);
    }
    return NULL;
}


void cleanup_handler(__attribute__((unused)) int signo)
{
    log_message("SS", "Cleanup handler called");

    // Save all files
    pthread_mutex_lock(&files_mutex);
    for (int i = 0; i < num_files; i++)
    {
        save_file(&files[i]);

        // Cleanup sentence locks
        if (files[i].sentence_locks)
        {
            for (int j = 0; j < files[i].locks_capacity; j++)
            {
                pthread_mutex_destroy(&files[i].sentence_locks[j].mutex);
                pthread_cond_destroy(&files[i].sentence_locks[j].cond);
            }
            free(files[i].sentence_locks);
        }
    }
    pthread_mutex_unlock(&files_mutex);

    exit(0);
}
// Main entry point
// Main entry point
int main(int argc, char *argv[])
{
    if (argc != 5)
    {
        printf("Usage: %s <nm_ip> <nm_port> <client_port> <storage_path>\n", argv[0]);
        return 1;
    }

    strncpy(nm_ip, argv[1], INET_ADDRSTRLEN - 1);
    nm_port = atoi(argv[2]);
    client_port = atoi(argv[3]);
    strncpy(storage_path, argv[4], MAX_PATH - 1);

    // Set up signal handlers
    signal(SIGINT, cleanup_handler);
    signal(SIGTERM, cleanup_handler);

    // Create storage directory if it doesn't exist
    mkdir(storage_path, 0755);

    // First check for and recover any interrupted operations
    DIR *dir = opendir(storage_path);
    if (dir)
    {
        struct dirent *entry;
        while ((entry = readdir(dir)) != NULL)
        {
            if (strstr(entry->d_name, ".recovery"))
            {
                char recovery_path[MAX_PATH];
                snprintf(recovery_path, sizeof(recovery_path), "%s/%s",
                         storage_path, entry->d_name);

                char log_buf[MAX_BUFFER];
                snprintf(log_buf, sizeof(log_buf),
                         "Found recovery file: %s, attempting recovery",
                         entry->d_name);
                log_message("SS", log_buf);

                if (recover_file_operation(recovery_path) == 0)
                {
                    log_message("SS", "Recovery successful");
                }
                else
                {
                    log_error("SS", "recovery", ERR_INTERNAL_ERROR,
                              "Failed to recover file operation");
                }
            }
        }
        closedir(dir);
    }

    // Now load all regular files
    dir = opendir(storage_path);
    if (dir)
    {
        struct dirent *entry;
        while ((entry = readdir(dir)) != NULL)
        {
            // Skip . and .. directories and temporary files
            if (strcmp(entry->d_name, ".") != 0 &&
                strcmp(entry->d_name, "..") != 0 &&
                !strstr(entry->d_name, ".tmp") &&
                !strstr(entry->d_name, ".bak") &&
                !strstr(entry->d_name, ".recovery"))
            {

                char log_buf[MAX_BUFFER];
                snprintf(log_buf, sizeof(log_buf),
                         "Loading file: %s", entry->d_name);
                log_message("SS", log_buf);

                load_file(entry->d_name);
            }
        }
        closedir(dir);
    }

    // Register with name server with retries
    int nm_sock = -1;
    int retries = 0;

    while (retries < MAX_RETRIES)
    {
        nm_sock = socket(AF_INET, SOCK_STREAM, 0);
        if (nm_sock < 0)
        {
            perror("socket");
            sleep(1);
            retries++;
            continue;
        }

        // Set socket options
        {
            struct timeval tv;
            tv.tv_sec = 5; // 5 second timeout
            tv.tv_usec = 0;
            if (setsockopt(nm_sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0 ||
                setsockopt(nm_sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) < 0)
            {
                perror("setsockopt timeout");
                close(nm_sock);
                sleep(1);
                retries++;
                continue;
            }
        }

        // Enable keep-alive
        {
            int opt = 1;
            if (setsockopt(nm_sock, SOL_SOCKET, SO_KEEPALIVE, &opt, sizeof(opt)) < 0)
            {
                perror("setsockopt keepalive");
                close(nm_sock);
                sleep(1);
                retries++;
                continue;
            }
        }

        // Set TCP keepalive parameters
        {
            int keepalive_time = 10;  // Start sending keepalive after 10 seconds of idle
            int keepalive_intvl = 5;  // Send keepalive every 5 seconds
            int keepalive_probes = 3; // Drop connection after 3 failed probes

            if (setsockopt(nm_sock, IPPROTO_TCP, TCP_KEEPIDLE, &keepalive_time, sizeof(keepalive_time)) < 0 ||
                setsockopt(nm_sock, IPPROTO_TCP, TCP_KEEPINTVL, &keepalive_intvl, sizeof(keepalive_intvl)) < 0 ||
                setsockopt(nm_sock, IPPROTO_TCP, TCP_KEEPCNT, &keepalive_probes, sizeof(keepalive_probes)) < 0)
            {
                perror("setsockopt TCP keepalive");
                close(nm_sock);
                sleep(1);
                retries++;
                continue;
            }
        }

        struct sockaddr_in nm_addr;
        memset(&nm_addr, 0, sizeof(nm_addr));
        nm_addr.sin_family = AF_INET;
        nm_addr.sin_port = htons(nm_port);
        if (inet_pton(AF_INET, nm_ip, &nm_addr.sin_addr) <= 0)
        {
            perror("inet_pton");
            close(nm_sock);
            sleep(1);
            retries++;
            continue;
        }

        if (connect(nm_sock, (struct sockaddr *)&nm_addr, sizeof(nm_addr)) < 0)
        {
            perror("connect");
            close(nm_sock);
            sleep(1);
            retries++;
            continue;
        }

        break; // Connection successful
    }

    if (retries == MAX_RETRIES)
    {
        log_error("SS", "connect", ERR_NETWORK_ERROR, "Failed to connect to name server after retries");
        return 1;
    }

    Message reg_msg;
    memset(&reg_msg, 0, sizeof(reg_msg));
    reg_msg.msg_type = MSG_REGISTER_SS;
    // Advertise local IP used for the connection so NM can provide a reachable endpoint to clients
    char local_ip[INET_ADDRSTRLEN] = "";
    struct sockaddr_in local_addr;
    socklen_t local_len = sizeof(local_addr);
    if (getsockname(nm_sock, (struct sockaddr *)&local_addr, &local_len) == 0)
    {
        inet_ntop(AF_INET, &local_addr.sin_addr, local_ip, sizeof(local_ip));
    }
    if (local_ip[0])
    {
        snprintf(reg_msg.data, MAX_BUFFER, "%d %d %s", nm_port, client_port, local_ip);
    }
    else
    {
        snprintf(reg_msg.data, MAX_BUFFER, "%d %d", nm_port, client_port);
    }

    send_message(nm_sock, &reg_msg);

    Message response;
    receive_message(nm_sock, &response);
    close(nm_sock);

    if (response.error_code != ERR_SUCCESS)
    {
        log_message("SS", "Failed to register with name server");
        return 1;
    }

    log_message("SS", "Registered with name server successfully");

    // Send initial file list to NM
    int nm_sock2 = socket(AF_INET, SOCK_STREAM, 0);
    if (nm_sock2 >= 0)
    {
        struct sockaddr_in nm_addr2;
        memset(&nm_addr2, 0, sizeof(nm_addr2));
        nm_addr2.sin_family = AF_INET;
        nm_addr2.sin_port = htons(nm_port);
        inet_pton(AF_INET, nm_ip, &nm_addr2.sin_addr);
        if (connect(nm_sock2, (struct sockaddr *)&nm_addr2, sizeof(nm_addr2)) == 0)
        {
            Message list_msg;
            memset(&list_msg, 0, sizeof(list_msg));
            list_msg.msg_type = MSG_SS_INFO;
            // Build payload with per-file metadata and ACLs.
            // Format:
            // LIST <n>\n
            // For each file:
            // <filename>\n
            // <owner>\n
            // <size> <words> <chars> <accessed> <modified> <created>\n
            // <num_users>\n
            // <user> <access>\n ...
            char payload[MAX_BUFFER];
            int count = num_files;
            int off = snprintf(payload, sizeof(payload), "LIST %d\n", count);
            for (int i = 0; i < num_files && off < (int)sizeof(payload) - 2; i++)
            {
                FileData *f = &files[i];
                // Ensure safe string formatting
                int n = snprintf(payload + off, sizeof(payload) - off, "%s\n", f->filename);
                if (n < 0)
                    break;
                off += n;
                n = snprintf(payload + off, sizeof(payload) - off, "%s\n", f->owner[0] ? f->owner : "-");
                if (n < 0)
                    break;
                off += n;
                long size = (long)strlen(f->content);
                n = snprintf(payload + off, sizeof(payload) - off, "%ld %d %d %ld %ld %ld\n",
                             size, f->word_count, f->char_count,
                             (long)f->last_access, (long)f->last_modified, (long)f->created_time);
                if (n < 0)
                    break;
                off += n;
                n = snprintf(payload + off, sizeof(payload) - off, "%d\n", f->num_users);
                if (n < 0)
                    break;
                off += n;
                for (int u = 0; u < f->num_users && off < (int)sizeof(payload) - 2; u++)
                {
                    n = snprintf(payload + off, sizeof(payload) - off, "%s %d\n",
                                 f->users[u].username, f->users[u].access_type);
                    if (n < 0)
                        break;
                    off += n;
                }
            }
            strncpy(list_msg.data, payload, MAX_BUFFER - 1);
            send_message(nm_sock2, &list_msg);
            Message ack2;
            receive_message(nm_sock2, &ack2);
        }
        close(nm_sock2);
    }

    // Start client server
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
    server_addr.sin_port = htons(client_port);

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
    snprintf(log_buf, sizeof(log_buf), "Storage Server started on port %d", client_port);
    log_message("SS", log_buf);

    // Start background cleanup thread
    pthread_t cleanup_tid;
    pthread_create(&cleanup_tid, NULL, cleanup_locks_thread, NULL);
    pthread_detach(cleanup_tid);

    // Set socket options for server socket
    int server_opt = 1;
    if (setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, &server_opt, sizeof(server_opt)) < 0)
    {
        perror("setsockopt reuse");
        close(server_sock);
        return 1;
    }

    // Enable keep-alive for server socket
    if (setsockopt(server_sock, SOL_SOCKET, SO_KEEPALIVE, &server_opt, sizeof(server_opt)) < 0)
    {
        perror("setsockopt keepalive");
        close(server_sock);
        return 1;
    }

    // Set TCP keepalive parameters for server socket
    int server_keepalive_time = 10;  // Start sending keepalive after 10 seconds of idle
    int server_keepalive_intvl = 5;  // Send keepalive every 5 seconds
    int server_keepalive_probes = 3; // Drop connection after 3 failed probes

    if (setsockopt(server_sock, IPPROTO_TCP, TCP_KEEPIDLE, &server_keepalive_time, sizeof(server_keepalive_time)) < 0 ||
        setsockopt(server_sock, IPPROTO_TCP, TCP_KEEPINTVL, &server_keepalive_intvl, sizeof(server_keepalive_intvl)) < 0 ||
        setsockopt(server_sock, IPPROTO_TCP, TCP_KEEPCNT, &server_keepalive_probes, sizeof(server_keepalive_probes)) < 0)
    {
        perror("setsockopt TCP keepalive");
        close(server_sock);
        return 1;
    }

    // Set socket timeout for server socket
    struct timeval server_tv;
    server_tv.tv_sec = 30; // 30 second timeout
    server_tv.tv_usec = 0;
    if (setsockopt(server_sock, SOL_SOCKET, SO_RCVTIMEO, &server_tv, sizeof(server_tv)) < 0 ||
        setsockopt(server_sock, SOL_SOCKET, SO_SNDTIMEO, &server_tv, sizeof(server_tv)) < 0)
    {
        perror("setsockopt timeout");
        close(server_sock);
        return 1;
    }

    // Initialize thread attributes for better concurrency
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

    while (1)
    {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        int *client_sock = malloc(sizeof(int));
        *client_sock = accept(server_sock, (struct sockaddr *)&client_addr, &client_len);

        if (*client_sock < 0)
        {
            if (errno == EINTR)
            {
                free(client_sock);
                continue;
            }
            if (errno == EAGAIN || errno == EWOULDBLOCK)
            {
                free(client_sock);
                usleep(10000);
                continue;
            }
            perror("accept");
            free(client_sock);
            continue;
        }
        {
            char acc[MAX_BUFFER];
            char ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &client_addr.sin_addr, ip, sizeof(ip));
            snprintf(acc, sizeof(acc), "accept() ok: %s:%d", ip, ntohs(client_addr.sin_port));
            log_message("SS", acc);
        }

        // Process client inline to improve stability; switch back to threads later if needed
        int fd = *client_sock;
        fprintf(stderr, "[SS-DBG] about to process_client ptr=%p fd=%d\n", (void *)client_sock, fd);
        fflush(stderr);
        free(client_sock);
        process_client(fd);
    }

    close(server_sock);
    return 0;
}