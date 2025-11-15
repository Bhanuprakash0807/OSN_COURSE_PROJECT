#include "common.h"
#include <sys/time.h>
#include <signal.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <netinet/tcp.h>
#include <unistd.h>

typedef struct TrieNode {
    struct TrieNode *children[256];
    int ss_index;
    int is_end;
} TrieNode;

typedef struct {
    FileMetadata metadata;
    int ss_index;
} FileRecord;

typedef struct {
    char key[MAX_FILENAME];
    FileRecord *value;
} CacheEntry;

// Global state
StorageServerInfo storage_servers[MAX_SS];
int num_ss = 0;
pthread_mutex_t ss_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t ss_cond = PTHREAD_COND_INITIALIZER;  // For signaling SS status changes

ClientInfo clients[MAX_CLIENTS];
int num_clients = 0;
pthread_mutex_t client_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t client_cond = PTHREAD_COND_INITIALIZER;  // For client list changes

FileRecord files[MAX_FILES];
int num_files = 0;
pthread_mutex_t file_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t file_access_mutex = PTHREAD_MUTEX_INITIALIZER;  // For file access operations

TrieNode *file_trie_root;
pthread_mutex_t trie_mutex = PTHREAD_MUTEX_INITIALIZER;

CacheEntry cache[100];
int cache_size = 0;
pthread_mutex_t cache_mutex = PTHREAD_MUTEX_INITIALIZER;
time_t cache_last_cleanup = 0;

int nm_port;

// --- Metadata persistence (owner/ACL) ---
static int save_metadata_locked();
static int save_metadata();
static int load_metadata();

// Forward declarations for functions used before their definitions
void trie_insert(TrieNode *root, const char *key, int ss_idx);
static void cache_clear();

static int save_metadata_locked() {
    // Assumes file_mutex is held
    char tmpfile[MAX_PATH] = {0};
    snprintf(tmpfile, sizeof(tmpfile), "%s.tmp", METADATA_FILE);
    FILE *fp = fopen(tmpfile, "w");
    if (!fp) return -1;
    // Write count first
    fprintf(fp, "%d\n", num_files);
    for (int i = 0; i < num_files; i++) {
        FileRecord *fr = &files[i];
        // filename
        fprintf(fp, "%s\n", fr->metadata.filename);
        // owner
        fprintf(fp, "%s\n", fr->metadata.owner);
        // timestamps and size/word/char (optional; NM treats SS as source of truth for these)
        fprintf(fp, "%ld %ld %ld %d %d\n",
                (long)fr->metadata.created_time,
                (long)fr->metadata.modified_time,
                (long)fr->metadata.accessed_time,
                fr->metadata.word_count,
                fr->metadata.char_count);
        // access list
        fprintf(fp, "%d\n", fr->metadata.num_users);
        for (int j = 0; j < fr->metadata.num_users; j++) {
            fprintf(fp, "%s %d\n", fr->metadata.users[j].username, fr->metadata.users[j].access_type);
        }
    }
    fflush(fp);
    fsync(fileno(fp));
    fclose(fp);
    // Atomic rename
    if (rename(tmpfile, METADATA_FILE) != 0) {
        unlink(tmpfile);
        return -1;
    }
    return 0;
}

static int save_metadata() {
    pthread_mutex_lock(&file_mutex);
    int rc = save_metadata_locked();
    pthread_mutex_unlock(&file_mutex);
    return rc;
}

static int load_metadata() {
    FILE *fp = fopen(METADATA_FILE, "r");
    if (!fp) return -1; // Not fatal if missing
    int count = 0;
    if (fscanf(fp, "%d\n", &count) != 1 || count < 0 || count > MAX_FILES) {
        fclose(fp);
        return -1;
    }
    pthread_mutex_lock(&file_mutex);
    num_files = 0;
    for (int i = 0; i < count; i++) {
        FileRecord fr = {0};
        char line[MAX_BUFFER];
        if (!fgets(line, sizeof(line), fp)) break; // filename
        line[strcspn(line, "\n")] = 0;
        strncpy(fr.metadata.filename, line, MAX_FILENAME - 1);
        if (!fgets(line, sizeof(line), fp)) break; // owner
        line[strcspn(line, "\n")] = 0;
        strncpy(fr.metadata.owner, line, MAX_USERNAME - 1);
        long c=0,m=0,a=0; int w=0,ch=0;
        if (!fgets(line, sizeof(line), fp)) break;
        sscanf(line, "%ld %ld %ld %d %d", &c, &m, &a, &w, &ch);
        fr.metadata.created_time = (time_t)c;
        fr.metadata.modified_time = (time_t)m;
        fr.metadata.accessed_time = (time_t)a;
        fr.metadata.word_count = w;
        fr.metadata.char_count = ch;
        int u = 0;
        if (fscanf(fp, "%d\n", &u) != 1) break;
        fr.metadata.num_users = 0;
        for (int j = 0; j < u && j < MAX_ACCESS_USERS; j++) {
            if (!fgets(line, sizeof(line), fp)) break;
            char uname[MAX_USERNAME]; int at = 0;
            if (sscanf(line, "%63s %d", uname, &at) == 2) {
                strncpy(fr.metadata.users[fr.metadata.num_users].username, uname, MAX_USERNAME - 1);
                fr.metadata.users[fr.metadata.num_users].access_type = at;
                fr.metadata.num_users++;
            }
        }
        fr.ss_index = -1; // Will be resolved on SS list arrival
        files[num_files++] = fr;
        // Insert into trie for faster lookup
        pthread_mutex_lock(&trie_mutex);
        trie_insert(file_trie_root, fr.metadata.filename, fr.ss_index);
        pthread_mutex_unlock(&trie_mutex);
    }
    pthread_mutex_unlock(&file_mutex);
    fclose(fp);
    cache_clear();
    return 0;
}

// Format a time_t into YYYY-MM-DD HH:MM:SS; returns malloc'd string
static char* format_time(time_t t) {
    char *buf = (char*)malloc(64);
    if (!buf) return strdup("-");
    struct tm tmv;
    localtime_r(&t, &tmv);
    strftime(buf, 64, "%Y-%m-%d %H:%M:%S", &tmv);
    return buf;
}

// Fetch live stats for a file from its storage server; update metadata if out is non-NULL
static int fetch_stats_from_ss(const char *filename, int ss_idx, FileMetadata *out, char *last_reader_out) {
    if (ss_idx < 0 || ss_idx >= num_ss || !storage_servers[ss_idx].is_active) return -1;
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return -1;
    struct timeval tv; tv.tv_sec = 5; tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    struct sockaddr_in addr; memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET; addr.sin_port = htons(storage_servers[ss_idx].client_port);
    inet_pton(AF_INET, storage_servers[ss_idx].ip, &addr.sin_addr);
    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) { close(sock); return -1; }
    Message req, resp; memset(&req, 0, sizeof(req));
    req.msg_type = MSG_SS_INFO; strncpy(req.data, filename, MAX_BUFFER-1);
    send_message(sock, &req);
    if (receive_message(sock, &resp) < 0) { close(sock); return -1; }
    close(sock);
    if (resp.error_code != ERR_SUCCESS) return resp.error_code == ERR_FILE_NOT_FOUND ? ERR_FILE_NOT_FOUND : -1;
    // Parse: words chars size last_access last_mod created [last_reader]
    long words=0, chars=0, size=0, acc=0, mod=0, crt=0;
    char last_reader[MAX_USERNAME] = "";
    int n = sscanf(resp.data, "%ld %ld %ld %ld %ld %ld %63s", &words, &chars, &size, &acc, &mod, &crt, last_reader);
    if (n < 6) return -1;
    if (out) {
        out->word_count = (int)words;
        out->char_count = (int)chars;
        out->size = size;
        out->accessed_time = (time_t)acc;
        out->modified_time = (time_t)mod;
        out->created_time = (time_t)crt;
    }
    if (last_reader_out && n == 7) {
        strncpy(last_reader_out, last_reader, MAX_USERNAME - 1);
        last_reader_out[MAX_USERNAME - 1] = '\0';
    }
    return 0;
}

// Forward a simple file command (CREATE/DELETE/EXEC helper) to SS and return response
static int ss_simple_request(int ss_idx, int msg_type, const char *filename, Message *out_resp) {
    if (ss_idx < 0 || ss_idx >= num_ss || !storage_servers[ss_idx].is_active) return ERR_SS_UNAVAILABLE;
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return ERR_NETWORK_ERROR;
    struct timeval tv; tv.tv_sec = 5; tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    struct sockaddr_in addr; memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET; addr.sin_port = htons(storage_servers[ss_idx].client_port);
    inet_pton(AF_INET, storage_servers[ss_idx].ip, &addr.sin_addr);
    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) { close(sock); return ERR_NETWORK_ERROR; }
    Message req, resp; memset(&req, 0, sizeof(req));
    req.msg_type = msg_type; strncpy(req.data, filename, MAX_BUFFER-1);
    send_message(sock, &req);
    if (receive_message(sock, &resp) < 0) { close(sock); return ERR_NETWORK_ERROR; }
    close(sock);
    if (out_resp) *out_resp = resp;
    return resp.error_code;
}

// Trie functions
TrieNode* create_trie_node() {
    TrieNode *node = (TrieNode*)calloc(1, sizeof(TrieNode));
    node->ss_index = -1;
    node->is_end = 0;
    return node;
}

void trie_insert(TrieNode *root, const char *key, int ss_idx) {
    TrieNode *curr = root;
    for (int i = 0; key[i]; i++) {
        unsigned char ch = (unsigned char)key[i];
        if (!curr->children[ch]) {
            curr->children[ch] = create_trie_node();
        }
        curr = curr->children[ch];
    }
    curr->is_end = 1;
    curr->ss_index = ss_idx;
}

int trie_search(TrieNode *root, const char *key) {
    TrieNode *curr = root;
    for (int i = 0; key[i]; i++) {
        unsigned char ch = (unsigned char)key[i];
        if (!curr->children[ch]) return -1;
        curr = curr->children[ch];
    }
    return (curr && curr->is_end) ? curr->ss_index : -1;
}

// Mark a given key as deleted in the trie (non-destructive; leaves nodes allocated)
void trie_delete(TrieNode *root, const char *key) {
    if (!root || !key) return;
    TrieNode *curr = root;
    for (int i = 0; key[i]; i++) {
        unsigned char ch = (unsigned char)key[i];
        if (!curr->children[ch]) return; // key not present
        curr = curr->children[ch];
    }
    if (curr) {
        curr->is_end = 0;
        curr->ss_index = -1;
    }
}

// Cache functions
static void cleanup_cache_locked() {
    // Assumes cache_mutex is held
    time_t now = time(NULL);
    
    // Only cleanup if it's been at least 5 minutes since last cleanup
    if (now - cache_last_cleanup < 300) {
        return;
    }
    
    // Remove entries older than 30 minutes
    int write_idx = 0;
    for (int read_idx = 0; read_idx < cache_size; read_idx++) {
        if (cache[read_idx].value && cache[read_idx].value->metadata.accessed_time > now - 1800) {
            if (write_idx != read_idx) {
                cache[write_idx] = cache[read_idx];
            }
            write_idx++;
        }
    }
    
    cache_size = write_idx;
    cache_last_cleanup = now;
}

void cache_add(const char *filename, FileRecord *record) {
    pthread_mutex_lock(&cache_mutex);
    
    // Periodically cleanup old entries
    cleanup_cache_locked();
    
    if (cache_size < 100) {
        strncpy(cache[cache_size].key, filename, MAX_FILENAME - 1);
        cache[cache_size].value = record;
        cache_size++;
    } else {
        // LRU-based replacement
        int oldest_idx = 0;
        time_t oldest_time = cache[0].value->metadata.accessed_time;
        
        for (int i = 1; i < 100; i++) {
            if (cache[i].value->metadata.accessed_time < oldest_time) {
                oldest_time = cache[i].value->metadata.accessed_time;
                oldest_idx = i;
            }
        }
        
        strncpy(cache[oldest_idx].key, filename, MAX_FILENAME - 1);
        cache[oldest_idx].value = record;
    }
    pthread_mutex_unlock(&cache_mutex);
}

FileRecord* cache_get(const char *filename) {
    pthread_mutex_lock(&cache_mutex);
    for (int i = 0; i < cache_size; i++) {
        if (strcmp(cache[i].key, filename) == 0) {
            FileRecord *record = cache[i].value;
            pthread_mutex_unlock(&cache_mutex);
            return record;
        }
    }
    pthread_mutex_unlock(&cache_mutex);
    return NULL;
}

// Clear cache completely to avoid stale pointers after files[] mutations
static void cache_clear() {
    pthread_mutex_lock(&cache_mutex);
    cache_size = 0;
    pthread_mutex_unlock(&cache_mutex);
}

// Find file by name (non-blocking: avoid deadlocks by using trylock)
FileRecord* find_file(const char *filename) {
    // First check cache
    FileRecord *cached = cache_get(filename);
    if (cached) {
        pthread_mutex_lock(&file_access_mutex);
        cached->metadata.accessed_time = time(NULL);
        pthread_mutex_unlock(&file_access_mutex);
        return cached;
    }

    // Try to acquire file mutex without blocking to avoid potential deadlocks
    if (pthread_mutex_trylock(&file_mutex) != 0) {
        return NULL; // Busy; caller can retry or treat as not found
    }
    
    for (int i = 0; i < num_files; i++) {
        if (strcmp(files[i].metadata.filename, filename) == 0) {
            pthread_mutex_lock(&file_access_mutex);
            files[i].metadata.accessed_time = time(NULL);
            pthread_mutex_unlock(&file_access_mutex);
            
            cache_add(filename, &files[i]);
            pthread_mutex_unlock(&file_mutex);
            return &files[i];
        }
    }
    pthread_mutex_unlock(&file_mutex);
    return NULL;
}

// Check user access
int check_access(FileRecord *file, const char *username, int required_access) {
    if (strcmp(file->metadata.owner, username) == 0) {
        return 1; // Owner has all access
    }
    
    for (int i = 0; i < file->metadata.num_users; i++) {
        if (strcmp(file->metadata.users[i].username, username) == 0) {
            if (required_access == ACCESS_READ) {
                return (file->metadata.users[i].access_type >= ACCESS_READ);
            } else if (required_access == ACCESS_WRITE) {
                return (file->metadata.users[i].access_type >= ACCESS_WRITE);
            }
        }
    }
    return 0;
}

// Handle client connections
void* handle_client(void *arg) {
    int client_sock = *(int*)arg;
    free(arg);
    
    // Set up signal mask for the thread
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGPIPE);
    pthread_sigmask(SIG_BLOCK, &set, NULL);
    
    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);
    char client_ip[INET_ADDRSTRLEN];
    
    // Get client IP with error handling
    if (getpeername(client_sock, (struct sockaddr*)&addr, &addr_len) < 0) {
        log_error("NM", "getpeername", ERR_NETWORK_ERROR, strerror(errno));
        close(client_sock);
        return NULL;
    }
    
    if (!inet_ntop(AF_INET, &addr.sin_addr, client_ip, INET_ADDRSTRLEN)) {
        log_error("NM", "inet_ntop", ERR_NETWORK_ERROR, strerror(errno));
        close(client_sock);
        return NULL;
    }
    
    // Set TCP_NODELAY to disable Nagle's algorithm
    int flag = 1;
    if (setsockopt(client_sock, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag)) < 0) {
        log_error("NM", "setsockopt TCP_NODELAY", ERR_NETWORK_ERROR, strerror(errno));
    }
    
    // Set socket timeout
    struct timeval tv;
    tv.tv_sec = 30;  // 30 second timeout
    tv.tv_usec = 0;
    if (setsockopt(client_sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
        log_error("NM", "setsockopt", ERR_NETWORK_ERROR, strerror(errno));
    }
    inet_ntop(AF_INET, &addr.sin_addr, client_ip, INET_ADDRSTRLEN);
    
    Message msg, response;
    
    // First message determines if this is a storage server or regular client
    if (receive_message(client_sock, &msg) < 0) {
        close(client_sock);
        return NULL;
    }

    if (msg.msg_type == MSG_REGISTER_SS) {
        pthread_mutex_lock(&ss_mutex);
        if (num_ss >= MAX_SS) {
            pthread_mutex_unlock(&ss_mutex);
            log_error("NM", "register_ss", ERR_TOO_MANY_FILES, "Max storage servers reached");
            Message resp; memset(&resp,0,sizeof(resp)); resp.msg_type = MSG_ERROR; resp.error_code = ERR_TOO_MANY_FILES;
            send_message(client_sock, &resp);
            close(client_sock);
            return NULL;
        }

        int ss_idx = num_ss;

        strncpy(storage_servers[ss_idx].ip, client_ip, INET_ADDRSTRLEN - 1);
        storage_servers[ss_idx].ip[INET_ADDRSTRLEN-1] = '\0';
        sscanf(msg.data, "%d %d", &storage_servers[ss_idx].nm_port,
               &storage_servers[ss_idx].client_port);
        storage_servers[ss_idx].num_files = 0;
        storage_servers[ss_idx].is_active = 1;

        num_ss++;
        pthread_mutex_unlock(&ss_mutex);
        
        log_message("NM", "Storage server registered successfully");
        
        Message response;
        memset(&response, 0, sizeof(response));
        response.msg_type = MSG_ACK;
        response.error_code = ERR_SUCCESS;
        send_message(client_sock, &response);
        close(client_sock);
        return NULL;
    }

    // Enter request-processing loop: process current msg, then wait for next one
    while (1) {
        log_request("NM", client_ip, ntohs(addr.sin_port), "Request received");

        memset(&response, 0, sizeof(response));
        response.msg_type = MSG_RESPONSE;
        response.error_code = ERR_SUCCESS;
        strncpy(response.username, msg.username, MAX_USERNAME - 1);
        response.username[MAX_USERNAME-1] = '\0';

        switch (msg.msg_type) {
            case MSG_REGISTER_CLIENT: {
                pthread_mutex_lock(&client_mutex);
                if (num_clients >= MAX_CLIENTS) {
                    pthread_mutex_unlock(&client_mutex);
                    response.error_code = ERR_TOO_MANY_FILES;
                    snprintf(response.data, MAX_BUFFER, "Max clients reached");
                    break;
                }

                strncpy(clients[num_clients].ip, client_ip, INET_ADDRSTRLEN - 1);
                clients[num_clients].ip[INET_ADDRSTRLEN-1] = '\0';
                clients[num_clients].port = ntohs(addr.sin_port);
                strncpy(clients[num_clients].username, msg.username, MAX_USERNAME - 1);
                clients[num_clients].username[MAX_USERNAME-1] = '\0';
                clients[num_clients].is_active = 1;
                num_clients++;
                pthread_mutex_unlock(&client_mutex);

                log_message("NM", "Client registered successfully");
                snprintf(response.data, MAX_BUFFER, "Registration successful");
                break;
            }
            
            case MSG_SS_INFO: {
                // Storage server sending initial file list after registration
                // Payload format: "LIST <n>\n<file1>\n<file2>\n..."
                // Identify SS by IP
                int ss_idx = -1;
                pthread_mutex_lock(&ss_mutex);
                for (int i = 0; i < num_ss; i++) {
                    if (strcmp(storage_servers[i].ip, client_ip) == 0) { ss_idx = i; break; }
                }
                pthread_mutex_unlock(&ss_mutex);
                if (ss_idx < 0) {
                    response.error_code = ERR_INVALID_COMMAND;
                    snprintf(response.data, MAX_BUFFER, "Unknown storage server");
                    break;
                }
                // Parse list
                int n = 0;
                if (sscanf(msg.data, "LIST %d", &n) == 1 && n >= 0) {
                    // Advance to filenames after first line
                    char *p = strchr(msg.data, '\n');
                    for (int i = 0; i < n && p; i++) {
                        p++;
                        if (!*p) break;
                        char fname[MAX_FILENAME];
                        int len = 0;
                        while (p[len] && p[len] != '\n' && len < MAX_FILENAME-1) len++;
                        memcpy(fname, p, len); fname[len] = '\0';
                        if (len > 0) {
                            // Register file if not present; otherwise update ss_index
                            pthread_mutex_lock(&file_mutex);
                            int found_index = -1;
                            for (int j = 0; j < num_files; j++) {
                                if (strcmp(files[j].metadata.filename, fname) == 0) { found_index = j; break; }
                            }
                            if (found_index >= 0) {
                                files[found_index].ss_index = ss_idx;
                            } else if (num_files < MAX_FILES) {
                                strncpy(files[num_files].metadata.filename, fname, MAX_FILENAME - 1);
                                files[num_files].metadata.owner[0] = '\0';
                                files[num_files].metadata.created_time = time(NULL);
                                files[num_files].metadata.modified_time = time(NULL);
                                files[num_files].metadata.accessed_time = time(NULL);
                                files[num_files].metadata.size = 0;
                                files[num_files].metadata.word_count = 0;
                                files[num_files].metadata.char_count = 0;
                                files[num_files].metadata.num_users = 0;
                                files[num_files].ss_index = ss_idx;
                                num_files++;
                            }
                            pthread_mutex_unlock(&file_mutex);
                            pthread_mutex_lock(&trie_mutex);
                            trie_insert(file_trie_root, fname, ss_idx);
                            pthread_mutex_unlock(&trie_mutex);
                        }
                        p = strchr(p, '\n');
                    }
                    snprintf(response.data, MAX_BUFFER, "OK");
                    // Persist metadata to capture any newly discovered files
                    save_metadata();
                } else {
                    response.error_code = ERR_INVALID_COMMAND;
                    snprintf(response.data, MAX_BUFFER, "Invalid SS_INFO payload");
                }
                break;
            }
            
            case MSG_VIEW_FILES: {
                char result[MAX_BUFFER] = "";
                // Support combined flags like -al or -la by scanning characters
                int show_all = (strchr(msg.data, 'a') != NULL);
                int show_details = (strchr(msg.data, 'l') != NULL);
                
                if (show_details) {
                    if (show_all) {
                        strcat(result, "All files with details:\n");
                    } else {
                        strcat(result, "Accessible files with details:\n");
                    }
                    strcat(result, "---------------------------------------------------------\n");
                    strcat(result, "|  Filename  | Words | Chars | Last Access Time | Owner |\n");
                    strcat(result, "|------------|-------|-------|------------------|-------|\n");
                }
                // Copy filenames to local list to avoid holding lock during network calls
                char filenames_local[MAX_FILES][MAX_FILENAME];
                int ss_idx_local[MAX_FILES];
                int count = 0;
                pthread_mutex_lock(&file_mutex);
                for (int i = 0; i < num_files && count < MAX_FILES; i++) {
                    int has_access = check_access(&files[i], msg.username, ACCESS_READ);
                    if (show_all || has_access) {
                        strncpy(filenames_local[count], files[i].metadata.filename, MAX_FILENAME-1);
                        ss_idx_local[count] = files[i].ss_index;
                        count++;
                    }
                }
                pthread_mutex_unlock(&file_mutex);
                for (int i = 0; i < count; i++) {
                    FileMetadata m = {0};
                    int rc = fetch_stats_from_ss(filenames_local[i], ss_idx_local[i], &m, NULL);
                    if (rc == ERR_FILE_NOT_FOUND) {
                        // Remove from registry lazily
                        pthread_mutex_lock(&file_mutex);
                        for (int j = 0; j < num_files; j++) {
                            if (strcmp(files[j].metadata.filename, filenames_local[i]) == 0) {
                                for (int k = j; k < num_files - 1; k++) files[k] = files[k+1];
                                num_files--;
                                // Invalidate trie and cache after mutation
                                pthread_mutex_lock(&trie_mutex);
                                trie_delete(file_trie_root, filenames_local[i]);
                                pthread_mutex_unlock(&trie_mutex);
                                cache_clear();
                                break;
                            }
                        }
                        pthread_mutex_unlock(&file_mutex);
                        continue;
                    }
                    if (show_details) {
                        // Owner from NM registry
                        pthread_mutex_lock(&file_mutex);
                        const char *owner = "-";
                        for (int j = 0; j < num_files; j++) {
                            if (strcmp(files[j].metadata.filename, filenames_local[i]) == 0) {
                                owner = files[j].metadata.owner;
                                break;
                            }
                        }
                        pthread_mutex_unlock(&file_mutex);
                        char line[512];
                        char *acc = format_time(m.accessed_time ? m.accessed_time : time(NULL));
                        snprintf(line, sizeof(line), "| %-10s | %5d | %5d | %-16s | %-5s |\n",
                                filenames_local[i], m.word_count, m.char_count, acc, owner);
                        free(acc);
                        strcat(result, line);
                    } else {
                        strcat(result, "--> ");
                        strcat(result, filenames_local[i]);
                        strcat(result, "\n");
                    }
                }
                
                if (show_details) {
                    strcat(result, "---------------------------------------------------------\n");
                }
                
                strncpy(response.data, result, MAX_BUFFER - 1);
                break;
            }
            
            case MSG_LIST_USERS: {
                char result[MAX_BUFFER] = "Users:\n";
                // Build a de-duplicated list of usernames
                char seen[MAX_CLIENTS][MAX_USERNAME];
                int seen_count = 0;
                pthread_mutex_lock(&client_mutex);
                for (int i = 0; i < num_clients; i++) {
                    int duplicate = 0;
                    for (int j = 0; j < seen_count; j++) {
                        if (strcmp(seen[j], clients[i].username) == 0) { duplicate = 1; break; }
                    }
                    if (!duplicate && seen_count < MAX_CLIENTS) {
                        strncpy(seen[seen_count], clients[i].username, MAX_USERNAME - 1);
                        seen[seen_count][MAX_USERNAME - 1] = '\0';
                        seen_count++;
                    }
                }
                pthread_mutex_unlock(&client_mutex);
                for (int i = 0; i < seen_count; i++) {
                    strcat(result, "--> ");
                    strcat(result, seen[i]);
                    strcat(result, "\n");
                }
                strncpy(response.data, result, MAX_BUFFER - 1);
                break;
            }
            
            case MSG_INFO_FILE: {
                FileRecord *file = find_file(msg.data);
                if (!file) {
                    response.error_code = ERR_FILE_NOT_FOUND;
                    snprintf(response.data, MAX_BUFFER, "File not found");
                } else {
                    FileMetadata m = {0};
                    char last_reader[MAX_USERNAME] = "";
                    int rc = fetch_stats_from_ss(file->metadata.filename, file->ss_index, &m, last_reader);
                    if (rc == ERR_FILE_NOT_FOUND) {
                        // Remove from NM and report not found
                        pthread_mutex_lock(&file_mutex);
                        for (int i = 0; i < num_files; i++) {
                            if (strcmp(files[i].metadata.filename, file->metadata.filename) == 0) {
                                for (int j = i; j < num_files - 1; j++) files[j] = files[j+1];
                                num_files--;
                                break;
                            }
                        }
                        pthread_mutex_unlock(&file_mutex);
                        pthread_mutex_lock(&trie_mutex);
                        trie_delete(file_trie_root, file->metadata.filename);
                        pthread_mutex_unlock(&trie_mutex);
                        cache_clear();
                        response.error_code = ERR_FILE_NOT_FOUND;
                        snprintf(response.data, MAX_BUFFER, "File not found");
                        break;
                    }
                    // Build info string
                    char result[MAX_BUFFER];
                    char *created_s = format_time(m.created_time ? m.created_time : time(NULL));
                    char *modified_s = format_time(m.modified_time ? m.modified_time : time(NULL));
                    char *accessed_s = format_time(m.accessed_time ? m.accessed_time : time(NULL));
                    snprintf(result, sizeof(result),
                        "File: %s\nOwner: %s\nCreated: %s\nLast Modified: %s\n"
                        "Size: %ld bytes\nLast Accessed: %s by %s\nAccess: ",
                        file->metadata.filename,
                        file->metadata.owner,
                        created_s, modified_s,
                        m.size,
                        accessed_s,
                        (last_reader[0] ? last_reader : file->metadata.owner));
                    free(created_s); free(modified_s); free(accessed_s);
                    strcat(result, file->metadata.owner);
                    strcat(result, " (RW)");
                    for (int i = 0; i < file->metadata.num_users; i++) {
                        strcat(result, ", ");
                        strcat(result, file->metadata.users[i].username);
                        strcat(result, " (");
                        strcat(result, file->metadata.users[i].access_type == ACCESS_WRITE ? "RW" : "R");
                        strcat(result, ")");
                    }
                    strncpy(response.data, result, MAX_BUFFER - 1);
                }
                break;
            }
            
            case MSG_ADD_ACCESS: {
                char *saveptr;
                char *token = strtok_r(msg.data, " ", &saveptr);
                int access_type = (token && strcmp(token, "-W") == 0) ? ACCESS_WRITE : ACCESS_READ;
                
                char *filename = strtok_r(NULL, " ", &saveptr);
                char *target_user = strtok_r(NULL, " ", &saveptr);
                
                if (!filename || !target_user) {
                    response.error_code = ERR_INVALID_COMMAND;
                    snprintf(response.data, MAX_BUFFER, "Invalid command format");
                    break;
                }
                
                FileRecord *file = find_file(filename);
                if (!file) {
                    response.error_code = ERR_FILE_NOT_FOUND;
                    snprintf(response.data, MAX_BUFFER, "File not found");
                } else if (strcmp(file->metadata.owner, msg.username) != 0) {
                    response.error_code = ERR_PERMISSION_DENIED;
                    snprintf(response.data, MAX_BUFFER, "Only owner can modify access");
                } else {
                    int found = 0;
                    for (int i = 0; i < file->metadata.num_users; i++) {
                        if (strcmp(file->metadata.users[i].username, target_user) == 0) {
                            file->metadata.users[i].access_type = access_type;
                            found = 1;
                            break;
                        }
                    }
                    
                    if (!found && file->metadata.num_users < MAX_ACCESS_USERS) {
                        strncpy(file->metadata.users[file->metadata.num_users].username,
                               target_user, MAX_USERNAME - 1);
                        file->metadata.users[file->metadata.num_users].access_type = access_type;
                        file->metadata.num_users++;
                    }
                    
                    save_metadata();
                    snprintf(response.data, MAX_BUFFER, "Access granted successfully");
                }
                break;
            }
            
            case MSG_REM_ACCESS: {
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 char *saveptr;
                char *filename = strtok_r(msg.data, " ", &saveptr);
                char *target_user = strtok_r(NULL, " ", &saveptr);
                
                if (!filename || !target_user) {
                    response.error_code = ERR_INVALID_COMMAND;
                    snprintf(response.data, MAX_BUFFER, "Invalid command format");
                    break;
                }
                
                FileRecord *file = find_file(filename);
                if (!file) {
                    response.error_code = ERR_FILE_NOT_FOUND;
                    snprintf(response.data, MAX_BUFFER, "File not found");
                } else if (strcmp(file->metadata.owner, msg.username) != 0) {
                    response.error_code = ERR_PERMISSION_DENIED;
                    snprintf(response.data, MAX_BUFFER, "Only owner can modify access");
                } else {
                    for (int i = 0; i < file->metadata.num_users; i++) {
                        if (strcmp(file->metadata.users[i].username, target_user) == 0) {
                            for (int j = i; j < file->metadata.num_users - 1; j++) {
                                file->metadata.users[j] = file->metadata.users[j + 1];
                            }
                            file->metadata.num_users--;
                            break;
                        }
                    }
                    save_metadata();
                    snprintf(response.data, MAX_BUFFER, "Access removed successfully");
                }
                break;
            }
            
            case MSG_CREATE_FILE: {
                char *filename = msg.data;
                // Check if duplicate
                if (find_file(filename)) {
                    response.error_code = ERR_FILE_EXISTS;
                    snprintf(response.data, MAX_BUFFER, "File already exists");
                    break;
                }
                // Choose SS with least files
                pthread_mutex_lock(&ss_mutex);
                int min_files = MAX_FILES, target_ss = -1;
                for (int i = 0; i < num_ss; i++) {
                    if (storage_servers[i].is_active && storage_servers[i].num_files < min_files) {
                        min_files = storage_servers[i].num_files;
                        target_ss = i;
                    }
                }
                pthread_mutex_unlock(&ss_mutex);
                if (target_ss < 0) {
                    response.error_code = ERR_SS_UNAVAILABLE;
                    snprintf(response.data, MAX_BUFFER, "Storage server unavailable");
                    break;
                }
                // Forward create to SS and wait for ACK
                Message ss_resp;
                int rc = ss_simple_request(target_ss, MSG_CREATE_FILE, filename, &ss_resp);
                if (rc != ERR_SUCCESS) {
                    response.error_code = rc;
                    snprintf(response.data, MAX_BUFFER, "%s", ss_resp.data[0] ? ss_resp.data : "Create failed");
                    break;
                }
                // Update NM registry on success
                pthread_mutex_lock(&file_mutex);
                strncpy(files[num_files].metadata.filename, filename, MAX_FILENAME - 1);
                strncpy(files[num_files].metadata.owner, msg.username, MAX_USERNAME - 1);
                files[num_files].metadata.created_time = time(NULL);
                files[num_files].metadata.modified_time = time(NULL);
                files[num_files].metadata.accessed_time = time(NULL);
                files[num_files].metadata.size = 0;
                files[num_files].metadata.word_count = 0;
                files[num_files].metadata.char_count = 0;
                files[num_files].metadata.num_users = 0;
                files[num_files].ss_index = target_ss;
                pthread_mutex_lock(&trie_mutex);
                trie_insert(file_trie_root, filename, target_ss);
                pthread_mutex_unlock(&trie_mutex);
                num_files++;
                pthread_mutex_unlock(&file_mutex);
                cache_clear();
                pthread_mutex_lock(&ss_mutex);
                strncpy(storage_servers[target_ss].files[storage_servers[target_ss].num_files], filename, MAX_FILENAME - 1);
                storage_servers[target_ss].num_files++;
                pthread_mutex_unlock(&ss_mutex);
                save_metadata();
                snprintf(response.data, MAX_BUFFER, "Created");
                break;
            }

            case MSG_DELETE_FILE: {
                char *filename = msg.data;
                FileRecord *file = find_file(filename);
                if (!file) {
                    response.error_code = ERR_FILE_NOT_FOUND;
                    snprintf(response.data, MAX_BUFFER, "File not found");
                    break;
                }
                // Permissions: owner or write access
                if (!check_access(file, msg.username, ACCESS_WRITE)) {
                    response.error_code = ERR_PERMISSION_DENIED;
                    snprintf(response.data, MAX_BUFFER, "Write permission required");
                    break;
                }
                int ss_idx = file->ss_index;
                Message ss_resp;
                int rc = ss_simple_request(ss_idx, MSG_DELETE_FILE, filename, &ss_resp);
                if (rc != ERR_SUCCESS) {
                    response.error_code = rc;
                    snprintf(response.data, MAX_BUFFER, "%s", ss_resp.data[0] ? ss_resp.data : "Delete failed");
                    break;
                }
                // Update NM registry
                pthread_mutex_lock(&file_mutex);
                for (int i = 0; i < num_files; i++) {
                    if (strcmp(files[i].metadata.filename, filename) == 0) {
                        for (int j = i; j < num_files - 1; j++) files[j] = files[j+1];
                        num_files--;
                        break;
                    }
                }
                pthread_mutex_unlock(&file_mutex);
                pthread_mutex_lock(&trie_mutex);
                trie_delete(file_trie_root, filename);
                pthread_mutex_unlock(&trie_mutex);
                cache_clear();
                pthread_mutex_lock(&ss_mutex);
                if (ss_idx >= 0 && ss_idx < num_ss && storage_servers[ss_idx].num_files > 0) {
                    storage_servers[ss_idx].num_files--; // Approximate
                }
                pthread_mutex_unlock(&ss_mutex);
                save_metadata();
                snprintf(response.data, MAX_BUFFER, "Deleted");
                break;
            }
            case MSG_READ_FILE:
            case MSG_WRITE_FILE:
            case MSG_STREAM_FILE:
            case MSG_UNDO: {
                // Forward to storage server
                char *filename = msg.data;
                {
                    char dbg[MAX_BUFFER];
                    snprintf(dbg, sizeof(dbg), "Forwarding op %d for file '%s' from user '%s'", msg.msg_type, filename, msg.username);
                    log_message("NM", dbg);
                }

                // Validate existence and access first using NM registry
                FileRecord *file = find_file(filename);
                if (!file) {
                    response.error_code = ERR_FILE_NOT_FOUND;
                    snprintf(response.data, MAX_BUFFER, "File not found");
                    break;
                }
                if (msg.msg_type == MSG_WRITE_FILE || msg.msg_type == MSG_UNDO) {
                    if (!check_access(file, msg.username, ACCESS_WRITE)) {
                        response.error_code = ERR_PERMISSION_DENIED;
                        snprintf(response.data, MAX_BUFFER, "Write permission required");
                        break;
                    }
                } else {
                    if (!check_access(file, msg.username, ACCESS_READ)) {
                        response.error_code = ERR_PERMISSION_DENIED;
                        snprintf(response.data, MAX_BUFFER, "Read permission required");
                        break;
                    }
                }

                // Resolve storage server index preferring registry, fallback to trie
                int ss_idx = file->ss_index;
                if (ss_idx < 0 || ss_idx >= num_ss || !storage_servers[ss_idx].is_active) {
                    pthread_mutex_lock(&trie_mutex);
                    ss_idx = trie_search(file_trie_root, filename);
                    pthread_mutex_unlock(&trie_mutex);
                }

                if (ss_idx < 0 || ss_idx >= num_ss || !storage_servers[ss_idx].is_active) {
                    response.error_code = ERR_SS_UNAVAILABLE;
                    snprintf(response.data, MAX_BUFFER, "Storage server unavailable");
                    break;
                }

                // Send SS endpoint to client
                snprintf(response.data, MAX_BUFFER, "%s %d",
                         storage_servers[ss_idx].ip,
                         storage_servers[ss_idx].client_port);
                {
                    char dbg[MAX_BUFFER];
                    snprintf(dbg, sizeof(dbg), "Selected SS %s:%d for file '%s'", storage_servers[ss_idx].ip, storage_servers[ss_idx].client_port, filename);
                    log_message("NM", dbg);
                }
                break;
            }

            case MSG_EXEC_FILE: {
                // NM handles execution: fetch content from SS, execute here, return output
                char *filename = msg.data;
                FileRecord *file = find_file(filename);
                if (!file) {
                    response.error_code = ERR_FILE_NOT_FOUND;
                    snprintf(response.data, MAX_BUFFER, "File not found");
                    break;
                }
                // Enforce read access for EXEC as per spec
                if (!check_access(file, msg.username, ACCESS_READ)) {
                    response.error_code = ERR_PERMISSION_DENIED;
                    snprintf(response.data, MAX_BUFFER, "Read permission required");
                    break;
                }
                int ss_idx = file->ss_index;
                Message ss_resp;
                int rc = ss_simple_request(ss_idx, MSG_EXEC_FILE, filename, &ss_resp);
                if (rc != ERR_SUCCESS) {
                    response.error_code = rc;
                    snprintf(response.data, MAX_BUFFER, "%s", ss_resp.data[0] ? ss_resp.data : "Exec fetch failed");
                    break;
                }
                // Execute the content as shell commands safely
                FILE *fp = popen(ss_resp.data, "r");
                if (!fp) {
                    response.error_code = ERR_INTERNAL_ERROR;
                    snprintf(response.data, MAX_BUFFER, "Failed to execute commands");
                    break;
                }
                char outbuf[4096];
                outbuf[0] = '\0';
                char line[512];
                while (fgets(line, sizeof(line), fp)) {
                    if (strlen(outbuf) + strlen(line) + 1 < MAX_BUFFER) strcat(outbuf, line);
                }
                pclose(fp);
                strncpy(response.data, outbuf, MAX_BUFFER - 1);
                break;
            }
            
            default:
                response.error_code = ERR_INVALID_COMMAND;
                snprintf(response.data, MAX_BUFFER, "Invalid command");
                break;
        }
        
        {
            char dbg[MAX_BUFFER];
            snprintf(dbg, sizeof(dbg), "About to send response for op=%d, error_code=%d, data='%s'", msg.msg_type, response.error_code, response.data);
            log_message("NM", dbg);
        }
        if (send_message(client_sock, &response) < 0) {
            // Network error sending response; stop servicing this client
            char errbuf[256];
            snprintf(errbuf, sizeof(errbuf), "send_message failed while responding to %s:%d", client_ip, ntohs(addr.sin_port));
            log_error("NM", "send_message", ERR_NETWORK_ERROR, errbuf);
            break;
        }

        char log_buf[MAX_BUFFER];
        snprintf(log_buf, sizeof(log_buf), "Response sent: error_code=%d", response.error_code);
        log_message("NM", log_buf);

        // Wait for next message from the same client; if recv fails, close connection
        if (receive_message(client_sock, &msg) < 0) {
            break;
        }
    }
    
    close(client_sock);
    return NULL;
}

void* handle_storage_server(void *arg) {
    int ss_sock = *(int*)arg;
    free(arg);
    
    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);
    getpeername(ss_sock, (struct sockaddr*)&addr, &addr_len);
    char ss_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &addr.sin_addr, ss_ip, INET_ADDRSTRLEN);
    
    Message msg;
    if (receive_message(ss_sock, &msg) < 0) {
        close(ss_sock);
        return NULL;
    }
    
    if (msg.msg_type == MSG_REGISTER_SS) {
        pthread_mutex_lock(&ss_mutex);
        int ss_idx = num_ss;
        
        strncpy(storage_servers[ss_idx].ip, ss_ip, INET_ADDRSTRLEN - 1);
        sscanf(msg.data, "%d %d", &storage_servers[ss_idx].nm_port,
               &storage_servers[ss_idx].client_port);
        storage_servers[ss_idx].num_files = 0;
        storage_servers[ss_idx].is_active = 1;
        
        num_ss++;
        pthread_mutex_unlock(&ss_mutex);
        
        log_message("NM", "Storage server registered successfully");
        
        Message response;
        memset(&response, 0, sizeof(response));
        response.msg_type = MSG_ACK;
        response.error_code = ERR_SUCCESS;
        send_message(ss_sock, &response);
    }
    
    close(ss_sock);
    return NULL;
}

void* cache_cleanup_thread(void *arg) {
    while (1) {
        sleep(300);  // Run every 5 minutes
        pthread_mutex_lock(&cache_mutex);
        cleanup_cache_locked();
        pthread_mutex_unlock(&cache_mutex);
    }
    return NULL;
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage: %s <port>\n", argv[0]);
        return 1;
    }
    
    nm_port = atoi(argv[1]);
    file_trie_root = create_trie_node();
    cache_last_cleanup = time(NULL);

    // Load persisted metadata (owner/ACL) before SS reconciliation
    load_metadata();
    
    int server_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (server_sock < 0) {
        perror("socket");
        return 1;
    }
    
    // Allow socket reuse
    int opt = 1;
    if (setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("setsockopt reuse");
        return 1;
    }
    
    // Enable keep-alive
    if (setsockopt(server_sock, SOL_SOCKET, SO_KEEPALIVE, &opt, sizeof(opt)) < 0) {
        perror("setsockopt keepalive");
        return 1;
    }
    
    // Set TCP keepalive parameters
    int keepalive_time = 10;  // Start sending keepalive after 10 seconds of idle
    int keepalive_intvl = 5;  // Send keepalive every 5 seconds
    int keepalive_probes = 3; // Drop connection after 3 failed probes
    
    if (setsockopt(server_sock, IPPROTO_TCP, TCP_KEEPIDLE, &keepalive_time, sizeof(keepalive_time)) < 0 ||
        setsockopt(server_sock, IPPROTO_TCP, TCP_KEEPINTVL, &keepalive_intvl, sizeof(keepalive_intvl)) < 0 ||
        setsockopt(server_sock, IPPROTO_TCP, TCP_KEEPCNT, &keepalive_probes, sizeof(keepalive_probes)) < 0) {
        perror("setsockopt TCP keepalive");
        return 1;
    }
    
    // Set socket timeout
    struct timeval tv;
    tv.tv_sec = 30;  // 30 second timeout
    tv.tv_usec = 0;
    if (setsockopt(server_sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0 ||
        setsockopt(server_sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) < 0) {
        perror("setsockopt timeout");
        return 1;
    }
    
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(nm_port);
    
    if (bind(server_sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("bind");
        return 1;
    }
    
    if (listen(server_sock, 50) < 0) {
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
    if (pthread_create(&cleanup_tid, &attr, cache_cleanup_thread, NULL) != 0) {
        log_error("NM", "pthread_create", ERR_INTERNAL_ERROR, "Failed to create cache cleanup thread");
    }
    
    while (1) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        int *client_sock = malloc(sizeof(int));
        if (!client_sock) {
            log_error("NM", "malloc", ERR_MEMORY_ERROR, "Failed to allocate client socket");
            continue;
        }
        
        *client_sock = accept(server_sock, (struct sockaddr*)&client_addr, &client_len);
        if (*client_sock < 0) {
            if (errno == EINTR) {
                free(client_sock);
                continue;  // interrupted by signal, retry accept
            }
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
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
        if (pthread_create(&tid, &attr, handle_client, client_sock) != 0) {
            log_error("NM", "pthread_create", ERR_INTERNAL_ERROR, "Failed to create thread");
            close(*client_sock);
            free(client_sock);
            continue;
        }
    }
    
    close(server_sock);
    return 0;
}