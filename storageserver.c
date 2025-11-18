#include "common.h"
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

typedef struct
{
    int locked;
    char owner[MAX_USERNAME];
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    time_t lock_time;
} SentenceLock;

// Structure to track word changes for undo operations
typedef struct
{
    char **original_words;   // Array of original words
    int *word_indices;       // Array of word indices that were changed
    int num_changes;         // Number of words changed
    char *original_sentence; // Complete original sentence
} UndoInfo;

typedef struct
{
    char filename[MAX_FILENAME];
    char content[MAX_BUFFER * 10];
    char backup[MAX_BUFFER * 10];
    char last_modifier[MAX_USERNAME];
    time_t last_modified;
    SentenceLock *sentence_locks;
    int locks_capacity; // Capacity of sentence_locks array
    int num_sentences;
    pthread_mutex_t lock;
    int word_count;      // Total words in file
    int char_count;      // Total characters in file
    int is_modified;     // Track if file was modified
    time_t last_access;  // Last access timestamp
    time_t created_time; // File creation timestamp
    char last_reader[MAX_USERNAME];
    char owner[MAX_USERNAME];
    UserAccess users[MAX_ACCESS_USERS];
    int num_users;
    UndoInfo last_undo; // Store last operation for undo
} FileData;

FileData files[MAX_FILES];
int num_files = 0;
pthread_mutex_t files_mutex = PTHREAD_MUTEX_INITIALIZER;

char storage_path[MAX_PATH];
int nm_port, client_port;
char nm_ip[INET_ADDRSTRLEN];

// Check if character is a sentence delimiter
#define MAX_DELIMITERS 3
const char SENTENCE_DELIMITERS[MAX_DELIMITERS] = {'.', '!', '?'};

int is_sentence_delimiter(char c)
{
    for (int i = 0; i < MAX_DELIMITERS; i++)
    {
        if (c == SENTENCE_DELIMITERS[i])
            return 1;
    }
    return 0;
}

// Checks if a character sequence ends with a delimiter
int has_delimiter_ending(const char *str)
{
    int len = strlen(str);
    if (len == 0)
        return 0;

    // Check for delimiters at the end
    for (int i = len - 1; i >= 0; i--)
    {
        if (is_sentence_delimiter(str[i]))
            return 1;
        if (str[i] != ' ' && str[i] != '\t' && str[i] != '\n')
            break;
    }
    return 0;
}

// Parse file into sentences with improved handling
// Count total words and characters in content
void count_stats(const char *content, int *words, int *chars)
{
    *words = 0;
    *chars = 0;
    int in_word = 0;

    for (const char *p = content; *p; p++)
    {
        (*chars)++;
        if (*p == ' ' || *p == '\n' || *p == '\t' || is_sentence_delimiter(*p))
        {
            in_word = 0;
        }
        else if (!in_word)
        {
            in_word = 1;
            (*words)++;
        }
    }
}

int parse_sentences(const char *content, char sentences[][MAX_SENTENCE_LEN], int max_sentences)
{
    int sent_idx = 0;
    int char_idx = 0;

    for (int i = 0; content[i] && sent_idx < max_sentences; i++)
    {
        char curr = content[i];

        // Add character to current sentence
        if (char_idx < MAX_SENTENCE_LEN - 2)
        {
            sentences[sent_idx][char_idx++] = curr;
        }

        // Check for sentence delimiter
        if (is_sentence_delimiter(curr))
        {
            // Handle multiple consecutive delimiters
            while (content[i + 1] && is_sentence_delimiter(content[i + 1]) && char_idx < MAX_SENTENCE_LEN - 2)
            {
                sentences[sent_idx][char_idx++] = content[++i];
            }

            // Finalize sentence
            sentences[sent_idx][char_idx] = '\0';
            sent_idx++;
            char_idx = 0;

            // Skip following whitespace
            while (content[i + 1] == ' ' || content[i + 1] == '\t' || content[i + 1] == '\n')
            {
                i++;
            }
            continue;
        }

        // Handle multiple spaces
        if ((curr == ' ' || curr == '\t' || curr == '\n') && char_idx > 1 &&
            (sentences[sent_idx][char_idx - 2] == ' ' ||
             sentences[sent_idx][char_idx - 2] == '\t' ||
             sentences[sent_idx][char_idx - 2] == '\n'))
        {
            char_idx--; // Remove extra space
        }
    }

    // Handle last sentence if not ended with delimiter
    if (char_idx > 0)
    {
        sentences[sent_idx][char_idx] = '\0';
        sent_idx++;
    }

    return sent_idx;
}

// Parse sentence into words
int parse_words(const char *sentence, char words[][MAX_WORD_LEN], int max_words)
{
    int word_idx = 0;
    int char_idx = 0;

    for (int i = 0; sentence[i] && word_idx < max_words; i++)
    {
        if (sentence[i] == ' ')
        {
            if (char_idx > 0)
            {
                words[word_idx][char_idx] = '\0';
                word_idx++;
                char_idx = 0;
            }
        }
        else
        {
            words[word_idx][char_idx++] = sentence[i];
        }
    }

    if (char_idx > 0)
    {
        words[word_idx][char_idx] = '\0';
        word_idx++;
    }

    return word_idx;
}

// Reconstruct content from sentences
// Count words and characters in content
void count_words_and_chars(const char *content, int *word_count, int *char_count)
{
    *word_count = 0;
    *char_count = 0;
    int in_word = 0;

    for (const char *p = content; *p; p++)
    {
        (*char_count)++;
        if (*p == ' ' || *p == '\n' || *p == '\t')
        {
            in_word = 0;
        }
        else if (!in_word)
        {
            in_word = 1;
            (*word_count)++;
        }
    }
}

void reconstruct_content(char sentences[][MAX_SENTENCE_LEN], int num_sentences, char *output)
{
    output[0] = '\0';
    for (int i = 0; i < num_sentences; i++)
    {
        strcat(output, sentences[i]);
        if (i < num_sentences - 1 && sentences[i][strlen(sentences[i]) - 1] != ' ')
        {
            strcat(output, " ");
        }
    }
}

FileData *find_file(const char *filename)
{
    pthread_mutex_lock(&files_mutex);
    for (int i = 0; i < num_files; i++)
    {
        if (strcmp(files[i].filename, filename) == 0)
        {
            pthread_mutex_unlock(&files_mutex);
            return &files[i];
        }
    }
    pthread_mutex_unlock(&files_mutex);
    return NULL;
}

// Reset undo info to safe defaults
static void reset_undo(FileData *file)
{
    if (!file)
        return;
    // Free any allocated memory first
    if (file->last_undo.original_words)
    {
        for (int i = 0; i < file->last_undo.num_changes; i++)
        {
            free(file->last_undo.original_words[i]);
        }
        free(file->last_undo.original_words);
        file->last_undo.original_words = NULL;
    }
    if (file->last_undo.word_indices)
    {
        free(file->last_undo.word_indices);
        file->last_undo.word_indices = NULL;
    }
    if (file->last_undo.original_sentence)
    {
        free(file->last_undo.original_sentence);
        file->last_undo.original_sentence = NULL;
    }
    file->last_undo.num_changes = 0;
}

// Ensure sentence_locks has at least `required` capacity; grow safely if needed
static int ensure_lock_capacity(FileData *file, int required)
{
    if (required <= 0)
        return 0;
    if (file->locks_capacity >= required && file->sentence_locks != NULL)
        return 0;

    int new_capacity = required + 10; // small headroom
    SentenceLock *new_locks = calloc(new_capacity, sizeof(SentenceLock));
    if (!new_locks)
        return -1;

    // Initialize all new mutexes/conds
    for (int i = 0; i < new_capacity; i++)
    {
        pthread_mutex_init(&new_locks[i].mutex, NULL);
        pthread_cond_init(&new_locks[i].cond, NULL);
        new_locks[i].locked = 0;
        new_locks[i].owner[0] = '\0';
        new_locks[i].lock_time = 0;
    }

    // Copy simple state from old locks (not the pthread primitives)
    if (file->sentence_locks)
    {
        int to_copy = file->locks_capacity < new_capacity ? file->locks_capacity : new_capacity;
        for (int i = 0; i < to_copy; i++)
        {
            new_locks[i].locked = file->sentence_locks[i].locked;
            strncpy(new_locks[i].owner, file->sentence_locks[i].owner, MAX_USERNAME - 1);
            new_locks[i].owner[MAX_USERNAME - 1] = '\0';
            new_locks[i].lock_time = file->sentence_locks[i].lock_time;
        }
        // Destroy old pthread primitives and free old array
        for (int i = 0; i < file->locks_capacity; i++)
        {
            pthread_mutex_destroy(&file->sentence_locks[i].mutex);
            pthread_cond_destroy(&file->sentence_locks[i].cond);
        }
        free(file->sentence_locks);
    }

    file->sentence_locks = new_locks;
    file->locks_capacity = new_capacity;
    return 0;
}

int init_sentence_locks(FileData *file)
{
    char sentences[1000][MAX_SENTENCE_LEN];
    int num_sentences = parse_sentences(file->content, sentences, 1000);

    file->num_sentences = num_sentences;

    if (ensure_lock_capacity(file, num_sentences + 1) != 0)
        return -1;

    return 0;
}

int lock_sentence(FileData *file, int sent_num, const char *username)
{
    if (sent_num < 0)
    {
        return ERR_INDEX_OUT_OF_RANGE;
    }

    // If the requested sentence is exactly the next index (append case), allow it.
    if (sent_num > file->num_sentences)
    {
        return ERR_INDEX_OUT_OF_RANGE;
    }
    // Ensure lock array has capacity for this index
    if (ensure_lock_capacity(file, sent_num + 1) != 0)
    {
        return ERR_MEMORY_ERROR;
    }

    // Get current time for timeout checks
    time_t now = time(NULL);

    pthread_mutex_lock(&file->sentence_locks[sent_num].mutex);

    // First check if already locked by this user
    if (file->sentence_locks[sent_num].locked)
    {
        if (strcmp(file->sentence_locks[sent_num].owner, username) == 0)
        {
            // Update lock time to prevent timeouts
            file->sentence_locks[sent_num].lock_time = now;
            pthread_mutex_unlock(&file->sentence_locks[sent_num].mutex);
            return ERR_SUCCESS;
        }

        // Check for lock timeout or stale locks
        if (now - file->sentence_locks[sent_num].lock_time > LOCK_TIMEOUT)
        {
            // Log stale lock removal
            char log_buf[MAX_BUFFER];
            snprintf(log_buf, sizeof(log_buf),
                     "Clearing stale lock on sentence %d in file %s (owner: %s)",
                     sent_num, file->filename, file->sentence_locks[sent_num].owner);
            log_message("SS", log_buf);

            // Force unlock if timeout
            file->sentence_locks[sent_num].locked = 0;
            file->sentence_locks[sent_num].owner[0] = '\0';
            // Notify any waiting threads
            pthread_cond_broadcast(&file->sentence_locks[sent_num].cond);
        }
        else
        {
            pthread_mutex_unlock(&file->sentence_locks[sent_num].mutex);
            return ERR_SENTENCE_LOCKED_BY_USER;
        }
    }

    // At this point, the sentence is either unlocked or we cleared a stale lock
    file->sentence_locks[sent_num].locked = 1;
    strncpy(file->sentence_locks[sent_num].owner, username, MAX_USERNAME - 1);
    file->sentence_locks[sent_num].lock_time = now;

    char log_buf[MAX_BUFFER];
    snprintf(log_buf, sizeof(log_buf),
             "Lock acquired on sentence %d in file %s by user %s",
             sent_num, file->filename, username);
    log_message("SS", log_buf);

    pthread_mutex_unlock(&file->sentence_locks[sent_num].mutex);
    return ERR_SUCCESS;
}

void unlock_sentence(FileData *file, int sent_num, const char *username)
{
    if (sent_num < 0 || sent_num >= file->locks_capacity)
        return;

    pthread_mutex_lock(&file->sentence_locks[sent_num].mutex);

    if (file->sentence_locks[sent_num].locked &&
        strcmp(file->sentence_locks[sent_num].owner, username) == 0)
    {
        file->sentence_locks[sent_num].locked = 0;
        file->sentence_locks[sent_num].owner[0] = '\0';
        pthread_cond_broadcast(&file->sentence_locks[sent_num].cond);
    }

    pthread_mutex_unlock(&file->sentence_locks[sent_num].mutex);
}

void load_file(const char *filename)
{
    char filepath[MAX_PATH];
    snprintf(filepath, sizeof(filepath), "%s/%s", storage_path, filename);

    FILE *fp = fopen(filepath, "r");
    if (!fp)
        return;

    pthread_mutex_lock(&files_mutex);
    if (num_files >= MAX_FILES)
    {
        pthread_mutex_unlock(&files_mutex);
        fclose(fp);
        return;
    }

    strncpy(files[num_files].filename, filename, MAX_FILENAME - 1);

    size_t len = fread(files[num_files].content, 1, sizeof(files[num_files].content) - 1, fp);
    files[num_files].content[len] = '\0';

    strcpy(files[num_files].backup, files[num_files].content);

    pthread_mutex_init(&files[num_files].lock, NULL);
    files[num_files].sentence_locks = NULL;
    files[num_files].locks_capacity = 0;
    files[num_files].num_users = 0;
    files[num_files].owner[0] = '\0';
    files[num_files].last_reader[0] = '\0';
    // Initialize undo state
    files[num_files].last_undo.original_words = NULL;
    files[num_files].last_undo.word_indices = NULL;
    files[num_files].last_undo.original_sentence = NULL;
    files[num_files].last_undo.num_changes = 0;

    // Initialize sentence locks
    if (init_sentence_locks(&files[num_files]) < 0)
    {
        log_message("SS", "Failed to initialize sentence locks");
        pthread_mutex_unlock(&files_mutex);
        return;
    }

    num_files++;
    pthread_mutex_unlock(&files_mutex);

    fclose(fp);
}

// Rescan the storage directory: remove in-memory files that no longer exist
// and load new files from disk. Returns number of files after rescan or -1 on error
int rescan_storage()
{
    DIR *dir = opendir(storage_path);
    if (!dir)
        return -1;

    // Build list of files on disk
    char disk_files[MAX_FILES][MAX_FILENAME];
    int disk_count = 0;
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL && disk_count < MAX_FILES)
    {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            continue;
        if (strstr(entry->d_name, ".tmp") || strstr(entry->d_name, ".bak") || strstr(entry->d_name, ".recovery"))
            continue;
        strncpy(disk_files[disk_count++], entry->d_name, MAX_FILENAME - 1);
    }
    closedir(dir);

    pthread_mutex_lock(&files_mutex);

    // Remove in-memory files that are no longer present on disk
    for (int i = 0; i < num_files;)
    {
        int found = 0;
        for (int j = 0; j < disk_count; j++)
        {
            if (strcmp(files[i].filename, disk_files[j]) == 0)
            {
                found = 1;
                break;
            }
        }
        if (!found)
        {
            // destroy locks and shift array
            if (files[i].sentence_locks)
            {
                for (int k = 0; k < files[i].locks_capacity; k++)
                {
                    pthread_mutex_destroy(&files[i].sentence_locks[k].mutex);
                    pthread_cond_destroy(&files[i].sentence_locks[k].cond);
                }
                free(files[i].sentence_locks);
            }
            pthread_mutex_destroy(&files[i].lock);
            for (int k = i; k < num_files - 1; k++)
                files[k] = files[k + 1];
            num_files--;
        }
        else
        {
            i++;
        }
    }

    // Load files that exist on disk but are not in memory
    for (int i = 0; i < disk_count; i++)
    {
        int present = 0;
        for (int j = 0; j < num_files; j++)
        {
            if (strcmp(files[j].filename, disk_files[i]) == 0)
            {
                present = 1;
                break;
            }
        }
        if (!present)
        {
            load_file(disk_files[i]);
        }
    }

    int final_count = num_files;
    pthread_mutex_unlock(&files_mutex);
    return final_count;
}

int save_file(FileData *file)
{
    char filepath[MAX_PATH];
    char temp_path[MAX_PATH];
    char backup_path[MAX_PATH];

    snprintf(filepath, sizeof(filepath), "%s/%s", storage_path, file->filename);
    snprintf(temp_path, sizeof(temp_path), "%s/%s.tmp", storage_path, file->filename);
    snprintf(backup_path, sizeof(backup_path), "%s/%s.bak", storage_path, file->filename);

    // Backup existing file if present
    if (access(filepath, F_OK) == 0)
    {
        if (rename(filepath, backup_path) != 0)
        {
            log_error("SS", "rename", ERR_INTERNAL_ERROR, "Failed to create backup file");
            return -1;
        }
    }

    // Write to temporary file
    FILE *fp = fopen(temp_path, "w");
    if (!fp)
    {
        log_error("SS", "fopen", ERR_INTERNAL_ERROR, "Failed to create temporary file");
        // Try to restore backup
        if (access(backup_path, F_OK) == 0)
        {
            rename(backup_path, filepath);
        }
        return -1;
    }

    // Write content
    size_t content_len = strlen(file->content);
    size_t written = fwrite(file->content, 1, content_len, fp);

    // Ensure all data is written to disk
    if (fflush(fp) != 0)
    {
        log_error("SS", "fflush", ERR_IO_ERROR, strerror(errno));
        fclose(fp);
        unlink(temp_path);
        if (access(backup_path, F_OK) == 0)
            rename(backup_path, filepath);
        return -1;
    }
    if (fsync(fileno(fp)) != 0)
    {
        log_error("SS", "fsync", ERR_IO_ERROR, strerror(errno));
        fclose(fp);
        unlink(temp_path);
        if (access(backup_path, F_OK) == 0)
            rename(backup_path, filepath);
        return -1;
    }
    fclose(fp);

    if (written != content_len)
    {
        log_error("SS", "write", ERR_IO_ERROR, "Incomplete file write");
        unlink(temp_path);
        if (access(backup_path, F_OK) == 0)
            rename(backup_path, filepath);
        return -1;
    }

    // Atomically replace the file
    if (rename(temp_path, filepath) != 0)
    {
        log_error("SS", "rename", ERR_IO_ERROR, strerror(errno));
        // Try to restore backup
        if (access(backup_path, F_OK) == 0)
            rename(backup_path, filepath);
        unlink(temp_path);
        return -1;
    }

    // Cleanup backup (success path)
    unlink(backup_path);
    return 0;
}

// Error handling helper
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

static void process_client(int client_sock)
{
    fprintf(stderr, "[SS-DBG] process_client: start fd=%d\n", client_sock);
    fflush(stderr);
    log_message("SS", "process_client: start");

    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);
    memset(&addr, 0, sizeof(addr));
    int gp_rc = getpeername(client_sock, (struct sockaddr *)&addr, &addr_len);
    char client_ip[INET_ADDRSTRLEN];
    if (gp_rc == 0)
    {
        inet_ntop(AF_INET, &addr.sin_addr, client_ip, INET_ADDRSTRLEN);
    }
    else
    {
        strncpy(client_ip, "unknown", sizeof(client_ip) - 1);
        client_ip[sizeof(client_ip) - 1] = '\0';
        addr.sin_port = 0;
    }
    {
        char acc[MAX_BUFFER];
        snprintf(acc, sizeof(acc), "Accepted connection from %s:%d", client_ip, ntohs(addr.sin_port));
        log_message("SS", acc);
    }

    // Set socket options
    {
        struct timeval tv;
        tv.tv_sec = 30; // 30 second timeout
        tv.tv_usec = 0;
        if (setsockopt(client_sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0 ||
            setsockopt(client_sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) < 0)
        {
            perror("setsockopt timeout");
            close(client_sock);
            return;
        }
    }

    // Enable keep-alive
    {
        int opt = 1;
        if (setsockopt(client_sock, SOL_SOCKET, SO_KEEPALIVE, &opt, sizeof(opt)) < 0)
        {
            perror("setsockopt keepalive");
            close(client_sock);
            return;
        }
    }

    // Set TCP keepalive parameters
    {
        int keepalive_time = 10;  // Start sending keepalive after 10 seconds of idle
        int keepalive_intvl = 5;  // Send keepalive every 5 seconds
        int keepalive_probes = 3; // Drop connection after 3 failed probes

        if (setsockopt(client_sock, IPPROTO_TCP, TCP_KEEPIDLE, &keepalive_time, sizeof(keepalive_time)) < 0 ||
            setsockopt(client_sock, IPPROTO_TCP, TCP_KEEPINTVL, &keepalive_intvl, sizeof(keepalive_intvl)) < 0 ||
            setsockopt(client_sock, IPPROTO_TCP, TCP_KEEPCNT, &keepalive_probes, sizeof(keepalive_probes)) < 0)
        {
            perror("setsockopt TCP keepalive");
            close(client_sock);
            return;
        }
    }

    // Set up error recovery
    signal(SIGPIPE, SIG_IGN); // Ignore SIGPIPE to handle client disconnects

    Message msg, response;

    if (receive_message(client_sock, &msg) < 0)
    {
        char err[MAX_BUFFER];
        snprintf(err, sizeof(err), "receive_message failed from %s:%d (errno=%d: %s)", client_ip, ntohs(addr.sin_port), errno, strerror(errno));
        log_message("SS", err);
        close(client_sock);
        return;
    }

    log_request("SS", client_ip, ntohs(addr.sin_port), "Request received");
    {
        char dbg[MAX_BUFFER];
        snprintf(dbg, sizeof(dbg), "Message type=%d user=%s", msg.msg_type, msg.username);
        log_message("SS", dbg);
    }

    memset(&response, 0, sizeof(response));
    response.msg_type = MSG_RESPONSE;
    response.error_code = ERR_SUCCESS;

    switch (msg.msg_type)
    {
    case MSG_CREATE_FILE:
    {
        char *filename = msg.data;
        char filepath[MAX_PATH];
        snprintf(filepath, sizeof(filepath), "%s/%s", storage_path, filename);

        FILE *fp = fopen(filepath, "w");
        if (!fp)
        {
            response.error_code = ERR_INTERNAL_ERROR;
            snprintf(response.data, MAX_BUFFER, "Failed to create file");
        }
        else
        {
            fclose(fp);
            pthread_mutex_lock(&files_mutex);
            strncpy(files[num_files].filename, filename, MAX_FILENAME - 1);
            files[num_files].content[0] = '\0';
            files[num_files].backup[0] = '\0';
            files[num_files].last_modified = time(NULL);
            files[num_files].created_time = time(NULL);
            files[num_files].last_access = time(NULL);
            files[num_files].is_modified = 0;
            files[num_files].word_count = 0;
            files[num_files].char_count = 0;
            files[num_files].num_sentences = 0;
            files[num_files].locks_capacity = 0;
            files[num_files].num_users = 0;
            files[num_files].owner[0] = '\0';
            files[num_files].last_reader[0] = '\0';
            pthread_mutex_init(&files[num_files].lock, NULL);
            files[num_files].sentence_locks = NULL;
            // Initialize sentence locks with initial capacity
            if (ensure_lock_capacity(&files[num_files], 16) != 0)
            {
                // If we fail to init locks, roll back creation in memory (keep file on disk)
                files[num_files].sentence_locks = NULL;
                files[num_files].locks_capacity = 0;
                pthread_mutex_unlock(&files_mutex);
                response.error_code = ERR_INTERNAL_ERROR;
                snprintf(response.data, MAX_BUFFER, "Failed to initialize locks");
                break;
            }
            // Initialize undo state
            files[num_files].last_undo.original_words = NULL;
            files[num_files].last_undo.word_indices = NULL;
            files[num_files].last_undo.original_sentence = NULL;
            files[num_files].last_undo.num_changes = 0;
            num_files++;
            pthread_mutex_unlock(&files_mutex);
            snprintf(response.data, MAX_BUFFER, "File created successfully");
            log_message("SS", "File created");
        }
        break;
    }

    case MSG_DELETE_FILE:
    {
        char *filename = msg.data;
        char filepath[MAX_PATH];
        snprintf(filepath, sizeof(filepath), "%s/%s", storage_path, filename);

        if (unlink(filepath) < 0)
        {
            response.error_code = ERR_INTERNAL_ERROR;
            snprintf(response.data, MAX_BUFFER, "Failed to delete file");
        }
        else
        {
            pthread_mutex_lock(&files_mutex);
            for (int i = 0; i < num_files; i++)
            {
                if (strcmp(files[i].filename, filename) == 0)
                {
                    for (int j = i; j < num_files - 1; j++)
                    {
                        files[j] = files[j + 1];
                    }
                    num_files--;
                    break;
                }
            }
            pthread_mutex_unlock(&files_mutex);

            snprintf(response.data, MAX_BUFFER, "File deleted successfully");
            log_message("SS", "File deleted");
        }
        break;
    }

    case MSG_READ_FILE:
    {
        char *filename = msg.data;
        FileData *file = find_file(filename);

        if (!file)
        {
            response.error_code = ERR_FILE_NOT_FOUND;
            snprintf(response.data, MAX_BUFFER, "File not found");
        }
        else
        {
            pthread_mutex_lock(&file->lock);
            strncpy(response.data, file->content, MAX_BUFFER - 1);
            file->last_access = time(NULL);
            strncpy(file->last_reader, msg.username, MAX_USERNAME - 1);
            pthread_mutex_unlock(&file->lock);
            log_message("SS", "File read");
        }
        break;
    }

    case MSG_STREAM_FILE:
    {
        char *filename = msg.data;
        FileData *file = find_file(filename);

        if (!file)
        {
            response.error_code = ERR_FILE_NOT_FOUND;
            snprintf(response.data, MAX_BUFFER, "File not found");
            send_message(client_sock, &response);
        }
        else
        {
            pthread_mutex_lock(&file->lock);
            char *dup = strdup(file->content);
            pthread_mutex_unlock(&file->lock);
            if (!dup)
            {
                response.error_code = ERR_MEMORY_ERROR;
                snprintf(response.data, MAX_BUFFER, "Out of memory");
                send_message(client_sock, &response);
                break;
            }
            char *saveptr2 = NULL;
            char *tok = strtok_r(dup, " \t\n", &saveptr2);
            while (tok)
            {
                memset(&response, 0, sizeof(response));
                response.msg_type = MSG_RESPONSE;
                response.error_code = ERR_SUCCESS;
                strncpy(response.data, tok, MAX_BUFFER - 1);
                if (send_message(client_sock, &response) < 0)
                {
                    break;
                }
                usleep(100000); // 0.1 second delay
                tok = strtok_r(NULL, " \t\n", &saveptr2);
            }
            free(dup);
            // Send stop signal
            memset(&response, 0, sizeof(response));
            response.msg_type = MSG_RESPONSE;
            response.error_code = ERR_SUCCESS;
            strcpy(response.data, "STOP");
            send_message(client_sock, &response);

            log_message("SS", "File streamed");
            close(client_sock);
            return;
        }
        break;
    }

    case MSG_WRITE_FILE:
    {
        // Parse write command parameters safely
        char *saveptr = NULL;
        char *tmp_data = strdup(msg.data);
        if (!tmp_data)
        {
            handle_error(client_sock, &response, ERR_MEMORY_ERROR, "Out of memory");
            break;
        }

        char *filename = strtok_r(tmp_data, "|", &saveptr);
        char *sent_num_str = strtok_r(NULL, "|", &saveptr);
        char *updates = strtok_r(NULL, "|", &saveptr);

        if (!filename || !sent_num_str || !updates)
        {
            free(tmp_data);
            handle_error(client_sock, &response, ERR_INVALID_COMMAND, "Invalid write format: missing parameters");
            break;
        }

        char *endptr = NULL;
        long sent_long = strtol(sent_num_str, &endptr, 10);
        if (*sent_num_str == '\0' || *endptr != '\0' || sent_long < 0 || sent_long > INT_MAX)
        {
            free(tmp_data);
            handle_error(client_sock, &response, ERR_INVALID_COMMAND, "Invalid sentence number format");
            break;
        }
        int sent_num = (int)sent_long;

        // Log write attempt
        char log_buf[MAX_BUFFER];
        snprintf(log_buf, sizeof(log_buf), "Write request: file=%s, sentence=%d, user=%s", filename, sent_num, msg.username);
        log_message("SS", log_buf);

        FileData *file = find_file(filename);
        if (!file)
        {
            free(tmp_data);
            response.error_code = ERR_FILE_NOT_FOUND;
            snprintf(response.data, MAX_BUFFER, "File not found");
            break;
        }

        pthread_mutex_lock(&file->lock);

        // Acquire sentence lock with small retry
        int lock_retries = 0;
        int lock_result = ERR_SENTENCE_LOCKED_BY_USER;
        while (lock_retries < 3)
        {
            lock_result = lock_sentence(file, sent_num, msg.username);
            if (lock_result == ERR_SUCCESS)
                break;
            if (lock_result == ERR_INDEX_OUT_OF_RANGE)
            {
                pthread_mutex_unlock(&file->lock);
                free(tmp_data);
                response.error_code = lock_result;
                snprintf(response.data, MAX_BUFFER, "Sentence index out of range");
                goto WRITE_DONE;
            }
            usleep(100000);
            lock_retries++;
        }
        if (lock_result != ERR_SUCCESS)
        {
            pthread_mutex_unlock(&file->lock);
            free(tmp_data);
            response.error_code = lock_result;
            snprintf(response.data, MAX_BUFFER, "Sentence is currently locked by another user");
            break;
        }

        // Backup current content for UNDO
        strncpy(file->backup, file->content, sizeof(file->backup) - 1);
        file->backup[sizeof(file->backup) - 1] = '\0';

        // Find sentence boundaries to avoid large stack arrays
        const char *content = file->content;
        size_t content_len = strlen(content);
        int current_idx = 0;
        size_t sent_start = 0, sent_end = 0;
        int found = 0;
        for (size_t i = 0; i <= content_len; i++)
        {
            int is_end = (i == content_len) || is_sentence_delimiter(content[i]);
            if (is_end)
            {
                if (current_idx == sent_num)
                {
                    sent_end = (i < content_len) ? i + 1 : i; // include delimiter if present
                    found = 1;
                    break;
                }
                current_idx++;
                sent_start = (i < content_len) ? i + 1 : i;
                while (sent_start < content_len && (content[sent_start] == ' ' || content[sent_start] == '\t' || content[sent_start] == '\n'))
                {
                    sent_start++;
                    i = sent_start;
                }
            }
        }
        int num_sentences = current_idx + (found ? 0 : (sent_start < content_len ? 1 : 0));
        if (!found && sent_num > current_idx)
        {
            unlock_sentence(file, sent_num, msg.username);
            pthread_mutex_unlock(&file->lock);
            free(tmp_data);
            response.error_code = ERR_INDEX_OUT_OF_RANGE;
            snprintf(response.data, MAX_BUFFER, "Sentence index out of range");
            break;
        }
        size_t cur_len = (found && sent_end > sent_start) ? (sent_end - sent_start) : 0;
        char *current_sentence = calloc(cur_len + 1, 1);
        if (!current_sentence)
        {
            unlock_sentence(file, sent_num, msg.username);
            pthread_mutex_unlock(&file->lock);
            free(tmp_data);
            response.error_code = ERR_MEMORY_ERROR;
            snprintf(response.data, MAX_BUFFER, "Out of memory");
            break;
        }
        if (cur_len > 0)
            memcpy(current_sentence, content + sent_start, cur_len);

        // Tokenize current sentence into words (dynamic)
        int words_cap = 16, num_words = 0;
        char **words = malloc(words_cap * sizeof(char *));
        if (!words)
        {
            free(current_sentence);
            unlock_sentence(file, sent_num, msg.username);
            pthread_mutex_unlock(&file->lock);
            free(tmp_data);
            response.error_code = ERR_MEMORY_ERROR;
            snprintf(response.data, MAX_BUFFER, "Out of memory");
            break;
        }
        {
            char *dup = strdup(current_sentence);
            char *sp = NULL;
            char *w = dup ? strtok_r(dup, " ", &sp) : NULL;
            while (w)
            {
                if (num_words == words_cap)
                {
                    words_cap *= 2;
                    char **nw = realloc(words, words_cap * sizeof(char *));
                    if (!nw)
                        break;
                    words = nw;
                }
                words[num_words++] = strdup(w);
                w = strtok_r(NULL, " ", &sp);
            }
            if (dup)
                free(dup);
        }

        // Apply updates of the form "<word_idx> <content>" separated by ';'
        // Semantics per spec:
        // - word_idx is 0-based for "insert at beginning"; k > 0 means insert AFTER the k-th word (1-based)
        // - For empty sentences, accept k == 0 or k == 1 and treat both as beginning
        char *updates_dup = strdup(updates);
        if (!updates_dup)
        {
            unlock_sentence(file, sent_num, msg.username);
            for (int i = 0; i < num_words; i++)
                free(words[i]);
            free(words);
            pthread_mutex_unlock(&file->lock);
            free(tmp_data);
            free(current_sentence);
            response.error_code = ERR_MEMORY_ERROR;
            snprintf(response.data, MAX_BUFFER, "Out of memory");
            goto WRITE_DONE;
        }
        char *seg_save = NULL;
        char *seg = strtok_r(updates_dup, ";", &seg_save);
        while (seg)
        {
            // Trim leading spaces
            while (*seg == ' ' || *seg == '\t')
                seg++;
            if (*seg == '\0')
            {
                seg = strtok_r(NULL, ";", &seg_save);
                continue;
            }
            // Parse index
            char *p = seg;
            char *endnum = NULL;
            long k = strtol(p, &endnum, 10);
            if (p == endnum)
            {
                // No number parsed
                seg = strtok_r(NULL, ";", &seg_save);
                continue;
            }
            // Skip spaces before content
            while (endnum && (*endnum == ' ' || *endnum == '\t'))
                endnum++;
            const char *ins_content = endnum && *endnum ? endnum : "";

            // Determine insertion position
            int pos;
            if (num_words == 0)
            {
                if (k == 0 || k == 1)
                    pos = 0;
                else
                {
                    free(updates_dup);
                    unlock_sentence(file, sent_num, msg.username);
                    for (int i = 0; i < num_words; i++)
                        free(words[i]);
                    free(words);
                    pthread_mutex_unlock(&file->lock);
                    free(tmp_data);
                    free(current_sentence);
                    response.error_code = ERR_INDEX_OUT_OF_RANGE;
                    snprintf(response.data, MAX_BUFFER, "Word index out of range");
                    goto WRITE_DONE;
                }
            }
            else
            {
                if (k < 0)
                {
                    free(updates_dup);
                    unlock_sentence(file, sent_num, msg.username);
                    for (int i = 0; i < num_words; i++)
                        free(words[i]);
                    free(words);
                    pthread_mutex_unlock(&file->lock);
                    free(tmp_data);
                    free(current_sentence);
                    response.error_code = ERR_INDEX_OUT_OF_RANGE;
                    snprintf(response.data, MAX_BUFFER, "Word index out of range");
                    goto WRITE_DONE;
                }
                // k is 0-based for beginning, else 1-based for after-kth
                if (k == 0)
                    pos = 0;
                else
                    pos = (int)k; // insert before element at index 'pos'
                if (pos > num_words)
                {
                    free(updates_dup);
                    unlock_sentence(file, sent_num, msg.username);
                    for (int i = 0; i < num_words; i++)
                        free(words[i]);
                    free(words);
                    pthread_mutex_unlock(&file->lock);
                    free(tmp_data);
                    free(current_sentence);
                    response.error_code = ERR_INDEX_OUT_OF_RANGE;
                    snprintf(response.data, MAX_BUFFER, "Word index out of range");
                    goto WRITE_DONE;
                }
            }

            // Split ins_content into words by whitespace, preserving punctuation
            // Count words first
            int add_count = 0, add_cap = 8;
            char **add_words = malloc(add_cap * sizeof(char *));
            if (!add_words)
            {
                free(updates_dup);
                unlock_sentence(file, sent_num, msg.username);
                for (int i = 0; i < num_words; i++)
                    free(words[i]);
                free(words);
                pthread_mutex_unlock(&file->lock);
                free(tmp_data);
                free(current_sentence);
                response.error_code = ERR_MEMORY_ERROR;
                snprintf(response.data, MAX_BUFFER, "Out of memory");
                goto WRITE_DONE;
            }
            char *ins_dup = strdup(ins_content);
            char *wsp = NULL;
            char *tok = ins_dup ? strtok_r(ins_dup, " \t\n", &wsp) : NULL;
            while (tok)
            {
                if (add_count == add_cap)
                {
                    add_cap *= 2;
                    char **nw = realloc(add_words, add_cap * sizeof(char *));
                    if (!nw)
                        break;
                    add_words = nw;
                }
                add_words[add_count++] = strdup(tok);
                tok = strtok_r(NULL, " \t\n", &wsp);
            }
            if (ins_dup)
                free(ins_dup);

            if (add_count > 0)
            {
                // Ensure capacity in main words array
                if (num_words + add_count > words_cap)
                {
                    while (num_words + add_count > words_cap)
                        words_cap *= 2;
                    char **nw = realloc(words, words_cap * sizeof(char *));
                    if (!nw)
                    {
                        for (int i = 0; i < add_count; i++)
                            free(add_words[i]);
                        free(add_words);
                        free(updates_dup);
                        unlock_sentence(file, sent_num, msg.username);
                        for (int i = 0; i < num_words; i++)
                            free(words[i]);
                        free(words);
                        pthread_mutex_unlock(&file->lock);
                        free(tmp_data);
                        free(current_sentence);
                        response.error_code = ERR_MEMORY_ERROR;
                        snprintf(response.data, MAX_BUFFER, "Out of memory");
                        goto WRITE_DONE;
                    }
                    words = nw;
                }
                // Shift existing words to the right
                memmove(words + pos + add_count, words + pos, (num_words - pos) * sizeof(char *));
                // Copy in new words
                for (int i = 0; i < add_count; i++)
                {
                    words[pos + i] = add_words[i];
                }
                num_words += add_count;
            }
            free(add_words);

            seg = strtok_r(NULL, ";", &seg_save);
        }
        free(updates_dup);

        // Reconstruct the modified sentence
        // Rebuild the modified sentence
        size_t new_len = 0;
        for (int i = 0; i < num_words; i++)
            new_len += strlen(words[i]) + 1;
        char *rebuilt = calloc(new_len + 1, 1);
        if (!rebuilt)
        {
            for (int i = 0; i < num_words; i++)
                free(words[i]);
            free(words);
            free(current_sentence);
            unlock_sentence(file, sent_num, msg.username);
            pthread_mutex_unlock(&file->lock);
            free(tmp_data);
            response.error_code = ERR_MEMORY_ERROR;
            snprintf(response.data, MAX_BUFFER, "Out of memory");
            break;
        }
        for (int i = 0; i < num_words; i++)
        {
            if (i)
                strcat(rebuilt, " ");
            strcat(rebuilt, words[i]);
        }

        // Rebuild full file content using prefix + modified + suffix
        char *new_content = NULL;
        size_t prefix_len = sent_start;
        size_t suffix_start = found ? sent_end : content_len;
        size_t suffix_len = (suffix_start < content_len) ? (content_len - suffix_start) : 0;
        // If appending a new sentence (not replacing any existing chars), ensure a space between previous and new content
        int need_space = 0;
        {
            int appending_at_end = (sent_start == content_len) && (suffix_start == content_len);
            if ((appending_at_end || !found) && prefix_len > 0)
            {
                char last = content[prefix_len - 1];
                if (!(last == ' ' || last == '\n' || last == '\t'))
                    need_space = 1;
            }
        }
        size_t total_len2 = prefix_len + need_space + strlen(rebuilt) + suffix_len + 2;
        new_content = malloc(total_len2);
        if (!new_content)
        {
            for (int i = 0; i < num_words; i++)
                free(words[i]);
            free(words);
            free(current_sentence);
            free(rebuilt);
            unlock_sentence(file, sent_num, msg.username);
            pthread_mutex_unlock(&file->lock);
            free(tmp_data);
            response.error_code = ERR_MEMORY_ERROR;
            snprintf(response.data, MAX_BUFFER, "Out of memory");
            break;
        }
        memcpy(new_content, content, prefix_len);
        size_t cursor = prefix_len;
        if (need_space)
            new_content[cursor++] = ' ';
        strcpy(new_content + cursor, rebuilt);
        if (suffix_len > 0)
            memcpy(new_content + cursor + strlen(rebuilt), content + suffix_start, suffix_len);
        new_content[cursor + strlen(rebuilt) + suffix_len] = '\0';
        strncpy(file->content, new_content, sizeof(file->content) - 1);
        file->content[sizeof(file->content) - 1] = '\0';
        free(new_content);
        for (int i = 0; i < num_words; i++)
            free(words[i]);
        free(words);
        free(current_sentence);
        free(rebuilt);

        // Ensure sentence locks capacity can accommodate new sentence count
        // Update sentence count estimate
        int total_sentences = 0;
        for (size_t i = 0; file->content[i]; i++)
            if (is_sentence_delimiter(file->content[i]))
                total_sentences++;
        if (total_sentences > file->locks_capacity)
        {
            if (ensure_lock_capacity(file, total_sentences) != 0)
            {
                unlock_sentence(file, sent_num, msg.username);
                pthread_mutex_unlock(&file->lock);
                free(tmp_data);
                response.error_code = ERR_MEMORY_ERROR;
                snprintf(response.data, MAX_BUFFER, "Failed to resize locks");
                break;
            }
        }

        // Update tracked sentence count after modification
        file->num_sentences = total_sentences;

        // Update metadata
        count_words_and_chars(file->content, &file->word_count, &file->char_count);
        file->last_modified = time(NULL);
        file->is_modified = 1;
        strncpy(file->last_modifier, msg.username, MAX_USERNAME - 1);

        // Persist changes
        if (save_file(file) != 0)
        {
            unlock_sentence(file, sent_num, msg.username);
            pthread_mutex_unlock(&file->lock);
            free(tmp_data);
            response.error_code = ERR_IO_ERROR;
            snprintf(response.data, MAX_BUFFER, "Failed to persist changes");
            break;
        }

        // Release locks and finish
        unlock_sentence(file, sent_num, msg.username);
        pthread_mutex_unlock(&file->lock);
        free(tmp_data);

        snprintf(response.data, MAX_BUFFER, "Write successful");
        log_message("SS", "File written");
        // Reset undo buffers for a fresh next operation (optional per spec)
        // Note: If you want multi-level undo, remove this reset and manage a stack instead
        // reset_undo(file);
        break;

    WRITE_DONE:
        // In case of early goto due to validation error
        break;
    }

    case MSG_UNDO:
    {
        char *filename = msg.data;
        FileData *file = find_file(filename);

        if (!file)
        {
            response.error_code = ERR_FILE_NOT_FOUND;
            snprintf(response.data, MAX_BUFFER, "File not found");
        }
        else
        {
            pthread_mutex_lock(&file->lock);
            strcpy(file->content, file->backup);

            // Protect against double-undo by checking if any changes
            if (file->is_modified)
            {
                // Update word and character counts after undo
                count_words_and_chars(file->content, &file->word_count, &file->char_count);

                file->last_modified = time(NULL);
                file->is_modified = 0;
                strncpy(file->last_modifier, msg.username, MAX_USERNAME - 1);

                // Try to save file with retry logic
                int save_retries = 0;
                const int max_save_retries = 3;
                while (save_retries < max_save_retries)
                {
                    if (save_file(file) == 0)
                        break; // Success
                    save_retries++;
                    usleep(100000); // Wait 100ms between retries
                }

                if (save_retries == max_save_retries)
                {
                    response.error_code = ERR_INTERNAL_ERROR;
                    snprintf(response.data, MAX_BUFFER, "Failed to save file after undo");
                }
            }
            else
            {
                response.error_code = ERR_INVALID_COMMAND;
                snprintf(response.data, MAX_BUFFER, "No changes to undo");
            }
            pthread_mutex_unlock(&file->lock);

            if (response.error_code == ERR_SUCCESS)
            {
                snprintf(response.data, MAX_BUFFER, "Undo successful");
                log_message("SS", "Undo performed");
            }
        }
        break;
    }

    case MSG_SS_INFO:
    {
        // Provide metadata to name server on request (words, chars, size, times)
        char *filename = msg.data;
        FileData *file = find_file(filename);
        if (!file)
        {
            response.error_code = ERR_FILE_NOT_FOUND;
            snprintf(response.data, MAX_BUFFER, "File not found");
        }
        else
        {
            // Build a small metadata payload for this single file
            pthread_mutex_lock(&file->lock);
            char payload[MAX_BUFFER];
            int off = 0;
            int n = snprintf(payload + off, sizeof(payload) - off, "%s\n", file->filename);
            if (n > 0)
                off += n;
            n = snprintf(payload + off, sizeof(payload) - off, "%s\n", file->owner[0] ? file->owner : "-");
            if (n > 0)
                off += n;
            long size = (long)strlen(file->content);
            n = snprintf(payload + off, sizeof(payload) - off, "%ld %d %d %ld %ld %ld\n",
                         size, file->word_count, file->char_count,
                         (long)file->last_access, (long)file->last_modified, (long)file->created_time);
            if (n > 0)
                off += n;
            n = snprintf(payload + off, sizeof(payload) - off, "%d\n", file->num_users);
            if (n > 0)
                off += n;
            for (int u = 0; u < file->num_users && off < (int)sizeof(payload) - 2; u++)
            {
                n = snprintf(payload + off, sizeof(payload) - off, "%s %d\n",
                             file->users[u].username, file->users[u].access_type);
                if (n < 0)
                    break;
                off += n;
            }
            pthread_mutex_unlock(&file->lock);

            strncpy(response.data, payload, MAX_BUFFER - 1);
            response.error_code = ERR_SUCCESS;
        }
        break;
    }

    case MSG_SS_RESCAN:
    {
        // Re-scan storage directory and return current file list in same format as initial LIST
        int cnt = rescan_storage();
        if (cnt < 0)
        {
            response.error_code = ERR_INTERNAL_ERROR;
            snprintf(response.data, MAX_BUFFER, "Rescan failed");
        }
        else
        {
            char payload[MAX_BUFFER];
            int off = snprintf(payload, sizeof(payload), "LIST %d\n", cnt);
            pthread_mutex_lock(&files_mutex);
            for (int i = 0; i < num_files && off < (int)sizeof(payload) - 2; i++)
            {
                int n = snprintf(payload + off, sizeof(payload) - off, "%s\n", files[i].filename);
                if (n < 0)
                    break;
                off += n;
            }
            pthread_mutex_unlock(&files_mutex);
            strncpy(response.data, payload, MAX_BUFFER - 1);
            response.error_code = ERR_SUCCESS;
        }
        break;
    }

    case MSG_EXEC_FILE:
    {
        char *filename = msg.data;
        FileData *file = find_file(filename);

        if (!file)
        {
            response.error_code = ERR_FILE_NOT_FOUND;
            snprintf(response.data, MAX_BUFFER, "File not found");
        }
        else
        {
            pthread_mutex_lock(&file->lock);
            strncpy(response.data, file->content, MAX_BUFFER - 1);
            pthread_mutex_unlock(&file->lock);
        }
        break;
    }

    default:
        response.error_code = ERR_INVALID_COMMAND;
        snprintf(response.data, MAX_BUFFER, "Invalid command");
        break;
    }

    send_message(client_sock, &response);
    close(client_sock);
    return;
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

// Utility function to check file integrity
int check_file_integrity(const char *filepath)
{
    FILE *fp = fopen(filepath, "r");
    if (!fp)
    {
        log_error("SS", "check_integrity", ERR_INTERNAL_ERROR, strerror(errno));
        return -1;
    }

    char buf[4096];
    size_t total = 0;
    size_t bytes;

    while ((bytes = fread(buf, 1, sizeof(buf), fp)) > 0)
    {
        total += bytes;

        // Check for read errors
        if (ferror(fp))
        {
            log_error("SS", "check_integrity", ERR_INTERNAL_ERROR, "Read error");
            fclose(fp);
            return -1;
        }
    }

    fclose(fp);
    return 0;
}

// Recovery function for failed operations
int recover_file_operation(const char *recovery_path)
{
    FILE *fp = fopen(recovery_path, "r");
    if (!fp)
        return -1;

    char filepath[MAX_PATH];
    char temp_path[MAX_PATH];
    char backup_path[MAX_PATH];
    char timestamp[20];

    if (fscanf(fp, "%s\n%s\n%s\n%s\n", filepath, temp_path, backup_path, timestamp) != 4)
    {
        fclose(fp);
        return -1;
    }
    fclose(fp);

    // Check what files exist and try to recover
    if (access(filepath, F_OK) == 0)
    {
        // Main file exists - check if it's valid
        if (check_file_integrity(filepath) == 0)
        {
            // File is good, clean up recovery files
            unlink(temp_path);
            unlink(backup_path);
            unlink(recovery_path);
            return 0;
        }
    }

    // Try temp file next
    if (access(temp_path, F_OK) == 0)
    {
        if (check_file_integrity(temp_path) == 0)
        {
            rename(temp_path, filepath);
            unlink(backup_path);
            unlink(recovery_path);
            return 0;
        }
    }

    // Finally try backup
    if (access(backup_path, F_OK) == 0)
    {
        if (check_file_integrity(backup_path) == 0)
        {
            rename(backup_path, filepath);
            unlink(temp_path);
            unlink(recovery_path);
            return 0;
        }
    }

    return -1;
}

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