#include "common.h"

void log_message(const char *component, const char *message) {
    char *timestamp = get_timestamp();
    printf("[%s] [%s] %s\n", timestamp, component, message);
    fflush(stdout);
    
    // Also log to file
    char logfile[MAX_PATH];
    snprintf(logfile, sizeof(logfile), "%s.log", component);
    FILE *fp = fopen(logfile, "a");
    if (fp) {
        fprintf(fp, "[%s] %s\n", timestamp, message);
        fclose(fp);
    }
    free(timestamp);
}

void log_error(const char *component, const char *operation, int error_code, const char *details) {
    char log_msg[MAX_BUFFER];
    snprintf(log_msg, sizeof(log_msg), "Error in %s: %s (code=%d) - %s", 
             operation, get_error_string(error_code), error_code, details);
    log_message(component, log_msg);
}

void log_request(const char *component, const char *ip, int port, const char *operation) {
    char log_msg[MAX_BUFFER];
    snprintf(log_msg, sizeof(log_msg), "Request from %s:%d - %s", ip, port, operation);
    log_message(component, log_msg);
}

const char* get_error_string(int error_code) {
    switch (error_code) {
        case ERR_SUCCESS: return "Success";
        case ERR_FILE_NOT_FOUND: return "File not found";
        case ERR_PERMISSION_DENIED: return "Permission denied";
        case ERR_FILE_EXISTS: return "File already exists";
        case ERR_INVALID_PATH: return "Invalid path";
        case ERR_SS_UNAVAILABLE: return "Storage server unavailable";
        case ERR_SENTENCE_LOCKED: return "Sentence is locked";
        case ERR_INDEX_OUT_OF_RANGE: return "Index out of range";
        case ERR_INVALID_COMMAND: return "Invalid command";
        case ERR_CONNECTION_FAILED: return "Connection failed";
        case ERR_INTERNAL_ERROR: return "Internal error";
        case ERR_SENTENCE_LOCKED_BY_USER: return "Sentence locked by user";
        case ERR_INVALID_SENTENCE_BOUNDARY: return "Invalid sentence boundary";
        case ERR_CONCURRENT_MODIFICATION: return "Concurrent modification";
        case ERR_INVALID_FILENAME: return "Invalid filename";
        case ERR_TOO_MANY_FILES: return "Too many files";
        case ERR_MEMORY_ERROR: return "Memory error";
        case ERR_IO_ERROR: return "I/O error";
        case ERR_NETWORK_ERROR: return "Network error";
        case ERR_SERVER_DISCONNECTED: return "Server disconnected";
        case ERR_FILE_CORRUPTED: return "File corrupted";
        case ERR_BACKUP_FAILED: return "Backup failed";
        default: return "Unknown error";
    }
}

char* get_timestamp() {
    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    char *timestamp = malloc(64);
    if (!timestamp) {
        static char fallback[64];
        strftime(fallback, sizeof(fallback), "%Y-%m-%d %H:%M:%S", t);
        return fallback;
    }
    strftime(timestamp, 64, "%Y-%m-%d %H:%M:%S", t);
    return timestamp;
}

int validate_filename(const char *filename, char *error_msg) {
    if (!filename || !*filename) {
        strcpy(error_msg, "Empty filename");
        return 0;
    }
    
    if (strlen(filename) >= MAX_FILENAME) {
        strcpy(error_msg, "Filename too long");
        return 0;
    }
    
    const char *p = filename;
    while (*p) {
        if (*p == '/' || *p == '\\' || *p == '?' || *p == '%' || *p == '*' ||
            *p == ':' || *p == '|' || *p == '"' || *p == '<' || *p == '>' || *p == '.' ||
            *p <= ' ') {
            strcpy(error_msg, "Invalid characters in filename");
            return 0;
        }
        p++;
    }
    return 1;
}

int check_file_access(const char *filename, const char *username, int access_type, char *error_msg) {
    FileMetadata metadata;
    char path[MAX_PATH];
    snprintf(path, sizeof(path), "%s/%s", TEMP_DIR, filename);
    
    FILE *fp = fopen(path, "r");
    if (!fp) {
        strcpy(error_msg, "File not found or inaccessible");
        return 0;
    }
    
    size_t bytes_read = fread(&metadata, 1, sizeof(metadata), fp);
    fclose(fp);
    
    if (bytes_read != sizeof(metadata)) {
        strcpy(error_msg, "Error reading file metadata");
        return 0;
    }
    
    if (strcmp(metadata.owner, username) == 0) {
        return 1; // Owner has all access
    }
    
    for (int i = 0; i < metadata.num_users; i++) {
        if (strcmp(metadata.users[i].username, username) == 0) {
            if (access_type == ACCESS_READ) {
                return 1; // All users with any access can read
            }
            return (metadata.users[i].access_type == ACCESS_WRITE);
        }
    }
    
    strcpy(error_msg, "Access denied");
    return 0;
}

int validate_sentence_boundary(const char *sentence, char *error_msg) {
    if (!sentence || !*sentence) {
        strcpy(error_msg, "Empty sentence");
        return 0;
    }
    
    const char *p = sentence;
    int has_period = 0;
    
    while (*p) {
        if (*p == '.' || *p == '!' || *p == '?') {
            has_period = 1;
            // Check for multiple consecutive delimiters
            if (p[1] == '.' || p[1] == '!' || p[1] == '?') {
                strcpy(error_msg, "Invalid sentence delimiter sequence");
                return 0;
            }
        }
        p++;
    }
    
    if (!has_period) {
        strcpy(error_msg, "Sentence must end with proper delimiter");
        return 0;
    }
    
    return 1;
}

int send_message(int sockfd, Message *msg) {
    size_t total_sent = 0;
    size_t bytes_left = sizeof(Message);
    ssize_t n;

    while (total_sent < sizeof(Message)) {
        n = send(sockfd, (char *)msg + total_sent, bytes_left, 0);
        if (n <= 0) {
            if (n < 0) {
                if (errno == EINTR) continue; // retry on interrupt
                // Avoid noisy logs for EWOULDBLOCK/EAGAIN; let caller handle
                if (errno != EWOULDBLOCK && errno != EAGAIN) perror("send");
            }
            return -1;
        }
        total_sent += (size_t)n;
        bytes_left -= (size_t)n;
    }
    return 0;
}

int receive_message(int sockfd, Message *msg) {
    // Ensure deterministic contents on error paths for callers that don't check return values
    memset(msg, 0, sizeof(Message));
    msg->msg_type = MSG_ERROR;
    msg->error_code = ERR_NETWORK_ERROR;

    size_t total_received = 0;
    size_t bytes_left = sizeof(Message);
    ssize_t n;

    while (total_received < sizeof(Message)) {
        n = recv(sockfd, (char *)msg + total_received, bytes_left, 0);
        if (n <= 0) {
            if (n < 0) {
                if (errno == EINTR) continue; // retry on interrupt
                // Suppress benign non-blocking/timeouts; caller will see ERR_NETWORK_ERROR
                if (errno != EWOULDBLOCK && errno != EAGAIN) perror("recv");
            }
            return -1;
        }
        total_received += (size_t)n;
        bytes_left -= (size_t)n;
    }
    return 0;
}