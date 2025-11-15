#ifndef COMMON_H
#define COMMON_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <pthread.h>
#include <time.h>
#include <sys/stat.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>

#define MAX_BUFFER 8192
#define MAX_PATH 512
#define MAX_FILENAME 256
#define MAX_USERNAME 64
#define MAX_CLIENTS 100
#define MAX_SS 50
#define MAX_FILES 10000
#define MAX_SENTENCE_LEN 4096
#define MAX_WORD_LEN 256
#define MAX_ACCESS_USERS 100

// Error Codes
#define ERR_SUCCESS 0
#define ERR_FILE_NOT_FOUND 1
#define ERR_PERMISSION_DENIED 2
#define ERR_FILE_EXISTS 3
#define ERR_INVALID_PATH 4
#define ERR_SS_UNAVAILABLE 5
#define ERR_SENTENCE_LOCKED 6
#define ERR_INDEX_OUT_OF_RANGE 7
#define ERR_INVALID_COMMAND 8
#define ERR_CONNECTION_FAILED 9
#define ERR_INTERNAL_ERROR 10
#define ERR_SENTENCE_LOCKED_BY_USER 11
#define ERR_INVALID_SENTENCE_BOUNDARY 12
#define ERR_CONCURRENT_MODIFICATION 13
#define ERR_INVALID_FILENAME 14
#define ERR_TOO_MANY_FILES 15
#define ERR_MEMORY_ERROR 16
#define ERR_IO_ERROR 17
#define ERR_NETWORK_ERROR 18
#define ERR_SERVER_DISCONNECTED 19
#define ERR_FILE_CORRUPTED 20
#define ERR_BACKUP_FAILED 21

#define METADATA_FILE "metadata.dat"
#define TEMP_DIR "/tmp/docs_plus_plus"
#define MAX_SENTENCE_LENGTH 4096
#define MAX_WORD_LENGTH 256
#define MAX_COMMAND_LENGTH 1024

// Message Types
#define MSG_REGISTER_SS 100
#define MSG_REGISTER_CLIENT 101
#define MSG_CREATE_FILE 102
#define MSG_DELETE_FILE 103
#define MSG_READ_FILE 104
#define MSG_WRITE_FILE 105
#define MSG_VIEW_FILES 106
#define MSG_INFO_FILE 107
#define MSG_STREAM_FILE 108
#define MSG_LIST_USERS 109
#define MSG_ADD_ACCESS 110
#define MSG_REM_ACCESS 111
#define MSG_EXEC_FILE 112
#define MSG_UNDO 113
#define MSG_RESPONSE 200
#define MSG_ERROR 201
#define MSG_ACK 202
#define MSG_SS_INFO 203

// File Access Rights
#define ACCESS_NONE 0
#define ACCESS_READ 1
#define ACCESS_WRITE 2

typedef struct {
    char username[MAX_USERNAME];
    int access_type; // ACCESS_READ or ACCESS_WRITE
} UserAccess;

typedef struct {
    char filename[MAX_FILENAME];
    char owner[MAX_USERNAME];
    time_t created_time;
    time_t modified_time;
    time_t accessed_time;
    long size;
    UserAccess users[MAX_ACCESS_USERS];
    int num_users;
    int word_count;
    int char_count;
} FileMetadata;

typedef struct {
    int msg_type;
    char data[MAX_BUFFER];
    int error_code;
    char username[MAX_USERNAME];
} Message;

typedef struct {
    char ip[INET_ADDRSTRLEN];
    int nm_port;
    int client_port;
    char files[MAX_FILES][MAX_FILENAME];
    int num_files;
    int is_active;
} StorageServerInfo;

typedef struct {
    char ip[INET_ADDRSTRLEN];
    int port;
    char username[MAX_USERNAME];
    int is_active;
} ClientInfo;

// Utility functions
// Logging and error handling utilities
void log_message(const char *component, const char *message);
void log_error(const char *component, const char *operation, int error_code, const char *details);
void log_request(const char *component, const char *ip, int port, const char *operation);
char* get_timestamp();
const char* get_error_string(int error_code);
int send_message(int sockfd, Message *msg);
int receive_message(int sockfd, Message *msg);

// File validation functions
int validate_filename(const char *filename, char *error_msg);
int check_file_access(const char *filename, const char *username, int access_type, char *error_msg);
int validate_sentence_boundary(const char *sentence, char *error_msg);

#endif