#ifndef STORAGESERVER_H
#define STORAGESERVER_H

#include "../common.h"

#define LOCK_TIMEOUT 300

typedef struct
{
    int locked;
    char owner[MAX_USERNAME];
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    time_t lock_time;
} SentenceLock;

typedef struct
{
    char **original_words;
    int *word_indices;
    int num_changes;
    char *original_sentence;
} UndoInfo;

typedef struct
{
    char filename[MAX_FILENAME];
    char content[MAX_BUFFER * 10];
    char backup[MAX_BUFFER * 10];
    char last_modifier[MAX_USERNAME];
    time_t last_modified;
    SentenceLock *sentence_locks;
    int locks_capacity;
    int num_sentences;
    pthread_mutex_t lock;
    int word_count;
    int char_count;
    int is_modified;
    time_t last_access;
    time_t created_time;
    char last_reader[MAX_USERNAME];
    char owner[MAX_USERNAME];
    UserAccess users[MAX_ACCESS_USERS];
    int num_users;
    UndoInfo last_undo;
} FileData;

// Storage server globals
extern FileData files[MAX_FILES];
extern int num_files;
extern pthread_mutex_t files_mutex;
extern char storage_path[MAX_PATH];
extern int nm_port;
extern int client_port;
extern char nm_ip[INET_ADDRSTRLEN];

// Public storage server helpers
int rescan_storage(void);
int save_file(FileData *file);
void load_file(const char *filename);
FileData *find_file(const char *filename);

#endif // STORAGESERVER_H
