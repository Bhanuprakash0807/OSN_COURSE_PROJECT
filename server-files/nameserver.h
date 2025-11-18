#ifndef NAMESERVER_H
#define NAMESERVER_H

#include "../common.h"

// Trie node used by the nameserver for filename -> SS lookup
typedef struct TrieNode
{
    struct TrieNode *children[256];
    int ss_index;
    int is_end;
} TrieNode;

// FileRecord stores persistent metadata plus SS index
typedef struct
{
    FileMetadata metadata;
    int ss_index;
} FileRecord;

typedef struct
{
    char key[MAX_FILENAME];
    FileRecord *value;
} CacheEntry;

// Global state exported by nameserver.c
extern StorageServerInfo storage_servers[MAX_SS];
extern int num_ss;
extern pthread_mutex_t ss_mutex;
extern pthread_cond_t ss_cond;

extern ClientInfo clients[MAX_CLIENTS];
extern int num_clients;
extern pthread_mutex_t client_mutex;
extern pthread_cond_t client_cond;

extern char known_users[MAX_CLIENTS][MAX_USERNAME];
extern int num_known_users;
extern pthread_mutex_t users_mutex;

extern FileRecord files[MAX_FILES];
extern int num_files;
extern pthread_mutex_t file_mutex;
extern pthread_mutex_t file_access_mutex;

extern TrieNode *file_trie_root;
extern pthread_mutex_t trie_mutex;

extern CacheEntry cache[100];
extern int cache_size;
extern pthread_mutex_t cache_mutex;
extern time_t cache_last_cleanup;

extern int nm_port;

// Nameserver public functions
int save_metadata(void);
int load_metadata(void);
void load_users(void);
void save_users(void);

// Trie / cache helpers
TrieNode *create_trie_node(void);
void trie_insert(TrieNode *root, const char *key, int ss_idx);
int trie_search(TrieNode *root, const char *key);
void trie_delete(TrieNode *root, const char *key);

void cache_add(const char *filename, FileRecord *record);
FileRecord *cache_get(const char *filename);
void cache_clear(void);

FileRecord *find_file(const char *filename);
int check_access(FileRecord *file, const char *username, int required_access);

// SS helpers
int fetch_stats_from_ss(const char *filename, int ss_idx, FileMetadata *out, char *last_reader_out);
int ss_simple_request(int ss_idx, int msg_type, const char *filename, Message *out_resp);

// Utility
char *format_time(time_t t);
void *handle_client(void *arg);
#endif // NAMESERVER_H
