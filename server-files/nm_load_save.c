#include "../common.h"
#include "nameserver.h"
#include <sys/time.h>
#include <signal.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <netinet/tcp.h>
#include <unistd.h>

void load_users()
{
    FILE *fp = fopen(USERS_FILE, "r");
    if (!fp)
        return;
    char line[MAX_USERNAME + 4];
    pthread_mutex_lock(&users_mutex);
    num_known_users = 0;
    while (fgets(line, sizeof(line), fp) && num_known_users < MAX_CLIENTS)
    {
        line[strcspn(line, "\n")] = '\0';
        if (line[0])
        {
            strncpy(known_users[num_known_users], line, MAX_USERNAME - 1);
            known_users[num_known_users][MAX_USERNAME - 1] = '\0';
            num_known_users++;
        }
    }
    pthread_mutex_unlock(&users_mutex);
    fclose(fp);
}

void save_users()
{
    pthread_mutex_lock(&users_mutex);
    char tmpfile[MAX_PATH];
    snprintf(tmpfile, sizeof(tmpfile), "%s.tmp", USERS_FILE);
    FILE *fp = fopen(tmpfile, "w");
    if (!fp)
    {
        pthread_mutex_unlock(&users_mutex);
        return;
    }
    for (int i = 0; i < num_known_users; i++)
    {
        fprintf(fp, "%s\n", known_users[i]);
    }
    fflush(fp);
    fsync(fileno(fp));
    fclose(fp);
    rename(tmpfile, USERS_FILE);
    pthread_mutex_unlock(&users_mutex);
}

FileRecord files[MAX_FILES];
int num_files = 0;
pthread_mutex_t file_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t file_access_mutex = PTHREAD_MUTEX_INITIALIZER; // For file access operations

TrieNode *file_trie_root;
pthread_mutex_t trie_mutex = PTHREAD_MUTEX_INITIALIZER;

CacheEntry cache[100];
int cache_size = 0;
pthread_mutex_t cache_mutex = PTHREAD_MUTEX_INITIALIZER;
time_t cache_last_cleanup = 0;

int nm_port;

// --- Metadata persistence (owner/ACL) ---
int save_metadata_locked();
int save_metadata();
int load_metadata();

// Forward declarations for functions used before their definitions
void trie_insert(TrieNode *root, const char *key, int ss_idx);
void cache_clear();

int save_metadata_locked()
{
    // Assumes file_mutex is held
    char tmpfile[MAX_PATH] = {0};
    snprintf(tmpfile, sizeof(tmpfile), "%s.tmp", METADATA_FILE);
    FILE *fp = fopen(tmpfile, "w");
    if (!fp)
        return -1;
    // Write count first
    fprintf(fp, "%d\n", num_files);
    for (int i = 0; i < num_files; i++)
    {
        FileRecord *fr = &files[i];
        // Do not persist metadata for the metadata file itself (avoid self-entry)
        if (strcmp(fr->metadata.filename, METADATA_FILE) == 0)
            continue;
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
        for (int j = 0; j < fr->metadata.num_users; j++)
        {
            fprintf(fp, "%s %d\n", fr->metadata.users[j].username, fr->metadata.users[j].access_type);
        }
    }
    fflush(fp);
    fsync(fileno(fp));
    fclose(fp);
    // Atomic rename
    if (rename(tmpfile, METADATA_FILE) != 0)
    {
        unlink(tmpfile);
        return -1;
    }
    return 0;
}

int save_metadata()
{
    pthread_mutex_lock(&file_mutex);
    int rc = save_metadata_locked();
    pthread_mutex_unlock(&file_mutex);
    return rc;
}

int load_metadata()
{
    FILE *fp = fopen(METADATA_FILE, "r");
    if (!fp)
        return -1; // Not fatal if missing
    int count = 0;
    if (fscanf(fp, "%d\n", &count) != 1 || count < 0 || count > MAX_FILES)
    {
        fclose(fp);
        return -1;
    }
    pthread_mutex_lock(&file_mutex);
    num_files = 0;
    for (int i = 0; i < count; i++)
    {
        FileRecord fr = {0};
        char line[MAX_BUFFER];
        if (!fgets(line, sizeof(line), fp))
            break; // filename
        line[strcspn(line, "\n")] = 0;
        strncpy(fr.metadata.filename, line, MAX_FILENAME - 1);
        if (!fgets(line, sizeof(line), fp))
            break; // owner
        line[strcspn(line, "\n")] = 0;
        strncpy(fr.metadata.owner, line, MAX_USERNAME - 1);
        long c = 0, m = 0, a = 0;
        int w = 0, ch = 0;
        if (!fgets(line, sizeof(line), fp))
            break;
        sscanf(line, "%ld %ld %ld %d %d", &c, &m, &a, &w, &ch);
        fr.metadata.created_time = (time_t)c;
        fr.metadata.modified_time = (time_t)m;
        fr.metadata.accessed_time = (time_t)a;
        fr.metadata.word_count = w;
        fr.metadata.char_count = ch;
        int u = 0;
        if (fscanf(fp, "%d\n", &u) != 1)
            break;
        fr.metadata.num_users = 0;
        for (int j = 0; j < u && j < MAX_ACCESS_USERS; j++)
        {
            if (!fgets(line, sizeof(line), fp))
                break;
            char uname[MAX_USERNAME];
            int at = 0;
            if (sscanf(line, "%63s %d", uname, &at) == 2)
            {
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
