#include "../common.h"
#include "nameserver.h"
#include <sys/time.h>
#include <signal.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <netinet/tcp.h>
#include <unistd.h>

// Find file by name (non-blocking: avoid deadlocks by using trylock)
FileRecord *find_file(const char *filename)
{
    // First check cache
    FileRecord *cached = cache_get(filename);
    if (cached)
    {
        pthread_mutex_lock(&file_access_mutex);
        cached->metadata.accessed_time = time(NULL);
        pthread_mutex_unlock(&file_access_mutex);
        return cached;
    }

    // Try to acquire file mutex without blocking to avoid potential deadlocks
    if (pthread_mutex_trylock(&file_mutex) != 0)
    {
        return NULL; // Busy; caller can retry or treat as not found
    }

    for (int i = 0; i < num_files; i++)
    {
        if (strcmp(files[i].metadata.filename, filename) == 0)
        {
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
int check_access(FileRecord *file, const char *username, int required_access)
{
    if (strcmp(file->metadata.owner, username) == 0)
    {
        return 1; // Owner has all access
    }

    for (int i = 0; i < file->metadata.num_users; i++)
    {
        if (strcmp(file->metadata.users[i].username, username) == 0)
        {
            if (required_access == ACCESS_READ)
            {
                return (file->metadata.users[i].access_type >= ACCESS_READ);
            }
            else if (required_access == ACCESS_WRITE)
            {
                return (file->metadata.users[i].access_type >= ACCESS_WRITE);
            }
        }
    }
    return 0;
}
