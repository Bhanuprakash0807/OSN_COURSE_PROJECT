#include "../common.h"
#include "nameserver.h"
#include <sys/time.h>
#include <signal.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <netinet/tcp.h>
#include <unistd.h>

// Cache functions
void cleanup_cache_locked()
{
    // Assumes cache_mutex is held
    time_t now = time(NULL);

    // Only cleanup if it's been at least 5 minutes since last cleanup
    if (now - cache_last_cleanup < 300)
    {
        return;
    }

    // Remove entries older than 30 minutes
    int write_idx = 0;
    for (int read_idx = 0; read_idx < cache_size; read_idx++)
    {
        if (cache[read_idx].value && cache[read_idx].value->metadata.accessed_time > now - 1800)
        {
            if (write_idx != read_idx)
            {
                cache[write_idx] = cache[read_idx];
            }
            write_idx++;
        }
    }

    cache_size = write_idx;
    cache_last_cleanup = now;
}

void cache_add(const char *filename, FileRecord *record)
{
    pthread_mutex_lock(&cache_mutex);

    // Periodically cleanup old entries
    cleanup_cache_locked();

    if (cache_size < 100)
    {
        strncpy(cache[cache_size].key, filename, MAX_FILENAME - 1);
        cache[cache_size].value = record;
        cache_size++;
    }
    else
    {
        // LRU-based replacement
        int oldest_idx = 0;
        time_t oldest_time = cache[0].value->metadata.accessed_time;

        for (int i = 1; i < 100; i++)
        {
            if (cache[i].value->metadata.accessed_time < oldest_time)
            {
                oldest_time = cache[i].value->metadata.accessed_time;
                oldest_idx = i;
            }
        }

        strncpy(cache[oldest_idx].key, filename, MAX_FILENAME - 1);
        cache[oldest_idx].value = record;
    }
    pthread_mutex_unlock(&cache_mutex);
}

FileRecord *cache_get(const char *filename)
{
    pthread_mutex_lock(&cache_mutex);
    for (int i = 0; i < cache_size; i++)
    {
        if (strcmp(cache[i].key, filename) == 0)
        {
            FileRecord *record = cache[i].value;
            pthread_mutex_unlock(&cache_mutex);
            return record;
        }
    }
    pthread_mutex_unlock(&cache_mutex);
    return NULL;
}

// Clear cache completely to avoid stale pointers after files[] mutations
void cache_clear()
{
    pthread_mutex_lock(&cache_mutex);
    cache_size = 0;
    pthread_mutex_unlock(&cache_mutex);
}
