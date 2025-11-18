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

// Ensure sentence_locks has at least `required` capacity; grow safely if needed
int ensure_lock_capacity(FileData *file, int required)
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
