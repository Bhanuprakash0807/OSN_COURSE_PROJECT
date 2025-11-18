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
