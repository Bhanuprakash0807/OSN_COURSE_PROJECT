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

// count_words_and_chars is provided by storage_content.c
extern void count_words_and_chars(const char *content, int *word_count, int *char_count);

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

    // Update word/char counts and timestamps from filesystem
    count_words_and_chars(files[num_files].content, &files[num_files].word_count, &files[num_files].char_count);
    // Try to stat file for timestamps
    snprintf(filepath, sizeof(filepath), "%s/%s", storage_path, filename);
    struct stat st;
    if (stat(filepath, &st) == 0)
    {
        files[num_files].last_modified = (time_t)st.st_mtime;
        files[num_files].created_time = (time_t)st.st_ctime;
    }
    else
    {
        files[num_files].last_modified = time(NULL);
        files[num_files].created_time = time(NULL);
    }
    files[num_files].last_access = time(NULL);

    num_files++;
    pthread_mutex_unlock(&files_mutex);

    fclose(fp);

    // Persist storage-server local metadata file
    save_ss_metadata();
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
    // After successful save, update ss metadata file
    save_ss_metadata();
    return 0;
}
