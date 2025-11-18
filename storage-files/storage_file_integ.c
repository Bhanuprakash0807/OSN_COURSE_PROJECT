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

// Utility function to check file integrity
int check_file_integrity(const char *filepath)
{
    FILE *fp = fopen(filepath, "r");
    if (!fp)
    {
        log_error("SS", "check_integrity", ERR_INTERNAL_ERROR, strerror(errno));
        return -1;
    }

    char buf[4096];
    size_t total = 0;
    size_t bytes;

    while ((bytes = fread(buf, 1, sizeof(buf), fp)) > 0)
    {
        total += bytes;

        // Check for read errors
        if (ferror(fp))
        {
            log_error("SS", "check_integrity", ERR_INTERNAL_ERROR, "Read error");
            fclose(fp);
            return -1;
        }
    }

    fclose(fp);
    return 0;
}

// Recovery function for failed operations
int recover_file_operation(const char *recovery_path)
{
    FILE *fp = fopen(recovery_path, "r");
    if (!fp)
        return -1;

    char filepath[MAX_PATH];
    char temp_path[MAX_PATH];
    char backup_path[MAX_PATH];
    char timestamp[20];

    if (fscanf(fp, "%s\n%s\n%s\n%s\n", filepath, temp_path, backup_path, timestamp) != 4)
    {
        fclose(fp);
        return -1;
    }
    fclose(fp);

    // Check what files exist and try to recover
    if (access(filepath, F_OK) == 0)
    {
        // Main file exists - check if it's valid
        if (check_file_integrity(filepath) == 0)
        {
            // File is good, clean up recovery files
            unlink(temp_path);
            unlink(backup_path);
            unlink(recovery_path);
            return 0;
        }
    }

    // Try temp file next
    if (access(temp_path, F_OK) == 0)
    {
        if (check_file_integrity(temp_path) == 0)
        {
            rename(temp_path, filepath);
            unlink(backup_path);
            unlink(recovery_path);
            return 0;
        }
    }

    // Finally try backup
    if (access(backup_path, F_OK) == 0)
    {
        if (check_file_integrity(backup_path) == 0)
        {
            rename(backup_path, filepath);
            unlink(temp_path);
            unlink(recovery_path);
            return 0;
        }
    }

    return -1;
}
