#include "storageserver.h"
#include "../common.h"
#include "../common.h"
// count_words_and_chars is implemented in storage_content.c
extern void count_words_and_chars(const char *content, int *word_count, int *char_count);
#include <sys/stat.h>

// Write a storage-server local metadata file to storage_path/metadata.dat
// Format per-file (similar to what NM accepts in LIST payload):
// <filename>\n
// <owner or ->\n
// <size> <words> <chars> <accessed> <modified> <created>\n
// <num_users>\n
// <user> <access>\n ...

int save_ss_metadata(void)
{
    char tmpfile[MAX_PATH];
    char outfile[MAX_PATH];
    snprintf(outfile, sizeof(outfile), "%s/metadata.dat", storage_path);
    snprintf(tmpfile, sizeof(tmpfile), "%s/metadata.dat.tmp", storage_path);

    FILE *fp = fopen(tmpfile, "w");
    if (!fp)
        return -1;

    pthread_mutex_lock(&files_mutex);
    // write count first
    fprintf(fp, "%d\n", num_files);
    for (int i = 0; i < num_files; i++)
    {
        FileData *f = &files[i];
        // ensure counts and times are up-to-date
        // recompute word/char counts from content
        count_words_and_chars(f->content, &f->word_count, &f->char_count);
        if (f->created_time == 0)
            f->created_time = time(NULL);
        if (f->last_modified == 0)
            f->last_modified = time(NULL);
        if (f->last_access == 0)
            f->last_access = time(NULL);

        fprintf(fp, "%s\n", f->filename);
        fprintf(fp, "%s\n", f->owner[0] ? f->owner : "-");
        fprintf(fp, "%ld %d %d %ld %ld %ld\n",
                (long)strlen(f->content), f->word_count, f->char_count,
                (long)f->last_access, (long)f->last_modified, (long)f->created_time);
        fprintf(fp, "%d\n", f->num_users);
        for (int u = 0; u < f->num_users; u++)
        {
            fprintf(fp, "%s %d\n", f->users[u].username, f->users[u].access_type);
        }
    }
    pthread_mutex_unlock(&files_mutex);

    fflush(fp);
    fsync(fileno(fp));
    fclose(fp);

    if (rename(tmpfile, outfile) != 0)
    {
        unlink(tmpfile);
        return -1;
    }
    return 0;
}
