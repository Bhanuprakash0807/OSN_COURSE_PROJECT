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

// Reset undo info to safe defaults
static void reset_undo(FileData *file)
{
    if (!file)
        return;
    // Free any allocated memory first
    if (file->last_undo.original_words)
    {
        for (int i = 0; i < file->last_undo.num_changes; i++)
        {
            free(file->last_undo.original_words[i]);
        }
        free(file->last_undo.original_words);
        file->last_undo.original_words = NULL;
    }
    if (file->last_undo.word_indices)
    {
        free(file->last_undo.word_indices);
        file->last_undo.word_indices = NULL;
    }
    if (file->last_undo.original_sentence)
    {
        free(file->last_undo.original_sentence);
        file->last_undo.original_sentence = NULL;
    }
    file->last_undo.num_changes = 0;
}
