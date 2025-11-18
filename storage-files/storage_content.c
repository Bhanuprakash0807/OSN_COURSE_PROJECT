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
// Check if character is a sentence delimiter
#define MAX_DELIMITERS 3
const char SENTENCE_DELIMITERS[MAX_DELIMITERS] = {'.', '!', '?'};

int is_sentence_delimiter(char c)
{
    for (int i = 0; i < MAX_DELIMITERS; i++)
    {
        if (c == SENTENCE_DELIMITERS[i])
            return 1;
    }
    return 0;
}

// Checks if a character sequence ends with a delimiter
int has_delimiter_ending(const char *str)
{
    int len = strlen(str);
    if (len == 0)
        return 0;

    // Check for delimiters at the end
    for (int i = len - 1; i >= 0; i--)
    {
        if (is_sentence_delimiter(str[i]))
            return 1;
        if (str[i] != ' ' && str[i] != '\t' && str[i] != '\n')
            break;
    }
    return 0;
}

// Parse file into sentences with improved handling
// Count total words and characters in content
void count_stats(const char *content, int *words, int *chars)
{
    *words = 0;
    *chars = 0;
    int in_word = 0;

    for (const char *p = content; *p; p++)
    {
        (*chars)++;
        if (*p == ' ' || *p == '\n' || *p == '\t' || is_sentence_delimiter(*p))
        {
            in_word = 0;
        }
        else if (!in_word)
        {
            in_word = 1;
            (*words)++;
        }
    }
}

int parse_sentences(const char *content, char sentences[][MAX_SENTENCE_LEN], int max_sentences)
{
    int sent_idx = 0;
    int char_idx = 0;

    for (int i = 0; content[i] && sent_idx < max_sentences; i++)
    {
        char curr = content[i];

        // Add character to current sentence
        if (char_idx < MAX_SENTENCE_LEN - 2)
        {
            sentences[sent_idx][char_idx++] = curr;
        }

        // Check for sentence delimiter
        if (is_sentence_delimiter(curr))
        {
            // Handle multiple consecutive delimiters
            while (content[i + 1] && is_sentence_delimiter(content[i + 1]) && char_idx < MAX_SENTENCE_LEN - 2)
            {
                sentences[sent_idx][char_idx++] = content[++i];
            }

            // Finalize sentence
            sentences[sent_idx][char_idx] = '\0';
            sent_idx++;
            char_idx = 0;

            // Skip following whitespace
            while (content[i + 1] == ' ' || content[i + 1] == '\t' || content[i + 1] == '\n')
            {
                i++;
            }
            continue;
        }

        // Handle multiple spaces
        if ((curr == ' ' || curr == '\t' || curr == '\n') && char_idx > 1 &&
            (sentences[sent_idx][char_idx - 2] == ' ' ||
             sentences[sent_idx][char_idx - 2] == '\t' ||
             sentences[sent_idx][char_idx - 2] == '\n'))
        {
            char_idx--; // Remove extra space
        }
    }

    // Handle last sentence if not ended with delimiter
    if (char_idx > 0)
    {
        sentences[sent_idx][char_idx] = '\0';
        sent_idx++;
    }

    return sent_idx;
}

// Parse sentence into words
int parse_words(const char *sentence, char words[][MAX_WORD_LEN], int max_words)
{
    int word_idx = 0;
    int char_idx = 0;

    for (int i = 0; sentence[i] && word_idx < max_words; i++)
    {
        if (sentence[i] == ' ')
        {
            if (char_idx > 0)
            {
                words[word_idx][char_idx] = '\0';
                word_idx++;
                char_idx = 0;
            }
        }
        else
        {
            words[word_idx][char_idx++] = sentence[i];
        }
    }

    if (char_idx > 0)
    {
        words[word_idx][char_idx] = '\0';
        word_idx++;
    }

    return word_idx;
}

// Reconstruct content from sentences
// Count words and characters in content
void count_words_and_chars(const char *content, int *word_count, int *char_count)
{
    *word_count = 0;
    *char_count = 0;
    int in_word = 0;

    for (const char *p = content; *p; p++)
    {
        (*char_count)++;
        if (*p == ' ' || *p == '\n' || *p == '\t')
        {
            in_word = 0;
        }
        else if (!in_word)
        {
            in_word = 1;
            (*word_count)++;
        }
    }
}

void reconstruct_content(char sentences[][MAX_SENTENCE_LEN], int num_sentences, char *output)
{
    output[0] = '\0';
    for (int i = 0; i < num_sentences; i++)
    {
        strcat(output, sentences[i]);
        if (i < num_sentences - 1 && sentences[i][strlen(sentences[i]) - 1] != ' ')
        {
            strcat(output, " ");
        }
    }
}
