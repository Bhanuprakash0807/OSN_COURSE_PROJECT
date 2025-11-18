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

void process_client(int client_sock)
{
    fprintf(stderr, "[SS-DBG] process_client: start fd=%d\n", client_sock);
    fflush(stderr);
    log_message("SS", "process_client: start");

    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);
    memset(&addr, 0, sizeof(addr));
    int gp_rc = getpeername(client_sock, (struct sockaddr *)&addr, &addr_len);
    char client_ip[INET_ADDRSTRLEN];
    if (gp_rc == 0)
    {
        inet_ntop(AF_INET, &addr.sin_addr, client_ip, INET_ADDRSTRLEN);
    }
    else
    {
        strncpy(client_ip, "unknown", sizeof(client_ip) - 1);
        client_ip[sizeof(client_ip) - 1] = '\0';
        addr.sin_port = 0;
    }
    {
        char acc[MAX_BUFFER];
        snprintf(acc, sizeof(acc), "Accepted connection from %s:%d", client_ip, ntohs(addr.sin_port));
        log_message("SS", acc);
    }

    // Set socket options
    {
        struct timeval tv;
        tv.tv_sec = 30; // 30 second timeout
        tv.tv_usec = 0;
        if (setsockopt(client_sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0 ||
            setsockopt(client_sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) < 0)
        {
            perror("setsockopt timeout");
            close(client_sock);
            return;
        }
    }

    // Enable keep-alive
    {
        int opt = 1;
        if (setsockopt(client_sock, SOL_SOCKET, SO_KEEPALIVE, &opt, sizeof(opt)) < 0)
        {
            perror("setsockopt keepalive");
            close(client_sock);
            return;
        }
    }

    // Set TCP keepalive parameters
    {
        int keepalive_time = 10;  // Start sending keepalive after 10 seconds of idle
        int keepalive_intvl = 5;  // Send keepalive every 5 seconds
        int keepalive_probes = 3; // Drop connection after 3 failed probes

        if (setsockopt(client_sock, IPPROTO_TCP, TCP_KEEPIDLE, &keepalive_time, sizeof(keepalive_time)) < 0 ||
            setsockopt(client_sock, IPPROTO_TCP, TCP_KEEPINTVL, &keepalive_intvl, sizeof(keepalive_intvl)) < 0 ||
            setsockopt(client_sock, IPPROTO_TCP, TCP_KEEPCNT, &keepalive_probes, sizeof(keepalive_probes)) < 0)
        {
            perror("setsockopt TCP keepalive");
            close(client_sock);
            return;
        }
    }

    // Set up error recovery
    signal(SIGPIPE, SIG_IGN); // Ignore SIGPIPE to handle client disconnects

    Message msg, response;

    if (receive_message(client_sock, &msg) < 0)
    {
        char err[MAX_BUFFER];
        snprintf(err, sizeof(err), "receive_message failed from %s:%d (errno=%d: %s)", client_ip, ntohs(addr.sin_port), errno, strerror(errno));
        log_message("SS", err);
        close(client_sock);
        return;
    }

    log_request("SS", client_ip, ntohs(addr.sin_port), "Request received");
    {
        char dbg[MAX_BUFFER];
        snprintf(dbg, sizeof(dbg), "Message type=%d user=%s", msg.msg_type, msg.username);
        log_message("SS", dbg);
    }

    memset(&response, 0, sizeof(response));
    response.msg_type = MSG_RESPONSE;
    response.error_code = ERR_SUCCESS;

    switch (msg.msg_type)
    {
    case MSG_CREATE_FILE:
    {
        char *filename = msg.data;
        char filepath[MAX_PATH];
        snprintf(filepath, sizeof(filepath), "%s/%s", storage_path, filename);

        FILE *fp = fopen(filepath, "w");
        if (!fp)
        {
            response.error_code = ERR_INTERNAL_ERROR;
            snprintf(response.data, MAX_BUFFER, "Failed to create file");
        }
        else
        {
            fclose(fp);
            pthread_mutex_lock(&files_mutex);
            strncpy(files[num_files].filename, filename, MAX_FILENAME - 1);
            files[num_files].content[0] = '\0';
            files[num_files].backup[0] = '\0';
            files[num_files].last_modified = time(NULL);
            files[num_files].created_time = time(NULL);
            files[num_files].last_access = time(NULL);
            files[num_files].is_modified = 0;
            files[num_files].word_count = 0;
            files[num_files].char_count = 0;
            files[num_files].num_sentences = 0;
            files[num_files].locks_capacity = 0;
            files[num_files].num_users = 0;
            files[num_files].owner[0] = '\0';
            files[num_files].last_reader[0] = '\0';
            pthread_mutex_init(&files[num_files].lock, NULL);
            files[num_files].sentence_locks = NULL;
            // Initialize sentence locks with initial capacity
            if (ensure_lock_capacity(&files[num_files], 16) != 0)
            {
                // If we fail to init locks, roll back creation in memory (keep file on disk)
                files[num_files].sentence_locks = NULL;
                files[num_files].locks_capacity = 0;
                pthread_mutex_unlock(&files_mutex);
                response.error_code = ERR_INTERNAL_ERROR;
                snprintf(response.data, MAX_BUFFER, "Failed to initialize locks");
                break;
            }
            // Initialize undo state
            files[num_files].last_undo.original_words = NULL;
            files[num_files].last_undo.word_indices = NULL;
            files[num_files].last_undo.original_sentence = NULL;
            files[num_files].last_undo.num_changes = 0;
            num_files++;
            pthread_mutex_unlock(&files_mutex);
            snprintf(response.data, MAX_BUFFER, "File created successfully");
            log_message("SS", "File created");
        }
        break;
    }

    case MSG_DELETE_FILE:
    {
        char *filename = msg.data;
        char filepath[MAX_PATH];
        snprintf(filepath, sizeof(filepath), "%s/%s", storage_path, filename);

        if (unlink(filepath) < 0)
        {
            response.error_code = ERR_INTERNAL_ERROR;
            snprintf(response.data, MAX_BUFFER, "Failed to delete file");
        }
        else
        {
            pthread_mutex_lock(&files_mutex);
            for (int i = 0; i < num_files; i++)
            {
                if (strcmp(files[i].filename, filename) == 0)
                {
                    for (int j = i; j < num_files - 1; j++)
                    {
                        files[j] = files[j + 1];
                    }
                    num_files--;
                    break;
                }
            }
            pthread_mutex_unlock(&files_mutex);

            snprintf(response.data, MAX_BUFFER, "File deleted successfully");
            log_message("SS", "File deleted");
        }
        break;
    }

    case MSG_READ_FILE:
    {
        char *filename = msg.data;
        FileData *file = find_file(filename);

        if (!file)
        {
            response.error_code = ERR_FILE_NOT_FOUND;
            snprintf(response.data, MAX_BUFFER, "File not found");
        }
        else
        {
            pthread_mutex_lock(&file->lock);
            strncpy(response.data, file->content, MAX_BUFFER - 1);
            file->last_access = time(NULL);
            strncpy(file->last_reader, msg.username, MAX_USERNAME - 1);
            pthread_mutex_unlock(&file->lock);
            log_message("SS", "File read");
        }
        break;
    }

    case MSG_STREAM_FILE:
    {
        char *filename = msg.data;
        FileData *file = find_file(filename);

        if (!file)
        {
            response.error_code = ERR_FILE_NOT_FOUND;
            snprintf(response.data, MAX_BUFFER, "File not found");
            send_message(client_sock, &response);
        }
        else
        {
            pthread_mutex_lock(&file->lock);
            char *dup = strdup(file->content);
            pthread_mutex_unlock(&file->lock);
            if (!dup)
            {
                response.error_code = ERR_MEMORY_ERROR;
                snprintf(response.data, MAX_BUFFER, "Out of memory");
                send_message(client_sock, &response);
                break;
            }
            char *saveptr2 = NULL;
            char *tok = strtok_r(dup, " \t\n", &saveptr2);
            while (tok)
            {
                memset(&response, 0, sizeof(response));
                response.msg_type = MSG_RESPONSE;
                response.error_code = ERR_SUCCESS;
                strncpy(response.data, tok, MAX_BUFFER - 1);
                if (send_message(client_sock, &response) < 0)
                {
                    break;
                }
                usleep(100000); // 0.1 second delay
                tok = strtok_r(NULL, " \t\n", &saveptr2);
            }
            free(dup);
            // Send stop signal
            memset(&response, 0, sizeof(response));
            response.msg_type = MSG_RESPONSE;
            response.error_code = ERR_SUCCESS;
            strcpy(response.data, "STOP");
            send_message(client_sock, &response);

            log_message("SS", "File streamed");
            close(client_sock);
            return;
        }
        break;
    }

    case MSG_WRITE_FILE:
    {
        // Parse write command parameters safely
        char *saveptr = NULL;
        char *tmp_data = strdup(msg.data);
        if (!tmp_data)
        {
            handle_error(client_sock, &response, ERR_MEMORY_ERROR, "Out of memory");
            break;
        }

        char *filename = strtok_r(tmp_data, "|", &saveptr);
        char *sent_num_str = strtok_r(NULL, "|", &saveptr);
        char *updates = strtok_r(NULL, "|", &saveptr);

        if (!filename || !sent_num_str || !updates)
        {
            free(tmp_data);
            handle_error(client_sock, &response, ERR_INVALID_COMMAND, "Invalid write format: missing parameters");
            break;
        }

        char *endptr = NULL;
        long sent_long = strtol(sent_num_str, &endptr, 10);
        if (*sent_num_str == '\0' || *endptr != '\0' || sent_long < 0 || sent_long > INT_MAX)
        {
            free(tmp_data);
            handle_error(client_sock, &response, ERR_INVALID_COMMAND, "Invalid sentence number format");
            break;
        }
        int sent_num = (int)sent_long;

        // Log write attempt
        char log_buf[MAX_BUFFER];
        snprintf(log_buf, sizeof(log_buf), "Write request: file=%s, sentence=%d, user=%s", filename, sent_num, msg.username);
        log_message("SS", log_buf);

        FileData *file = find_file(filename);
        if (!file)
        {
            free(tmp_data);
            response.error_code = ERR_FILE_NOT_FOUND;
            snprintf(response.data, MAX_BUFFER, "File not found");
            break;
        }

        pthread_mutex_lock(&file->lock);

        // Acquire sentence lock with small retry
        int lock_retries = 0;
        int lock_result = ERR_SENTENCE_LOCKED_BY_USER;
        while (lock_retries < 3)
        {
            lock_result = lock_sentence(file, sent_num, msg.username);
            if (lock_result == ERR_SUCCESS)
                break;
            if (lock_result == ERR_INDEX_OUT_OF_RANGE)
            {
                pthread_mutex_unlock(&file->lock);
                free(tmp_data);
                response.error_code = lock_result;
                snprintf(response.data, MAX_BUFFER, "Sentence index out of range");
                goto WRITE_DONE;
            }
            usleep(100000);
            lock_retries++;
        }
        if (lock_result != ERR_SUCCESS)
        {
            pthread_mutex_unlock(&file->lock);
            free(tmp_data);
            response.error_code = lock_result;
            snprintf(response.data, MAX_BUFFER, "Sentence is currently locked by another user");
            break;
        }

        // Backup current content for UNDO
        strncpy(file->backup, file->content, sizeof(file->backup) - 1);
        file->backup[sizeof(file->backup) - 1] = '\0';

        // Find sentence boundaries to avoid large stack arrays
        const char *content = file->content;
        size_t content_len = strlen(content);
        int current_idx = 0;
        size_t sent_start = 0, sent_end = 0;
        int found = 0;
        for (size_t i = 0; i <= content_len; i++)
        {
            int is_end = (i == content_len) || is_sentence_delimiter(content[i]);
            if (is_end)
            {
                if (current_idx == sent_num)
                {
                    sent_end = (i < content_len) ? i + 1 : i; // include delimiter if present
                    found = 1;
                    break;
                }
                current_idx++;
                sent_start = (i < content_len) ? i + 1 : i;
                while (sent_start < content_len && (content[sent_start] == ' ' || content[sent_start] == '\t' || content[sent_start] == '\n'))
                {
                    sent_start++;
                    i = sent_start;
                }
            }
        }
        int num_sentences = current_idx + (found ? 0 : (sent_start < content_len ? 1 : 0));
        if (!found && sent_num > current_idx)
        {
            unlock_sentence(file, sent_num, msg.username);
            pthread_mutex_unlock(&file->lock);
            free(tmp_data);
            response.error_code = ERR_INDEX_OUT_OF_RANGE;
            snprintf(response.data, MAX_BUFFER, "Sentence index out of range");
            break;
        }
        size_t cur_len = (found && sent_end > sent_start) ? (sent_end - sent_start) : 0;
        char *current_sentence = calloc(cur_len + 1, 1);
        if (!current_sentence)
        {
            unlock_sentence(file, sent_num, msg.username);
            pthread_mutex_unlock(&file->lock);
            free(tmp_data);
            response.error_code = ERR_MEMORY_ERROR;
            snprintf(response.data, MAX_BUFFER, "Out of memory");
            break;
        }
        if (cur_len > 0)
            memcpy(current_sentence, content + sent_start, cur_len);

        // Tokenize current sentence into words (dynamic)
        int words_cap = 16, num_words = 0;
        char **words = malloc(words_cap * sizeof(char *));
        if (!words)
        {
            free(current_sentence);
            unlock_sentence(file, sent_num, msg.username);
            pthread_mutex_unlock(&file->lock);
            free(tmp_data);
            response.error_code = ERR_MEMORY_ERROR;
            snprintf(response.data, MAX_BUFFER, "Out of memory");
            break;
        }
        {
            char *dup = strdup(current_sentence);
            char *sp = NULL;
            char *w = dup ? strtok_r(dup, " ", &sp) : NULL;
            while (w)
            {
                if (num_words == words_cap)
                {
                    words_cap *= 2;
                    char **nw = realloc(words, words_cap * sizeof(char *));
                    if (!nw)
                        break;
                    words = nw;
                }
                words[num_words++] = strdup(w);
                w = strtok_r(NULL, " ", &sp);
            }
            if (dup)
                free(dup);
        }

        // Apply updates of the form "<word_idx> <content>" separated by ';'
        // Semantics per spec:
        // - word_idx is 0-based for "insert at beginning"; k > 0 means insert AFTER the k-th word (1-based)
        // - For empty sentences, accept k == 0 or k == 1 and treat both as beginning
        char *updates_dup = strdup(updates);
        if (!updates_dup)
        {
            unlock_sentence(file, sent_num, msg.username);
            for (int i = 0; i < num_words; i++)
                free(words[i]);
            free(words);
            pthread_mutex_unlock(&file->lock);
            free(tmp_data);
            free(current_sentence);
            response.error_code = ERR_MEMORY_ERROR;
            snprintf(response.data, MAX_BUFFER, "Out of memory");
            goto WRITE_DONE;
        }
        char *seg_save = NULL;
        char *seg = strtok_r(updates_dup, ";", &seg_save);
        while (seg)
        {
            // Trim leading spaces
            while (*seg == ' ' || *seg == '\t')
                seg++;
            if (*seg == '\0')
            {
                seg = strtok_r(NULL, ";", &seg_save);
                continue;
            }
            // Parse index
            char *p = seg;
            char *endnum = NULL;
            long k = strtol(p, &endnum, 10);
            if (p == endnum)
            {
                // No number parsed
                seg = strtok_r(NULL, ";", &seg_save);
                continue;
            }
            // Skip spaces before content
            while (endnum && (*endnum == ' ' || *endnum == '\t'))
                endnum++;
            const char *ins_content = endnum && *endnum ? endnum : "";

            // Determine insertion position
            int pos;
            if (num_words == 0)
            {
                if (k == 0 || k == 1)
                    pos = 0;
                else
                {
                    free(updates_dup);
                    unlock_sentence(file, sent_num, msg.username);
                    for (int i = 0; i < num_words; i++)
                        free(words[i]);
                    free(words);
                    pthread_mutex_unlock(&file->lock);
                    free(tmp_data);
                    free(current_sentence);
                    response.error_code = ERR_INDEX_OUT_OF_RANGE;
                    snprintf(response.data, MAX_BUFFER, "Word index out of range");
                    goto WRITE_DONE;
                }
            }
            else
            {
                if (k < 0)
                {
                    free(updates_dup);
                    unlock_sentence(file, sent_num, msg.username);
                    for (int i = 0; i < num_words; i++)
                        free(words[i]);
                    free(words);
                    pthread_mutex_unlock(&file->lock);
                    free(tmp_data);
                    free(current_sentence);
                    response.error_code = ERR_INDEX_OUT_OF_RANGE;
                    snprintf(response.data, MAX_BUFFER, "Word index out of range");
                    goto WRITE_DONE;
                }
                // k is 0-based for beginning, else 1-based for after-kth
                if (k == 0)
                    pos = 0;
                else
                    pos = (int)k; // insert before element at index 'pos'
                if (pos > num_words)
                {
                    free(updates_dup);
                    unlock_sentence(file, sent_num, msg.username);
                    for (int i = 0; i < num_words; i++)
                        free(words[i]);
                    free(words);
                    pthread_mutex_unlock(&file->lock);
                    free(tmp_data);
                    free(current_sentence);
                    response.error_code = ERR_INDEX_OUT_OF_RANGE;
                    snprintf(response.data, MAX_BUFFER, "Word index out of range");
                    goto WRITE_DONE;
                }
            }

            // Split ins_content into words by whitespace, preserving punctuation
            // Count words first
            int add_count = 0, add_cap = 8;
            char **add_words = malloc(add_cap * sizeof(char *));
            if (!add_words)
            {
                free(updates_dup);
                unlock_sentence(file, sent_num, msg.username);
                for (int i = 0; i < num_words; i++)
                    free(words[i]);
                free(words);
                pthread_mutex_unlock(&file->lock);
                free(tmp_data);
                free(current_sentence);
                response.error_code = ERR_MEMORY_ERROR;
                snprintf(response.data, MAX_BUFFER, "Out of memory");
                goto WRITE_DONE;
            }
            char *ins_dup = strdup(ins_content);
            char *wsp = NULL;
            char *tok = ins_dup ? strtok_r(ins_dup, " \t\n", &wsp) : NULL;
            while (tok)
            {
                if (add_count == add_cap)
                {
                    add_cap *= 2;
                    char **nw = realloc(add_words, add_cap * sizeof(char *));
                    if (!nw)
                        break;
                    add_words = nw;
                }
                add_words[add_count++] = strdup(tok);
                tok = strtok_r(NULL, " \t\n", &wsp);
            }
            if (ins_dup)
                free(ins_dup);

            if (add_count > 0)
            {
                // Ensure capacity in main words array
                if (num_words + add_count > words_cap)
                {
                    while (num_words + add_count > words_cap)
                        words_cap *= 2;
                    char **nw = realloc(words, words_cap * sizeof(char *));
                    if (!nw)
                    {
                        for (int i = 0; i < add_count; i++)
                            free(add_words[i]);
                        free(add_words);
                        free(updates_dup);
                        unlock_sentence(file, sent_num, msg.username);
                        for (int i = 0; i < num_words; i++)
                            free(words[i]);
                        free(words);
                        pthread_mutex_unlock(&file->lock);
                        free(tmp_data);
                        free(current_sentence);
                        response.error_code = ERR_MEMORY_ERROR;
                        snprintf(response.data, MAX_BUFFER, "Out of memory");
                        goto WRITE_DONE;
                    }
                    words = nw;
                }
                // Shift existing words to the right
                memmove(words + pos + add_count, words + pos, (num_words - pos) * sizeof(char *));
                // Copy in new words
                for (int i = 0; i < add_count; i++)
                {
                    words[pos + i] = add_words[i];
                }
                num_words += add_count;
            }
            free(add_words);

            seg = strtok_r(NULL, ";", &seg_save);
        }
        free(updates_dup);

        // Reconstruct the modified sentence
        // Rebuild the modified sentence
        size_t new_len = 0;
        for (int i = 0; i < num_words; i++)
            new_len += strlen(words[i]) + 1;
        char *rebuilt = calloc(new_len + 1, 1);
        if (!rebuilt)
        {
            for (int i = 0; i < num_words; i++)
                free(words[i]);
            free(words);
            free(current_sentence);
            unlock_sentence(file, sent_num, msg.username);
            pthread_mutex_unlock(&file->lock);
            free(tmp_data);
            response.error_code = ERR_MEMORY_ERROR;
            snprintf(response.data, MAX_BUFFER, "Out of memory");
            break;
        }
        for (int i = 0; i < num_words; i++)
        {
            if (i)
                strcat(rebuilt, " ");
            strcat(rebuilt, words[i]);
        }

        // Rebuild full file content using prefix + modified + suffix
        char *new_content = NULL;
        size_t prefix_len = sent_start;
        size_t suffix_start = found ? sent_end : content_len;
        size_t suffix_len = (suffix_start < content_len) ? (content_len - suffix_start) : 0;
        // If appending a new sentence (not replacing any existing chars), ensure a space between previous and new content
        int need_space = 0;
        {
            int appending_at_end = (sent_start == content_len) && (suffix_start == content_len);
            if ((appending_at_end || !found) && prefix_len > 0)
            {
                char last = content[prefix_len - 1];
                if (!(last == ' ' || last == '\n' || last == '\t'))
                    need_space = 1;
            }
        }
        size_t total_len2 = prefix_len + need_space + strlen(rebuilt) + suffix_len + 2;
        new_content = malloc(total_len2);
        if (!new_content)
        {
            for (int i = 0; i < num_words; i++)
                free(words[i]);
            free(words);
            free(current_sentence);
            free(rebuilt);
            unlock_sentence(file, sent_num, msg.username);
            pthread_mutex_unlock(&file->lock);
            free(tmp_data);
            response.error_code = ERR_MEMORY_ERROR;
            snprintf(response.data, MAX_BUFFER, "Out of memory");
            break;
        }
        memcpy(new_content, content, prefix_len);
        size_t cursor = prefix_len;
        if (need_space)
            new_content[cursor++] = ' ';
        strcpy(new_content + cursor, rebuilt);
        if (suffix_len > 0)
            memcpy(new_content + cursor + strlen(rebuilt), content + suffix_start, suffix_len);
        new_content[cursor + strlen(rebuilt) + suffix_len] = '\0';
        strncpy(file->content, new_content, sizeof(file->content) - 1);
        file->content[sizeof(file->content) - 1] = '\0';
        free(new_content);
        for (int i = 0; i < num_words; i++)
            free(words[i]);
        free(words);
        free(current_sentence);
        free(rebuilt);

        // Ensure sentence locks capacity can accommodate new sentence count
        // Update sentence count estimate
        int total_sentences = 0;
        for (size_t i = 0; file->content[i]; i++)
            if (is_sentence_delimiter(file->content[i]))
                total_sentences++;
        if (total_sentences > file->locks_capacity)
        {
            if (ensure_lock_capacity(file, total_sentences) != 0)
            {
                unlock_sentence(file, sent_num, msg.username);
                pthread_mutex_unlock(&file->lock);
                free(tmp_data);
                response.error_code = ERR_MEMORY_ERROR;
                snprintf(response.data, MAX_BUFFER, "Failed to resize locks");
                break;
            }
        }

        // Update tracked sentence count after modification
        file->num_sentences = total_sentences;

        // Update metadata
        count_words_and_chars(file->content, &file->word_count, &file->char_count);
        file->last_modified = time(NULL);
        file->is_modified = 1;
        strncpy(file->last_modifier, msg.username, MAX_USERNAME - 1);

        // Persist changes
        if (save_file(file) != 0)
        {
            unlock_sentence(file, sent_num, msg.username);
            pthread_mutex_unlock(&file->lock);
            free(tmp_data);
            response.error_code = ERR_IO_ERROR;
            snprintf(response.data, MAX_BUFFER, "Failed to persist changes");
            break;
        }

        // Release locks and finish
        unlock_sentence(file, sent_num, msg.username);
        pthread_mutex_unlock(&file->lock);
        free(tmp_data);

        snprintf(response.data, MAX_BUFFER, "Write successful");
        log_message("SS", "File written");
        // Reset undo buffers for a fresh next operation (optional per spec)
        // Note: If you want multi-level undo, remove this reset and manage a stack instead
        // reset_undo(file);
        break;

    WRITE_DONE:
        // In case of early goto due to validation error
        break;
    }

    case MSG_UNDO:
    {
        char *filename = msg.data;
        FileData *file = find_file(filename);

        if (!file)
        {
            response.error_code = ERR_FILE_NOT_FOUND;
            snprintf(response.data, MAX_BUFFER, "File not found");
        }
        else
        {
            pthread_mutex_lock(&file->lock);
            strcpy(file->content, file->backup);

            // Protect against double-undo by checking if any changes
            if (file->is_modified)
            {
                // Update word and character counts after undo
                count_words_and_chars(file->content, &file->word_count, &file->char_count);

                file->last_modified = time(NULL);
                file->is_modified = 0;
                strncpy(file->last_modifier, msg.username, MAX_USERNAME - 1);

                // Try to save file with retry logic
                int save_retries = 0;
                const int max_save_retries = 3;
                while (save_retries < max_save_retries)
                {
                    if (save_file(file) == 0)
                        break; // Success
                    save_retries++;
                    usleep(100000); // Wait 100ms between retries
                }

                if (save_retries == max_save_retries)
                {
                    response.error_code = ERR_INTERNAL_ERROR;
                    snprintf(response.data, MAX_BUFFER, "Failed to save file after undo");
                }
            }
            else
            {
                response.error_code = ERR_INVALID_COMMAND;
                snprintf(response.data, MAX_BUFFER, "No changes to undo");
            }
            pthread_mutex_unlock(&file->lock);

            if (response.error_code == ERR_SUCCESS)
            {
                snprintf(response.data, MAX_BUFFER, "Undo successful");
                log_message("SS", "Undo performed");
            }
        }
        break;
    }

    case MSG_SS_INFO:
    {
        // Provide metadata to name server on request (words, chars, size, times)
        char *filename = msg.data;
        FileData *file = find_file(filename);
        if (!file)
        {
            response.error_code = ERR_FILE_NOT_FOUND;
            snprintf(response.data, MAX_BUFFER, "File not found");
        }
        else
        {
            // Build a small metadata payload for this single file
            pthread_mutex_lock(&file->lock);
            char payload[MAX_BUFFER];
            int off = 0;
            int n = snprintf(payload + off, sizeof(payload) - off, "%s\n", file->filename);
            if (n > 0)
                off += n;
            n = snprintf(payload + off, sizeof(payload) - off, "%s\n", file->owner[0] ? file->owner : "-");
            if (n > 0)
                off += n;
            long size = (long)strlen(file->content);
            n = snprintf(payload + off, sizeof(payload) - off, "%ld %d %d %ld %ld %ld\n",
                         size, file->word_count, file->char_count,
                         (long)file->last_access, (long)file->last_modified, (long)file->created_time);
            if (n > 0)
                off += n;
            n = snprintf(payload + off, sizeof(payload) - off, "%d\n", file->num_users);
            if (n > 0)
                off += n;
            for (int u = 0; u < file->num_users && off < (int)sizeof(payload) - 2; u++)
            {
                n = snprintf(payload + off, sizeof(payload) - off, "%s %d\n",
                             file->users[u].username, file->users[u].access_type);
                if (n < 0)
                    break;
                off += n;
            }
            pthread_mutex_unlock(&file->lock);

            strncpy(response.data, payload, MAX_BUFFER - 1);
            response.error_code = ERR_SUCCESS;
        }
        break;
    }

    case MSG_SS_RESCAN:
    {
        // Re-scan storage directory and return current file list in same format as initial LIST
        int cnt = rescan_storage();
        if (cnt < 0)
        {
            response.error_code = ERR_INTERNAL_ERROR;
            snprintf(response.data, MAX_BUFFER, "Rescan failed");
        }
        else
        {
            char payload[MAX_BUFFER];
            int off = snprintf(payload, sizeof(payload), "LIST %d\n", cnt);
            pthread_mutex_lock(&files_mutex);
            for (int i = 0; i < num_files && off < (int)sizeof(payload) - 2; i++)
            {
                int n = snprintf(payload + off, sizeof(payload) - off, "%s\n", files[i].filename);
                if (n < 0)
                    break;
                off += n;
            }
            pthread_mutex_unlock(&files_mutex);
            strncpy(response.data, payload, MAX_BUFFER - 1);
            response.error_code = ERR_SUCCESS;
        }
        break;
    }

    case MSG_EXEC_FILE:
    {
        char *filename = msg.data;
        FileData *file = find_file(filename);

        if (!file)
        {
            response.error_code = ERR_FILE_NOT_FOUND;
            snprintf(response.data, MAX_BUFFER, "File not found");
        }
        else
        {
            pthread_mutex_lock(&file->lock);
            strncpy(response.data, file->content, MAX_BUFFER - 1);
            pthread_mutex_unlock(&file->lock);
        }
        break;
    }

    default:
        response.error_code = ERR_INVALID_COMMAND;
        snprintf(response.data, MAX_BUFFER, "Invalid command");
        break;
    }

    send_message(client_sock, &response);
    close(client_sock);
    return;
}
