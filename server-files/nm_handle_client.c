#include "../common.h"
#include "nameserver.h"
#include <sys/time.h>
#include <signal.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <netinet/tcp.h>
#include <unistd.h>

// Handle client connections
void *handle_client(void *arg)
{
    int client_sock = *(int *)arg;
    free(arg);

    // Set up signal mask for the thread
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGPIPE);
    pthread_sigmask(SIG_BLOCK, &set, NULL);

    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);
    char client_ip[INET_ADDRSTRLEN];

    // Get client IP with error handling
    if (getpeername(client_sock, (struct sockaddr *)&addr, &addr_len) < 0)
    {
        log_error("NM", "getpeername", ERR_NETWORK_ERROR, strerror(errno));
        close(client_sock);
        return NULL;
    }

    if (!inet_ntop(AF_INET, &addr.sin_addr, client_ip, INET_ADDRSTRLEN))
    {
        log_error("NM", "inet_ntop", ERR_NETWORK_ERROR, strerror(errno));
        close(client_sock);
        return NULL;
    }

    // Set TCP_NODELAY to disable Nagle's algorithm
    int flag = 1;
    if (setsockopt(client_sock, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag)) < 0)
    {
        log_error("NM", "setsockopt TCP_NODELAY", ERR_NETWORK_ERROR, strerror(errno));
    }

    // Set socket timeout
    struct timeval tv;
    tv.tv_sec = 30; // 30 second timeout
    tv.tv_usec = 0;
    if (setsockopt(client_sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0)
    {
        log_error("NM", "setsockopt", ERR_NETWORK_ERROR, strerror(errno));
    }
    inet_ntop(AF_INET, &addr.sin_addr, client_ip, INET_ADDRSTRLEN);

    Message msg, response;

    // First message determines if this is a storage server or regular client
    if (receive_message(client_sock, &msg) < 0)
    {
        close(client_sock);
        return NULL;
    }

    if (msg.msg_type == MSG_REGISTER_SS)
    {
        pthread_mutex_lock(&ss_mutex);
        if (num_ss >= MAX_SS)
        {
            pthread_mutex_unlock(&ss_mutex);
            log_error("NM", "register_ss", ERR_TOO_MANY_FILES, "Max storage servers reached");
            Message resp;
            memset(&resp, 0, sizeof(resp));
            resp.msg_type = MSG_ERROR;
            resp.error_code = ERR_TOO_MANY_FILES;
            send_message(client_sock, &resp);
            close(client_sock);
            return NULL;
        }

        int ss_idx = num_ss;

        strncpy(storage_servers[ss_idx].ip, client_ip, INET_ADDRSTRLEN - 1);
        storage_servers[ss_idx].ip[INET_ADDRSTRLEN - 1] = '\0';
        sscanf(msg.data, "%d %d", &storage_servers[ss_idx].nm_port,
               &storage_servers[ss_idx].client_port);
        storage_servers[ss_idx].num_files = 0;
        storage_servers[ss_idx].is_active = 1;

        num_ss++;
        pthread_mutex_unlock(&ss_mutex);

        log_message("NM", "Storage server registered successfully");

        Message response;
        memset(&response, 0, sizeof(response));
        response.msg_type = MSG_ACK;
        response.error_code = ERR_SUCCESS;
        send_message(client_sock, &response);
        close(client_sock);
        return NULL;
    }

    // Enter request-processing loop: process current msg, then wait for next one
    while (1)
    {
        log_request("NM", client_ip, ntohs(addr.sin_port), "Request received");

        memset(&response, 0, sizeof(response));
        response.msg_type = MSG_RESPONSE;
        response.error_code = ERR_SUCCESS;
        strncpy(response.username, msg.username, MAX_USERNAME - 1);
        response.username[MAX_USERNAME - 1] = '\0';

        switch (msg.msg_type)
        {
        case MSG_REGISTER_CLIENT:
        {
            pthread_mutex_lock(&client_mutex);
            if (num_clients >= MAX_CLIENTS)
            {
                pthread_mutex_unlock(&client_mutex);
                response.error_code = ERR_TOO_MANY_FILES;
                snprintf(response.data, MAX_BUFFER, "Max clients reached");
                break;
            }

            strncpy(clients[num_clients].ip, client_ip, INET_ADDRSTRLEN - 1);
            clients[num_clients].ip[INET_ADDRSTRLEN - 1] = '\0';
            clients[num_clients].port = ntohs(addr.sin_port);
            strncpy(clients[num_clients].username, msg.username, MAX_USERNAME - 1);
            clients[num_clients].username[MAX_USERNAME - 1] = '\0';
            clients[num_clients].is_active = 1;
            num_clients++;
            pthread_mutex_unlock(&client_mutex);

            log_message("NM", "Client registered successfully");
            // Persist username if new (add under lock, save after unlocking)
            int save_needed = 0;
            pthread_mutex_lock(&users_mutex);
            int found = 0;
            for (int ui = 0; ui < num_known_users; ui++)
            {
                if (strcmp(known_users[ui], msg.username) == 0)
                {
                    found = 1;
                    break;
                }
            }
            if (!found && num_known_users < MAX_CLIENTS)
            {
                strncpy(known_users[num_known_users], msg.username, MAX_USERNAME - 1);
                known_users[num_known_users][MAX_USERNAME - 1] = '\0';
                num_known_users++;
                save_needed = 1;
            }
            pthread_mutex_unlock(&users_mutex);
            if (save_needed)
                save_users();
            snprintf(response.data, MAX_BUFFER, "Registration successful");
            break;
        }

        case MSG_SS_INFO:
        {
            // Storage server sending initial file list after registration
            // Payload format: "LIST <n>\n<file1>\n<file2>\n..."
            // Identify SS by IP
            int ss_idx = -1;
            pthread_mutex_lock(&ss_mutex);
            for (int i = 0; i < num_ss; i++)
            {
                if (strcmp(storage_servers[i].ip, client_ip) == 0)
                {
                    ss_idx = i;
                    break;
                }
            }
            pthread_mutex_unlock(&ss_mutex);
            if (ss_idx < 0)
            {
                response.error_code = ERR_INVALID_COMMAND;
                snprintf(response.data, MAX_BUFFER, "Unknown storage server");
                break;
            }
            // Parse list
            int n = 0;
            if (sscanf(msg.data, "LIST %d", &n) == 1 && n >= 0)
            {
                // Parse extended payload: for each file include owner, metadata and ACLs
                char *p = strchr(msg.data, '\n');
                for (int i = 0; i < n && p; i++)
                {
                    p++;
                    if (!*p)
                        break;
                    // filename
                    char fname[MAX_FILENAME] = "";
                    int len = 0;
                    while (p[len] && p[len] != '\n' && len < MAX_FILENAME - 1)
                        len++;
                    if (len > 0)
                    {
                        memcpy(fname, p, len);
                        fname[len] = '\0';
                    }
                    p += len;
                    if (*p == '\n')
                        p++;

                    // owner
                    char owner[MAX_USERNAME] = "";
                    len = 0;
                    while (p[len] && p[len] != '\n' && len < MAX_USERNAME - 1)
                        len++;
                    if (len > 0)
                    {
                        memcpy(owner, p, len);
                        owner[len] = '\0';
                    }
                    p += len;
                    if (*p == '\n')
                        p++;

                    // metadata line: size words chars accessed modified created
                    long size = 0;
                    int words = 0, chars = 0;
                    long acc = 0, mod = 0, crt = 0;
                    if (sscanf(p, "%ld %d %d %ld %ld %ld", &size, &words, &chars, &acc, &mod, &crt) < 6)
                    {
                        // malformed; stop parsing
                        break;
                    }
                    // advance to end of metadata line
                    char *nl = strchr(p, '\n');
                    if (!nl)
                        break;
                    p = nl + 1;

                    // number of users
                    int u = 0;
                    if (sscanf(p, "%d", &u) == 1)
                    {
                        nl = strchr(p, '\n');
                        if (!nl)
                            break;
                        p = nl + 1;
                    }

                    UserAccess tmp_users[MAX_ACCESS_USERS];
                    int tmp_u = 0;
                    for (int uu = 0; uu < u && p; uu++)
                    {
                        char uname[MAX_USERNAME] = "";
                        int at = ACCESS_READ;
                        if (sscanf(p, "%63s %d", uname, &at) == 2)
                        {
                            strncpy(tmp_users[tmp_u].username, uname, MAX_USERNAME - 1);
                            tmp_users[tmp_u].access_type = at;
                            tmp_u++;
                        }
                        nl = strchr(p, '\n');
                        if (!nl)
                        {
                            p = NULL;
                            break;
                        }
                        p = nl + 1;
                    }

                    if (strlen(fname) > 0)
                    {
                        pthread_mutex_lock(&file_mutex);
                        int found_index = -1;
                        for (int j = 0; j < num_files; j++)
                        {
                            if (strcmp(files[j].metadata.filename, fname) == 0)
                            {
                                found_index = j;
                                break;
                            }
                        }
                        if (found_index >= 0)
                        {
                            files[found_index].ss_index = ss_idx;
                            strncpy(files[found_index].metadata.owner, owner, MAX_USERNAME - 1);
                            files[found_index].metadata.size = size;
                            files[found_index].metadata.word_count = words;
                            files[found_index].metadata.char_count = chars;
                            files[found_index].metadata.accessed_time = (time_t)acc;
                            files[found_index].metadata.modified_time = (time_t)mod;
                            files[found_index].metadata.created_time = (time_t)crt;
                            files[found_index].metadata.num_users = 0;
                            for (int uu = 0; uu < tmp_u && uu < MAX_ACCESS_USERS; uu++)
                            {
                                strncpy(files[found_index].metadata.users[uu].username, tmp_users[uu].username, MAX_USERNAME - 1);
                                files[found_index].metadata.users[uu].access_type = tmp_users[uu].access_type;
                                files[found_index].metadata.num_users++;
                            }
                        }
                        else if (num_files < MAX_FILES)
                        {
                            strncpy(files[num_files].metadata.filename, fname, MAX_FILENAME - 1);
                            strncpy(files[num_files].metadata.owner, owner, MAX_USERNAME - 1);
                            files[num_files].metadata.size = size;
                            files[num_files].metadata.word_count = words;
                            files[num_files].metadata.char_count = chars;
                            files[num_files].metadata.accessed_time = (time_t)acc;
                            files[num_files].metadata.modified_time = (time_t)mod;
                            files[num_files].metadata.created_time = (time_t)crt;
                            files[num_files].metadata.num_users = 0;
                            for (int uu = 0; uu < tmp_u && uu < MAX_ACCESS_USERS; uu++)
                            {
                                strncpy(files[num_files].metadata.users[uu].username, tmp_users[uu].username, MAX_USERNAME - 1);
                                files[num_files].metadata.users[uu].access_type = tmp_users[uu].access_type;
                                files[num_files].metadata.num_users++;
                            }
                            files[num_files].ss_index = ss_idx;
                            num_files++;
                        }
                        pthread_mutex_unlock(&file_mutex);
                        pthread_mutex_lock(&trie_mutex);
                        trie_insert(file_trie_root, fname, ss_idx);
                        pthread_mutex_unlock(&trie_mutex);
                    }
                }
                snprintf(response.data, MAX_BUFFER, "OK");
                // Persist metadata to capture any newly discovered files
                save_metadata();
            }
            else
            {
                response.error_code = ERR_INVALID_COMMAND;
                snprintf(response.data, MAX_BUFFER, "Invalid SS_INFO payload");
            }
            break;
        }

        case MSG_SS_RESCAN:
        {
            // Client requested NM to ask SS(s) to rescan their storage directories.
            // msg.data can be an IP to rescan a specific SS, or "ALL"/empty to rescan all.
            char target[MAX_BUFFER];
            strncpy(target, msg.data, sizeof(target) - 1);
            target[sizeof(target) - 1] = '\0';

            int rescan_success = 0;
            char aggregated[MAX_BUFFER];
            aggregated[0] = '\0';

            pthread_mutex_lock(&ss_mutex);
            for (int i = 0; i < num_ss; i++)
            {
                if (!storage_servers[i].is_active)
                    continue;
                if (strlen(target) > 0 && strcmp(target, "ALL") != 0)
                {
                    if (strcmp(storage_servers[i].ip, target) != 0)
                        continue;
                }

                Message ss_resp;
                int rc = ss_simple_request(i, MSG_SS_RESCAN, "", &ss_resp);
                if (rc == ERR_SUCCESS)
                {
                    // Parse LIST payload and update NM registry similar to MSG_SS_INFO
                    int n = 0;
                    if (sscanf(ss_resp.data, "LIST %d", &n) == 1 && n >= 0)
                    {
                        char *p = strchr(ss_resp.data, '\n');
                        for (int j = 0; j < n && p; j++)
                        {
                            p++;
                            if (!*p)
                                break;
                            char fname[MAX_FILENAME] = "";
                            int len = 0;
                            while (p[len] && p[len] != '\n' && len < MAX_FILENAME - 1)
                                len++;
                            if (len > 0)
                            {
                                memcpy(fname, p, len);
                                fname[len] = '\0';
                            }
                            p += len;
                            if (*p == '\n')
                                p++;

                            char owner[MAX_USERNAME] = "";
                            len = 0;
                            while (p[len] && p[len] != '\n' && len < MAX_USERNAME - 1)
                                len++;
                            if (len > 0)
                            {
                                memcpy(owner, p, len);
                                owner[len] = '\0';
                            }
                            p += len;
                            if (*p == '\n')
                                p++;

                            long size = 0;
                            int words = 0, chars = 0;
                            long acc = 0, mod = 0, crt = 0;
                            if (sscanf(p, "%ld %d %d %ld %ld %ld", &size, &words, &chars, &acc, &mod, &crt) < 6)
                                break;
                            char *nl = strchr(p, '\n');
                            if (!nl)
                                break;
                            p = nl + 1;

                            int u = 0;
                            if (sscanf(p, "%d", &u) == 1)
                            {
                                nl = strchr(p, '\n');
                                if (!nl)
                                    break;
                                p = nl + 1;
                            }

                            UserAccess tmp_users[MAX_ACCESS_USERS];
                            int tmp_u = 0;
                            for (int uu = 0; uu < u && p; uu++)
                            {
                                char uname[MAX_USERNAME] = "";
                                int at = ACCESS_READ;
                                if (sscanf(p, "%63s %d", uname, &at) == 2)
                                {
                                    strncpy(tmp_users[tmp_u].username, uname, MAX_USERNAME - 1);
                                    tmp_users[tmp_u].access_type = at;
                                    tmp_u++;
                                }
                                nl = strchr(p, '\n');
                                if (!nl)
                                {
                                    p = NULL;
                                    break;
                                }
                                p = nl + 1;
                            }

                            if (strlen(fname) > 0)
                            {
                                pthread_mutex_lock(&file_mutex);
                                int found_index = -1;
                                for (int k = 0; k < num_files; k++)
                                {
                                    if (strcmp(files[k].metadata.filename, fname) == 0)
                                    {
                                        found_index = k;
                                        break;
                                    }
                                }
                                if (found_index >= 0)
                                {
                                    files[found_index].ss_index = i;
                                    strncpy(files[found_index].metadata.owner, owner, MAX_USERNAME - 1);
                                    files[found_index].metadata.size = size;
                                    files[found_index].metadata.word_count = words;
                                    files[found_index].metadata.char_count = chars;
                                    files[found_index].metadata.accessed_time = (time_t)acc;
                                    files[found_index].metadata.modified_time = (time_t)mod;
                                    files[found_index].metadata.created_time = (time_t)crt;
                                    files[found_index].metadata.num_users = 0;
                                    for (int uu = 0; uu < tmp_u && uu < MAX_ACCESS_USERS; uu++)
                                    {
                                        strncpy(files[found_index].metadata.users[uu].username, tmp_users[uu].username, MAX_USERNAME - 1);
                                        files[found_index].metadata.users[uu].access_type = tmp_users[uu].access_type;
                                        files[found_index].metadata.num_users++;
                                    }
                                }
                                else if (num_files < MAX_FILES)
                                {
                                    strncpy(files[num_files].metadata.filename, fname, MAX_FILENAME - 1);
                                    strncpy(files[num_files].metadata.owner, owner, MAX_USERNAME - 1);
                                    files[num_files].metadata.size = size;
                                    files[num_files].metadata.word_count = words;
                                    files[num_files].metadata.char_count = chars;
                                    files[num_files].metadata.accessed_time = (time_t)acc;
                                    files[num_files].metadata.modified_time = (time_t)mod;
                                    files[num_files].metadata.created_time = (time_t)crt;
                                    files[num_files].metadata.num_users = 0;
                                    for (int uu = 0; uu < tmp_u && uu < MAX_ACCESS_USERS; uu++)
                                    {
                                        strncpy(files[num_files].metadata.users[uu].username, tmp_users[uu].username, MAX_USERNAME - 1);
                                        files[num_files].metadata.users[uu].access_type = tmp_users[uu].access_type;
                                        files[num_files].metadata.num_users++;
                                    }
                                    files[num_files].ss_index = i;
                                    num_files++;
                                }
                                pthread_mutex_unlock(&file_mutex);
                                pthread_mutex_lock(&trie_mutex);
                                trie_insert(file_trie_root, fname, i);
                                pthread_mutex_unlock(&trie_mutex);
                            }
                        }
                        rescan_success = 1;
                    }
                }
                // aggregate response messages
                if (ss_resp.data[0])
                {
                    strncat(aggregated, ss_resp.data, sizeof(aggregated) - strlen(aggregated) - 1);
                    strncat(aggregated, "\n", sizeof(aggregated) - strlen(aggregated) - 1);
                }
                if (strlen(target) > 0 && strcmp(target, "ALL") != 0 && strcmp(storage_servers[i].ip, target) == 0)
                    break;
            }
            pthread_mutex_unlock(&ss_mutex);

            if (rescan_success)
            {
                save_metadata();
                response.error_code = ERR_SUCCESS;
                snprintf(response.data, MAX_BUFFER, "Rescan completed\n%s", aggregated);
            }
            else
            {
                response.error_code = ERR_INTERNAL_ERROR;
                snprintf(response.data, MAX_BUFFER, "Rescan failed or no matching storage servers");
            }
            break;
        }

        case MSG_VIEW_FILES:
        {
            char result[MAX_BUFFER] = "";
            // Support combined flags like -al or -la by scanning characters
            int show_all = (strchr(msg.data, 'a') != NULL);
            int show_details = (strchr(msg.data, 'l') != NULL);

            if (show_details)
            {
                if (show_all)
                {
                    strcat(result, "All files with details:\n");
                }
                else
                {
                    strcat(result, "Accessible files with details:\n");
                }
                strcat(result, "---------------------------------------------------------\n");
                strcat(result, "|  Filename  | Words | Chars | Last Access Time | Owner |\n");
                strcat(result, "|------------|-------|-------|------------------|-------|\n");
            }
            // Copy filenames to local list to avoid holding lock during network calls
            char filenames_local[MAX_FILES][MAX_FILENAME];
            int ss_idx_local[MAX_FILES];
            int count = 0;
            pthread_mutex_lock(&file_mutex);
            for (int i = 0; i < num_files && count < MAX_FILES; i++)
            {
                int has_access = check_access(&files[i], msg.username, ACCESS_READ);
                if (show_all || has_access)
                {
                    strncpy(filenames_local[count], files[i].metadata.filename, MAX_FILENAME - 1);
                    ss_idx_local[count] = files[i].ss_index;
                    count++;
                }
            }
            pthread_mutex_unlock(&file_mutex);
            for (int i = 0; i < count; i++)
            {
                FileMetadata m = {0};
                int rc = fetch_stats_from_ss(filenames_local[i], ss_idx_local[i], &m, NULL);
                if (rc == ERR_FILE_NOT_FOUND)
                {
                    // Remove from registry lazily
                    pthread_mutex_lock(&file_mutex);
                    for (int j = 0; j < num_files; j++)
                    {
                        if (strcmp(files[j].metadata.filename, filenames_local[i]) == 0)
                        {
                            for (int k = j; k < num_files - 1; k++)
                                files[k] = files[k + 1];
                            num_files--;
                            // Invalidate trie and cache after mutation
                            pthread_mutex_lock(&trie_mutex);
                            trie_delete(file_trie_root, filenames_local[i]);
                            pthread_mutex_unlock(&trie_mutex);
                            cache_clear();
                            break;
                        }
                    }
                    pthread_mutex_unlock(&file_mutex);
                    // Persist metadata after removing an entry so NM's metadata file
                    // stays in sync with the in-memory registry.
                    save_metadata();
                    continue;
                }
                if (show_details)
                {
                    // Owner from NM registry
                    pthread_mutex_lock(&file_mutex);
                    const char *owner = "-";
                    for (int j = 0; j < num_files; j++)
                    {
                        if (strcmp(files[j].metadata.filename, filenames_local[i]) == 0)
                        {
                            owner = files[j].metadata.owner;
                            break;
                        }
                    }
                    pthread_mutex_unlock(&file_mutex);
                    char line[512];
                    char *acc = format_time(m.accessed_time ? m.accessed_time : time(NULL));
                    snprintf(line, sizeof(line), "| %-10s | %5d | %5d | %-16s | %-5s |\n",
                             filenames_local[i], m.word_count, m.char_count, acc, owner);
                    free(acc);
                    strcat(result, line);
                }
                else
                {
                    strcat(result, "--> ");
                    strcat(result, filenames_local[i]);
                    strcat(result, "\n");
                }
            }

            if (show_details)
            {
                strcat(result, "---------------------------------------------------------\n");
            }

            strncpy(response.data, result, MAX_BUFFER - 1);
            break;
        }

        case MSG_LIST_USERS:
        {
            char result[MAX_BUFFER] = "Users:\n";
            // Build a de-duplicated list of usernames
            char seen[MAX_CLIENTS][MAX_USERNAME];
            int seen_count = 0;
            pthread_mutex_lock(&client_mutex);
            for (int i = 0; i < num_clients; i++)
            {
                int duplicate = 0;
                for (int j = 0; j < seen_count; j++)
                {
                    if (strcmp(seen[j], clients[i].username) == 0)
                    {
                        duplicate = 1;
                        break;
                    }
                }
                if (!duplicate && seen_count < MAX_CLIENTS)
                {
                    strncpy(seen[seen_count], clients[i].username, MAX_USERNAME - 1);
                    seen[seen_count][MAX_USERNAME - 1] = '\0';
                    seen_count++;
                }
            }
            pthread_mutex_unlock(&client_mutex);
            for (int i = 0; i < seen_count; i++)
            {
                strcat(result, "--> ");
                strcat(result, seen[i]);
                strcat(result, "\n");
            }
            strncpy(response.data, result, MAX_BUFFER - 1);
            break;
        }

        case MSG_INFO_FILE:
        {
            FileRecord *file = find_file(msg.data);
            if (!file)
            {
                response.error_code = ERR_FILE_NOT_FOUND;
                snprintf(response.data, MAX_BUFFER, "File not found");
            }
            else
            {
                FileMetadata m = {0};
                char last_reader[MAX_USERNAME] = "";
                int rc = fetch_stats_from_ss(file->metadata.filename, file->ss_index, &m, last_reader);
                if (rc == ERR_FILE_NOT_FOUND)
                {
                    // Remove from NM and report not found
                    pthread_mutex_lock(&file_mutex);
                    for (int i = 0; i < num_files; i++)
                    {
                        if (strcmp(files[i].metadata.filename, file->metadata.filename) == 0)
                        {
                            for (int j = i; j < num_files - 1; j++)
                                files[j] = files[j + 1];
                            num_files--;
                            break;
                        }
                    }
                    pthread_mutex_unlock(&file_mutex);
                    pthread_mutex_lock(&trie_mutex);
                    trie_delete(file_trie_root, file->metadata.filename);
                    pthread_mutex_unlock(&trie_mutex);
                    cache_clear();
                    // Persist the removal so metadata file no longer references
                    // the deleted file.
                    save_metadata();
                    response.error_code = ERR_FILE_NOT_FOUND;
                    snprintf(response.data, MAX_BUFFER, "File not found");
                    break;
                }
                // Build info string
                char result[MAX_BUFFER];
                char *created_s = format_time(m.created_time ? m.created_time : time(NULL));
                char *modified_s = format_time(m.modified_time ? m.modified_time : time(NULL));
                char *accessed_s = format_time(m.accessed_time ? m.accessed_time : time(NULL));
                snprintf(result, sizeof(result),
                         "File: %s\nOwner: %s\nCreated: %s\nLast Modified: %s\n"
                         "Size: %ld bytes\nLast Accessed: %s by %s\nAccess: ",
                         file->metadata.filename,
                         file->metadata.owner,
                         created_s, modified_s,
                         m.size,
                         accessed_s,
                         (last_reader[0] ? last_reader : file->metadata.owner));
                free(created_s);
                free(modified_s);
                free(accessed_s);
                strcat(result, file->metadata.owner);
                strcat(result, " (RW)");
                for (int i = 0; i < file->metadata.num_users; i++)
                {
                    strcat(result, ", ");
                    strcat(result, file->metadata.users[i].username);
                    strcat(result, " (");
                    strcat(result, file->metadata.users[i].access_type == ACCESS_WRITE ? "RW" : "R");
                    strcat(result, ")");
                }
                strncpy(response.data, result, MAX_BUFFER - 1);
            }
            break;
        }

        case MSG_ADD_ACCESS:
        {
            char *saveptr;
            char *token = strtok_r(msg.data, " ", &saveptr);
            int access_type = (token && strcmp(token, "-W") == 0) ? ACCESS_WRITE : ACCESS_READ;

            char *filename = strtok_r(NULL, " ", &saveptr);
            char *target_user = strtok_r(NULL, " ", &saveptr);

            if (!filename || !target_user)
            {
                response.error_code = ERR_INVALID_COMMAND;
                snprintf(response.data, MAX_BUFFER, "Invalid command format");
                break;
            }

            FileRecord *file = find_file(filename);
            if (!file)
            {
                response.error_code = ERR_FILE_NOT_FOUND;
                snprintf(response.data, MAX_BUFFER, "File not found");
            }
            else if (strcmp(file->metadata.owner, msg.username) != 0)
            {
                response.error_code = ERR_PERMISSION_DENIED;
                snprintf(response.data, MAX_BUFFER, "Only owner can modify access");
            }
            else
            {
                int found = 0;
                for (int i = 0; i < file->metadata.num_users; i++)
                {
                    if (strcmp(file->metadata.users[i].username, target_user) == 0)
                    {
                        file->metadata.users[i].access_type = access_type;
                        found = 1;
                        break;
                    }
                }

                if (!found && file->metadata.num_users < MAX_ACCESS_USERS)
                {
                    strncpy(file->metadata.users[file->metadata.num_users].username,
                            target_user, MAX_USERNAME - 1);
                    file->metadata.users[file->metadata.num_users].access_type = access_type;
                    file->metadata.num_users++;
                }

                save_metadata();
                snprintf(response.data, MAX_BUFFER, "Access granted successfully");
            }
            break;
        }

        case MSG_REM_ACCESS:
        {
            char *saveptr;
            char *filename = strtok_r(msg.data, " ", &saveptr);
            char *target_user = strtok_r(NULL, " ", &saveptr);

            if (!filename || !target_user)
            {
                response.error_code = ERR_INVALID_COMMAND;
                snprintf(response.data, MAX_BUFFER, "Invalid command format");
                break;
            }

            FileRecord *file = find_file(filename);
            if (!file)
            {
                response.error_code = ERR_FILE_NOT_FOUND;
                snprintf(response.data, MAX_BUFFER, "File not found");
            }
            else if (strcmp(file->metadata.owner, msg.username) != 0)
            {
                response.error_code = ERR_PERMISSION_DENIED;
                snprintf(response.data, MAX_BUFFER, "Only owner can modify access");
            }
            else
            {
                for (int i = 0; i < file->metadata.num_users; i++)
                {
                    if (strcmp(file->metadata.users[i].username, target_user) == 0)
                    {
                        for (int j = i; j < file->metadata.num_users - 1; j++)
                        {
                            file->metadata.users[j] = file->metadata.users[j + 1];
                        }
                        file->metadata.num_users--;
                        break;
                    }
                }
                save_metadata();
                snprintf(response.data, MAX_BUFFER, "Access removed successfully");
            }
            break;
        }

        case MSG_CREATE_FILE:
        {
            char *filename = msg.data;
            // Check if duplicate
            if (find_file(filename))
            {
                response.error_code = ERR_FILE_EXISTS;
                snprintf(response.data, MAX_BUFFER, "File already exists");
                break;
            }
            // Choose SS with least files
            pthread_mutex_lock(&ss_mutex);
            int min_files = MAX_FILES, target_ss = -1;
            for (int i = 0; i < num_ss; i++)
            {
                if (storage_servers[i].is_active && storage_servers[i].num_files < min_files)
                {
                    min_files = storage_servers[i].num_files;
                    target_ss = i;
                }
            }
            pthread_mutex_unlock(&ss_mutex);
            if (target_ss < 0)
            {
                response.error_code = ERR_SS_UNAVAILABLE;
                snprintf(response.data, MAX_BUFFER, "Storage server unavailable");
                break;
            }
            // Forward create to SS and wait for ACK
            Message ss_resp;
            int rc = ss_simple_request(target_ss, MSG_CREATE_FILE, filename, &ss_resp);
            if (rc != ERR_SUCCESS)
            {
                response.error_code = rc;
                snprintf(response.data, MAX_BUFFER, "%s", ss_resp.data[0] ? ss_resp.data : "Create failed");
                break;
            }
            // Update NM registry on success
            pthread_mutex_lock(&file_mutex);
            strncpy(files[num_files].metadata.filename, filename, MAX_FILENAME - 1);
            strncpy(files[num_files].metadata.owner, msg.username, MAX_USERNAME - 1);
            files[num_files].metadata.created_time = time(NULL);
            files[num_files].metadata.modified_time = time(NULL);
            files[num_files].metadata.accessed_time = time(NULL);
            files[num_files].metadata.size = 0;
            files[num_files].metadata.word_count = 0;
            files[num_files].metadata.char_count = 0;
            files[num_files].metadata.num_users = 0;
            files[num_files].ss_index = target_ss;
            pthread_mutex_lock(&trie_mutex);
            trie_insert(file_trie_root, filename, target_ss);
            pthread_mutex_unlock(&trie_mutex);
            num_files++;
            pthread_mutex_unlock(&file_mutex);
            cache_clear();
            pthread_mutex_lock(&ss_mutex);
            strncpy(storage_servers[target_ss].files[storage_servers[target_ss].num_files], filename, MAX_FILENAME - 1);
            storage_servers[target_ss].num_files++;
            pthread_mutex_unlock(&ss_mutex);
            save_metadata();
            snprintf(response.data, MAX_BUFFER, "Created");
            break;
        }

        case MSG_DELETE_FILE:
        {
            char *filename = msg.data;
            FileRecord *file = find_file(filename);
            if (!file)
            {
                response.error_code = ERR_FILE_NOT_FOUND;
                snprintf(response.data, MAX_BUFFER, "File not found");
                break;
            }
            // Permissions: owner or write access
            if (!check_access(file, msg.username, ACCESS_WRITE))
            {
                response.error_code = ERR_PERMISSION_DENIED;
                snprintf(response.data, MAX_BUFFER, "Write permission required");
                break;
            }
            int ss_idx = file->ss_index;
            Message ss_resp;
            int rc = ss_simple_request(ss_idx, MSG_DELETE_FILE, filename, &ss_resp);
            if (rc != ERR_SUCCESS)
            {
                response.error_code = rc;
                snprintf(response.data, MAX_BUFFER, "%s", ss_resp.data[0] ? ss_resp.data : "Delete failed");
                break;
            }
            // Update NM registry
            pthread_mutex_lock(&file_mutex);
            for (int i = 0; i < num_files; i++)
            {
                if (strcmp(files[i].metadata.filename, filename) == 0)
                {
                    for (int j = i; j < num_files - 1; j++)
                        files[j] = files[j + 1];
                    num_files--;
                    break;
                }
            }
            pthread_mutex_unlock(&file_mutex);
            pthread_mutex_lock(&trie_mutex);
            trie_delete(file_trie_root, filename);
            pthread_mutex_unlock(&trie_mutex);
            cache_clear();
            pthread_mutex_lock(&ss_mutex);
            if (ss_idx >= 0 && ss_idx < num_ss && storage_servers[ss_idx].num_files > 0)
            {
                storage_servers[ss_idx].num_files--; // Approximate
            }
            pthread_mutex_unlock(&ss_mutex);
            save_metadata();
            snprintf(response.data, MAX_BUFFER, "Deleted");
            break;
        }
        case MSG_READ_FILE:
        case MSG_WRITE_FILE:
        case MSG_STREAM_FILE:
        case MSG_UNDO:
        {
            // Forward to storage server
            char *filename = msg.data;
            {
                char dbg[MAX_BUFFER];
                snprintf(dbg, sizeof(dbg), "Forwarding op %d for file '%s' from user '%s'", msg.msg_type, filename, msg.username);
                log_message("NM", dbg);
            }

            // Validate existence and access first using NM registry
            FileRecord *file = find_file(filename);
            if (!file)
            {
                response.error_code = ERR_FILE_NOT_FOUND;
                snprintf(response.data, MAX_BUFFER, "File not found");
                break;
            }
            if (msg.msg_type == MSG_WRITE_FILE || msg.msg_type == MSG_UNDO)
            {
                if (!check_access(file, msg.username, ACCESS_WRITE))
                {
                    response.error_code = ERR_PERMISSION_DENIED;
                    snprintf(response.data, MAX_BUFFER, "Write permission required");
                    break;
                }
            }
            else
            {
                if (!check_access(file, msg.username, ACCESS_READ))
                {
                    response.error_code = ERR_PERMISSION_DENIED;
                    snprintf(response.data, MAX_BUFFER, "Read permission required");
                    break;
                }
            }

            // Resolve storage server index preferring registry, fallback to trie
            int ss_idx = file->ss_index;
            if (ss_idx < 0 || ss_idx >= num_ss || !storage_servers[ss_idx].is_active)
            {
                pthread_mutex_lock(&trie_mutex);
                ss_idx = trie_search(file_trie_root, filename);
                pthread_mutex_unlock(&trie_mutex);
            }

            if (ss_idx < 0 || ss_idx >= num_ss || !storage_servers[ss_idx].is_active)
            {
                response.error_code = ERR_SS_UNAVAILABLE;
                snprintf(response.data, MAX_BUFFER, "Storage server unavailable");
                break;
            }

            // Send SS endpoint to client
            snprintf(response.data, MAX_BUFFER, "%s %d",
                     storage_servers[ss_idx].ip,
                     storage_servers[ss_idx].client_port);
            {
                char dbg[MAX_BUFFER];
                snprintf(dbg, sizeof(dbg), "Selected SS %s:%d for file '%s'", storage_servers[ss_idx].ip, storage_servers[ss_idx].client_port, filename);
                log_message("NM", dbg);
            }
            break;
        }

        case MSG_EXEC_FILE:
        {
            // NM handles execution: fetch content from SS, execute here, return output
            char *filename = msg.data;
            FileRecord *file = find_file(filename);
            if (!file)
            {
                response.error_code = ERR_FILE_NOT_FOUND;
                snprintf(response.data, MAX_BUFFER, "File not found");
                break;
            }
            // Enforce read access for EXEC as per spec
            if (!check_access(file, msg.username, ACCESS_READ))
            {
                response.error_code = ERR_PERMISSION_DENIED;
                snprintf(response.data, MAX_BUFFER, "Read permission required");
                break;
            }
            int ss_idx = file->ss_index;
            Message ss_resp;
            int rc = ss_simple_request(ss_idx, MSG_EXEC_FILE, filename, &ss_resp);
            if (rc != ERR_SUCCESS)
            {
                response.error_code = rc;
                snprintf(response.data, MAX_BUFFER, "%s", ss_resp.data[0] ? ss_resp.data : "Exec fetch failed");
                break;
            }
            // Execute the content as shell commands safely
            FILE *fp = popen(ss_resp.data, "r");
            if (!fp)
            {
                response.error_code = ERR_INTERNAL_ERROR;
                snprintf(response.data, MAX_BUFFER, "Failed to execute commands");
                break;
            }
            char outbuf[4096];
            outbuf[0] = '\0';
            char line[512];
            while (fgets(line, sizeof(line), fp))
            {
                if (strlen(outbuf) + strlen(line) + 1 < MAX_BUFFER)
                    strcat(outbuf, line);
            }
            pclose(fp);
            strncpy(response.data, outbuf, MAX_BUFFER - 1);
            break;
        }

        default:
            response.error_code = ERR_INVALID_COMMAND;
            snprintf(response.data, MAX_BUFFER, "Invalid command");
            break;
        }

        {
            char dbg[MAX_BUFFER];
            snprintf(dbg, sizeof(dbg), "About to send response for op=%d, error_code=%d, data='%s'", msg.msg_type, response.error_code, response.data);
            log_message("NM", dbg);
        }
        if (send_message(client_sock, &response) < 0)
        {
            // Network error sending response; stop servicing this client
            char errbuf[256];
            snprintf(errbuf, sizeof(errbuf), "send_message failed while responding to %s:%d", client_ip, ntohs(addr.sin_port));
            log_error("NM", "send_message", ERR_NETWORK_ERROR, errbuf);
            break;
        }

        char log_buf[MAX_BUFFER];
        snprintf(log_buf, sizeof(log_buf), "Response sent: error_code=%d", response.error_code);
        log_message("NM", log_buf);

        // Wait for next message from the same client; if recv fails, close connection
        if (receive_message(client_sock, &msg) < 0)
        {
            break;
        }
    }

    close(client_sock);
    return NULL;
}
