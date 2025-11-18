#include "../common.h"
#include "nameserver.h"
#include <sys/time.h>
#include <signal.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <netinet/tcp.h>
#include <unistd.h>

// Fetch live stats for a file from its storage server; update metadata if out is non-NULL
int fetch_stats_from_ss(const char *filename, int ss_idx, FileMetadata *out, char *last_reader_out)
{
    if (ss_idx < 0 || ss_idx >= num_ss || !storage_servers[ss_idx].is_active)
        return -1;
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0)
        return -1;
    struct timeval tv;
    tv.tv_sec = 5;
    tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(storage_servers[ss_idx].client_port);
    inet_pton(AF_INET, storage_servers[ss_idx].ip, &addr.sin_addr);
    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    {
        close(sock);
        return -1;
    }
    Message req, resp;
    memset(&req, 0, sizeof(req));
    req.msg_type = MSG_SS_INFO;
    strncpy(req.data, filename, MAX_BUFFER - 1);
    send_message(sock, &req);
    if (receive_message(sock, &resp) < 0)
    {
        close(sock);
        return -1;
    }
    close(sock);
    if (resp.error_code != ERR_SUCCESS)
        return resp.error_code == ERR_FILE_NOT_FOUND ? ERR_FILE_NOT_FOUND : -1;
    // Response from SS may include filename and owner lines first.
    // Skip up to two leading lines (filename, owner) then parse:
    // size words chars accessed modified created [last_reader]
    long size = 0, words = 0, chars = 0, acc = 0, mod = 0, crt = 0;
    char last_reader[MAX_USERNAME] = "";
    char *p = resp.data;
    // Skip first line (filename)
    char *nl = strchr(p, '\n');
    if (nl)
        p = nl + 1;
    // Skip second line (owner)
    nl = strchr(p, '\n');
    if (nl)
        p = nl + 1;

    int n = sscanf(p, "%ld %ld %ld %ld %ld %ld %63s",
                   &size, &words, &chars, &acc, &mod, &crt, last_reader);
    if (n < 6)
        return -1;
    if (out)
    {
        out->size = size;
        out->word_count = (int)words;
        out->char_count = (int)chars;
        out->accessed_time = (time_t)acc;
        out->modified_time = (time_t)mod;
        out->created_time = (time_t)crt;
    }
    if (last_reader_out && n == 7)
    {
        strncpy(last_reader_out, last_reader, MAX_USERNAME - 1);
        last_reader_out[MAX_USERNAME - 1] = '\0';
    }
    return 0;
}

// Forward a simple file command (CREATE/DELETE/EXEC helper) to SS and return response
int ss_simple_request(int ss_idx, int msg_type, const char *filename, Message *out_resp)
{
    if (ss_idx < 0 || ss_idx >= num_ss || !storage_servers[ss_idx].is_active)
        return ERR_SS_UNAVAILABLE;
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0)
        return ERR_NETWORK_ERROR;
    struct timeval tv;
    tv.tv_sec = 5;
    tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(storage_servers[ss_idx].client_port);
    inet_pton(AF_INET, storage_servers[ss_idx].ip, &addr.sin_addr);
    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    {
        close(sock);
        return ERR_NETWORK_ERROR;
    }
    Message req, resp;
    memset(&req, 0, sizeof(req));
    req.msg_type = msg_type;
    strncpy(req.data, filename, MAX_BUFFER - 1);
    send_message(sock, &req);
    if (receive_message(sock, &resp) < 0)
    {
        close(sock);
        return ERR_NETWORK_ERROR;
    }
    close(sock);
    if (out_resp)
        *out_resp = resp;
    return resp.error_code;
}
