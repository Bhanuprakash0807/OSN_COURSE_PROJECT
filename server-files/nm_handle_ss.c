#include "../common.h"
#include "nameserver.h"
#include <sys/time.h>
#include <signal.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <netinet/tcp.h>
#include <unistd.h>

void *handle_storage_server(void *arg)
{
    int ss_sock = *(int *)arg;
    free(arg);

    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);
    getpeername(ss_sock, (struct sockaddr *)&addr, &addr_len);
    char ss_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &addr.sin_addr, ss_ip, INET_ADDRSTRLEN);

    Message msg;
    if (receive_message(ss_sock, &msg) < 0)
    {
        close(ss_sock);
        return NULL;
    }

    if (msg.msg_type == MSG_REGISTER_SS)
    {
        pthread_mutex_lock(&ss_mutex);
        int ss_idx = num_ss;

        strncpy(storage_servers[ss_idx].ip, ss_ip, INET_ADDRSTRLEN - 1);
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
        send_message(ss_sock, &response);
    }

    close(ss_sock);
    return NULL;
}
