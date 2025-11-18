#include "../common.h"
#include "client.h"
#include <sys/time.h>
#include <netinet/tcp.h>
#include <unistd.h>
#include <signal.h>

void handle_addaccess(char *args)
{
    int sock = connect_to_nm();
    if (sock < 0)
    {
        printf("ERROR: Failed to connect to name server\n");
        return;
    }

    Message msg, response;
    memset(&msg, 0, sizeof(msg));
    msg.msg_type = MSG_ADD_ACCESS;
    strncpy(msg.username, username, MAX_USERNAME - 1);
    strncpy(msg.data, args, MAX_BUFFER - 1);

    send_message(sock, &msg);
    receive_message(sock, &response);

    if (response.error_code == ERR_SUCCESS)
    {
        printf("Access granted successfully!\n");
    }
    else
    {
        printf("ERROR: %s\n", response.data);
    }

    close(sock);
}

void handle_remaccess(char *args)
{
    int sock = connect_to_nm();
    if (sock < 0)
    {
        printf("ERROR: Failed to connect to name server\n");
        return;
    }

    Message msg, response;
    memset(&msg, 0, sizeof(msg));
    msg.msg_type = MSG_REM_ACCESS;
    strncpy(msg.username, username, MAX_USERNAME - 1);
    strncpy(msg.data, args, MAX_BUFFER - 1);

    send_message(sock, &msg);
    receive_message(sock, &response);

    if (response.error_code == ERR_SUCCESS)
    {
        printf("Access removed successfully!\n");
    }
    else
    {
        printf("ERROR: %s\n", response.data);
    }

    close(sock);
}
