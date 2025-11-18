#include "../common.h"
#include "client.h"
#include <sys/time.h>
#include <netinet/tcp.h>
#include <unistd.h>
#include <signal.h>

void handle_exec(char *filename)
{
    int sock = connect_to_nm();
    if (sock < 0)
    {
        printf("ERROR: Failed to connect to name server\n");
        return;
    }

    Message msg, response;
    memset(&msg, 0, sizeof(msg));
    msg.msg_type = MSG_EXEC_FILE;
    strncpy(msg.username, username, MAX_USERNAME - 1);
    strncpy(msg.data, filename, MAX_BUFFER - 1);

    send_message(sock, &msg);
    receive_message(sock, &response);
    if (response.error_code == ERR_SUCCESS)
    {
        // Output produced by NM execution
        printf("%s", response.data);
    }
    else
    {
        printf("ERROR: %s\n", response.data);
    }

    close(sock);
}
