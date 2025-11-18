#include "../common.h"
#include "client.h"
#include <sys/time.h>
#include <netinet/tcp.h>
#include <unistd.h>
#include <signal.h>

void handle_create(char *filename)
{
    int sock = connect_to_nm();
    if (sock < 0)
    {
        printf("ERROR: Failed to connect to name server\n");
        return;
    }

    Message msg, response;
    memset(&msg, 0, sizeof(msg));
    msg.msg_type = MSG_CREATE_FILE;
    strncpy(msg.username, username, MAX_USERNAME - 1);
    strncpy(msg.data, filename, MAX_BUFFER - 1);

    send_message(sock, &msg);
    if (receive_message(sock, &response) < 0)
    {
        printf("ERROR: Failed to receive response from name server\n");
        close(sock);
        return;
    }
    if (response.error_code == ERR_SUCCESS)
    {
        printf("File Created Successfully!\n");
    }
    else
    {
        printf("ERROR: %s\n", response.data);
    }

    close(sock);
}

void handle_write(char *filename, char *sent_num_str)
{
    int sent_num = atoi(sent_num_str);

    printf("Enter updates (format: <word_index> <content>), type ETIRW to finish:\n");

    char updates[MAX_BUFFER] = "";
    char line[512];

    while (1)
    {
        if (!fgets(line, sizeof(line), stdin))
            break;

        // Remove newline
        line[strcspn(line, "\n")] = 0;

        if (strcmp(line, "ETIRW") == 0)
        {
            break;
        }

        if (strlen(updates) > 0)
        {
            strcat(updates, ";");
        }
        strcat(updates, line);
    }

    int sock = connect_to_nm();
    if (sock < 0)
    {
        printf("ERROR: Failed to connect to name server\n");
        return;
    }

    Message msg, response;
    memset(&msg, 0, sizeof(msg));
    msg.msg_type = MSG_WRITE_FILE;
    strncpy(msg.username, username, MAX_USERNAME - 1);
    strncpy(msg.data, filename, MAX_BUFFER - 1);

    send_message(sock, &msg);
    if (receive_message(sock, &response) < 0)
    {
        printf("ERROR: Failed to receive response from name server\n");
        close(sock);
        return;
    }
    close(sock);

    if (response.error_code != ERR_SUCCESS)
    {
        printf("ERROR: %s\n", response.data);
        return;
    }

    char ss_ip[INET_ADDRSTRLEN];
    int ss_port;
    sscanf(response.data, "%s %d", ss_ip, &ss_port);

    int ss_sock = connect_to_ss(ss_ip, ss_port);
    if (ss_sock < 0)
    {
        printf("ERROR: Failed to connect to storage server\n");
        return;
    }

    memset(&msg, 0, sizeof(msg));
    msg.msg_type = MSG_WRITE_FILE;
    strncpy(msg.username, username, MAX_USERNAME - 1);
    snprintf(msg.data, MAX_BUFFER, "%s|%d|%s", filename, sent_num, updates);

    send_message(ss_sock, &msg);
    if (receive_message(ss_sock, &response) < 0)
    {
        printf("ERROR: Failed to receive response from storage server\n");
        close(ss_sock);
        return;
    }

    if (response.error_code == ERR_SUCCESS)
    {
        printf("Write Successful!\n");
    }
    else
    {
        printf("ERROR: %s\n", response.data);
    }

    close(ss_sock);
}
