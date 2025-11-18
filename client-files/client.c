#include "../common.h"
#include "client.h"
#include <sys/time.h>
#include <netinet/tcp.h>
#include <unistd.h>
#include <signal.h>

char username[MAX_USERNAME];
char nm_ip[INET_ADDRSTRLEN];
int nm_port;


int main(int argc, char *argv[])
{
    if (argc != 3)
    {
        printf("Usage: %s <nm_ip> <nm_port>\n", argv[0]);
        return 1;
    }

    strncpy(nm_ip, argv[1], INET_ADDRSTRLEN - 1);
    nm_port = atoi(argv[2]);

    // Set up signal handler for SIGPIPE
    signal(SIGPIPE, SIG_IGN);

    printf("Enter username: ");
    if (!fgets(username, sizeof(username), stdin))
    {
        printf("ERROR: Failed to read username\n");
        return 1;
    }
    username[strcspn(username, "\n")] = 0;

    if (strlen(username) == 0)
    {
        printf("ERROR: Username cannot be empty\n");
        return 1;
    }

    // Register with name server
    int sock = connect_to_nm();
    if (sock < 0)
    {
        printf("ERROR: Failed to connect to name server\n");
        return 1;
    }

    Message msg, response;
    memset(&msg, 0, sizeof(msg));
    msg.msg_type = MSG_REGISTER_CLIENT;
    strncpy(msg.username, username, MAX_USERNAME - 1);

    send_message(sock, &msg);
    receive_message(sock, &response);
    close(sock);

    if (response.error_code != ERR_SUCCESS)
    {
        printf("ERROR: Failed to register\n");
        return 1;
    }

    printf("Welcome %s! Type 'help' for commands.\n\n", username);

    char command_history[10][MAX_BUFFER]; // Keep track of last 10 commands
    int history_index = 0;
    int history_count = 0;

    char input[MAX_BUFFER];
    while (1)
    {
        printf("> ");
        if (!fgets(input, sizeof(input), stdin))
            break;

        input[strcspn(input, "\n")] = 0;

        if (strlen(input) == 0)
            continue;

        // Add command to history
        strncpy(command_history[history_index], input, MAX_BUFFER - 1);
        history_index = (history_index + 1) % 10;
        if (history_count < 10)
            history_count++;

        char *cmd = strtok(input, " ");
        if (!cmd)
            continue;

        if (strcmp(cmd, "VIEW") == 0)
        {
            char *args = strtok(NULL, "");
            handle_view(args);
        }
        else if (strcmp(cmd, "READ") == 0)
        {
            char *filename = strtok(NULL, " ");
            if (filename)
                handle_read(filename);
            else
                printf("ERROR: Missing filename\n");
        }
        else if (strcmp(cmd, "CREATE") == 0)
        {
            char *filename = strtok(NULL, " ");
            if (filename)
                handle_create(filename);
            else
                printf("ERROR: Missing filename\n");
        }
        else if (strcmp(cmd, "WRITE") == 0)
        {
            char *filename = strtok(NULL, " ");
            char *sent_num = strtok(NULL, " ");
            if (filename && sent_num)
                handle_write(filename, sent_num);
            else
                printf("ERROR: Missing arguments\n");
        }
        else if (strcmp(cmd, "UNDO") == 0)
        {
            char *filename = strtok(NULL, " ");
            if (filename)
                handle_undo(filename);
            else
                printf("ERROR: Missing filename\n");
        }
        else if (strcmp(cmd, "INFO") == 0)
        {
            char *filename = strtok(NULL, " ");
            if (filename)
                handle_info(filename);
            else
                printf("ERROR: Missing filename\n");
        }
        else if (strcmp(cmd, "DELETE") == 0)
        {
            char *filename = strtok(NULL, " ");
            if (filename)
                handle_delete(filename);
            else
                printf("ERROR: Missing filename\n");
        }
        else if (strcmp(cmd, "STREAM") == 0)
        {
            char *filename = strtok(NULL, " ");
            if (filename)
                handle_stream(filename);
            else
                printf("ERROR: Missing filename\n");
        }
        else if (strcmp(cmd, "LIST") == 0)
        {
            handle_list();
        }
        else if (strcmp(cmd, "ADDACCESS") == 0)
        {
            char *args = strtok(NULL, "");
            if (args)
                handle_addaccess(args);
            else
                printf("ERROR: Missing arguments\n");
        }
        else if (strcmp(cmd, "REMACCESS") == 0)
        {
            char *args = strtok(NULL, "");
            if (args)
                handle_remaccess(args);
            else
                printf("ERROR: Missing arguments\n");
        }
        else if (strcmp(cmd, "EXEC") == 0)
        {
            char *filename = strtok(NULL, " ");
            if (filename)
                handle_exec(filename);
            else
                printf("ERROR: Missing filename\n");
        }
        else if (strcmp(cmd, "RESCAN") == 0)
        {
            char *target = strtok(NULL, " ");
            if (!target)
            {
                printf("ERROR: Missing target (ip or ALL)\n");
            }
            else
            {
                int sock = connect_to_nm();
                if (sock < 0)
                {
                    printf("ERROR: Failed to connect to name server\n");
                }
                else
                {
                    Message msg, response;
                    memset(&msg, 0, sizeof(msg));
                    msg.msg_type = MSG_SS_RESCAN;
                    strncpy(msg.username, username, MAX_USERNAME - 1);
                    strncpy(msg.data, target, MAX_BUFFER - 1);
                    send_message(sock, &msg);
                    if (receive_message(sock, &response) < 0)
                    {
                        printf("ERROR: Failed to receive response from name server\n");
                    }
                    else
                    {
                        if (response.error_code == ERR_SUCCESS)
                            printf("%s\n", response.data);
                        else
                            printf("ERROR: %s\n", response.data);
                    }
                    close(sock);
                }
            }
        }
        else if (strcmp(cmd, "exit") == 0 || strcmp(cmd, "quit") == 0)
        {
            break;
        }
        else if (strcmp(cmd, "help") == 0)
        {
            printf("Commands:\n");
            printf("  VIEW [-a] [-l] [-al]  - View files\n");
            printf("  READ <file>           - Read file\n");
            printf("  CREATE <file>         - Create file\n");
            printf("  WRITE <file> <sent#>  - Write to file\n");
            printf("  UNDO <file>           - Undo last change\n");
            printf("  INFO <file>           - Get file info\n");
            printf("  DELETE <file>         - Delete file\n");
            printf("  STREAM <file>         - Stream file\n");
            printf("  LIST                  - List users\n");
            printf("  ADDACCESS -R/-W <file> <user> - Add access\n");
            printf("  REMACCESS <file> <user> - Remove access\n");
            printf("  EXEC <file>           - Execute file\n");
            printf("  RESCAN <ip|ALL>       - Ask NM to request SS to rescan storage (ip or ALL)\n");
            printf("  exit/quit             - Exit\n");
        }
        else
        {
            printf("ERROR: Unknown command. Type 'help' for commands.\n");
        }
    }

    return 0;
}