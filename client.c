#include "common.h"
#include <sys/time.h>
#include <netinet/tcp.h>
#include <unistd.h>
#include <signal.h>

char username[MAX_USERNAME];
char nm_ip[INET_ADDRSTRLEN];
int nm_port;

int connect_to_nm() {
    int retry_count = 0;
    const int max_retries = 3;
    int sock;

    while (retry_count < max_retries) {
        sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) {
            perror("socket");
            sleep(1);
            retry_count++;
            continue;
        }
        
        // Set socket options
        struct timeval tv;
        tv.tv_sec = 5;  // 5 second timeout
        tv.tv_usec = 0;
        if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0 ||
            setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) < 0) {
            perror("setsockopt timeout");
            close(sock);
            sleep(1);
            retry_count++;
            continue;
        }
        
        int opt = 1;
        if (setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, &opt, sizeof(opt)) < 0) {
            perror("setsockopt keepalive");
            close(sock);
            sleep(1);
            retry_count++;
            continue;
        }

        // Set TCP keepalive parameters
        int keepalive_time = 10;  // Start sending keepalive after 10 seconds of idle
        int keepalive_intvl = 5;  // Send keepalive every 5 seconds
        int keepalive_probes = 3;  // Drop connection after 3 failed probes
        
        if (setsockopt(sock, IPPROTO_TCP, TCP_KEEPIDLE, &keepalive_time, sizeof(keepalive_time)) < 0 ||
            setsockopt(sock, IPPROTO_TCP, TCP_KEEPINTVL, &keepalive_intvl, sizeof(keepalive_intvl)) < 0 ||
            setsockopt(sock, IPPROTO_TCP, TCP_KEEPCNT, &keepalive_probes, sizeof(keepalive_probes)) < 0) {
            perror("setsockopt TCP keepalive");
            close(sock);
            sleep(1);
            retry_count++;
            continue;
        }
        
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(nm_port);
        if (inet_pton(AF_INET, nm_ip, &addr.sin_addr) <= 0) {
            perror("inet_pton");
            close(sock);
            sleep(1);
            retry_count++;
            continue;
        }
        
        if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
            perror("connect");
            close(sock);
            sleep(1);
            retry_count++;
            continue;
        }
        
        return sock;
    }
    
    printf("ERROR: Failed to connect to nameserver after %d retries\n", max_retries);
    return -1;
}

int connect_to_ss(const char *ip, int port) {
    int retry_count = 0;
    const int max_retries = 3;
    int sock;
    
    while (retry_count < max_retries) {
        sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) {
            perror("socket");
            sleep(1);
            retry_count++;
            continue;
        }
        
        // Set socket options for timeouts
        struct timeval tv;
        tv.tv_sec = 5;  // 5 second timeout
        tv.tv_usec = 0;
        if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0 ||
            setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) < 0) {
            perror("setsockopt timeout");
            close(sock);
            sleep(1);
            retry_count++;
            continue;
        }
        
        // Enable TCP keepalive
        int opt = 1;
        if (setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, &opt, sizeof(opt)) < 0) {
            perror("setsockopt keepalive");
            close(sock);
            sleep(1);
            retry_count++;
            continue;
        }
        
        // Set TCP keepalive parameters
        int keepalive_time = 10;  // Start sending keepalive after 10 seconds of idle
        int keepalive_intvl = 5;  // Send keepalive every 5 seconds
        int keepalive_probes = 3;  // Drop connection after 3 failed probes
        
        if (setsockopt(sock, IPPROTO_TCP, TCP_KEEPIDLE, &keepalive_time, sizeof(keepalive_time)) < 0 ||
            setsockopt(sock, IPPROTO_TCP, TCP_KEEPINTVL, &keepalive_intvl, sizeof(keepalive_intvl)) < 0 ||
            setsockopt(sock, IPPROTO_TCP, TCP_KEEPCNT, &keepalive_probes, sizeof(keepalive_probes)) < 0) {
            perror("setsockopt TCP keepalive");
            close(sock);
            sleep(1);
            retry_count++;
            continue;
        }
        
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        if (inet_pton(AF_INET, ip, &addr.sin_addr) <= 0) {
            perror("inet_pton");
            close(sock);
            sleep(1);
            retry_count++;
            continue;
        }
        
        if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
            perror("connect");
            close(sock);
            sleep(1);
            retry_count++;
            continue;
        }
        
        return sock;
    }
    
    printf("ERROR: Failed to connect to storage server after %d retries\n", max_retries);
    return -1;
}

void handle_view(char *args) {
    int sock = connect_to_nm();
    if (sock < 0) {
        printf("ERROR: Failed to connect to name server\n");
        return;
    }
    
    Message msg, response;
    memset(&msg, 0, sizeof(msg));
    msg.msg_type = MSG_VIEW_FILES;
    strncpy(msg.username, username, MAX_USERNAME - 1);
    strncpy(msg.data, args ? args : "", MAX_BUFFER - 1);
    
    send_message(sock, &msg);
    if (receive_message(sock, &response) < 0) {
        printf("ERROR: Failed to receive response from name server\n");
        close(sock);
        return;
    }
    
    if (response.error_code == ERR_SUCCESS) {
        printf("%s", response.data);
    } else {
        printf("ERROR: %s\n", response.data);
    }
    
    close(sock);
}

void handle_read(char *filename) {
    int sock = connect_to_nm();
    if (sock < 0) {
        printf("ERROR: Failed to connect to name server\n");
        return;
    }
    
    Message msg, response;
    memset(&msg, 0, sizeof(msg));
    msg.msg_type = MSG_READ_FILE;
    strncpy(msg.username, username, MAX_USERNAME - 1);
    strncpy(msg.data, filename, MAX_BUFFER - 1);
    
    send_message(sock, &msg);
    if (receive_message(sock, &response) < 0) {
        printf("ERROR: Failed to receive response from name server\n");
        close(sock);
        return;
    }
    close(sock);
    
    if (response.error_code != ERR_SUCCESS) {
        printf("ERROR: %s\n", response.data);
        return;
    }
    
    char ss_ip[INET_ADDRSTRLEN];
    int ss_port;
    sscanf(response.data, "%s %d", ss_ip, &ss_port);
    
    int ss_sock = connect_to_ss(ss_ip, ss_port);
    if (ss_sock < 0) {
        printf("ERROR: Failed to connect to storage server\n");
        return;
    }
    
    memset(&msg, 0, sizeof(msg));
    msg.msg_type = MSG_READ_FILE;
    strncpy(msg.username, username, MAX_USERNAME - 1);
    strncpy(msg.data, filename, MAX_BUFFER - 1);
    
    send_message(ss_sock, &msg);
    if (receive_message(ss_sock, &response) < 0) {
        printf("ERROR: Failed to receive response from storage server\n");
        close(ss_sock);
        return;
    }
    
    if (response.error_code == ERR_SUCCESS) {
        printf("%s\n", response.data);
    } else {
        printf("ERROR: %s\n", response.data);
    }
    
    close(ss_sock);
}

void handle_create(char *filename) {
    int sock = connect_to_nm();
    if (sock < 0) {
        printf("ERROR: Failed to connect to name server\n");
        return;
    }
    
    Message msg, response;
    memset(&msg, 0, sizeof(msg));
    msg.msg_type = MSG_CREATE_FILE;
    strncpy(msg.username, username, MAX_USERNAME - 1);
    strncpy(msg.data, filename, MAX_BUFFER - 1);
    
    send_message(sock, &msg);
    if (receive_message(sock, &response) < 0) {
        printf("ERROR: Failed to receive response from name server\n");
        close(sock);
        return;
    }
    if (response.error_code == ERR_SUCCESS) {
        printf("File Created Successfully!\n");
    } else {
        printf("ERROR: %s\n", response.data);
    }
    
    close(sock);
}

void handle_write(char *filename, char *sent_num_str) {
    int sent_num = atoi(sent_num_str);
    
    printf("Enter updates (format: <word_index> <content>), type ETIRW to finish:\n");
    
    char updates[MAX_BUFFER] = "";
    char line[512];
    
    while (1) {
        if (!fgets(line, sizeof(line), stdin)) break;
        
        // Remove newline
        line[strcspn(line, "\n")] = 0;
        
        if (strcmp(line, "ETIRW") == 0) {
            break;
        }
        
        if (strlen(updates) > 0) {
            strcat(updates, ";");
        }
        strcat(updates, line);
    }
    
    int sock = connect_to_nm();
    if (sock < 0) {
        printf("ERROR: Failed to connect to name server\n");
        return;
    }
    
    Message msg, response;
    memset(&msg, 0, sizeof(msg));
    msg.msg_type = MSG_WRITE_FILE;
    strncpy(msg.username, username, MAX_USERNAME - 1);
    strncpy(msg.data, filename, MAX_BUFFER - 1);
    
    send_message(sock, &msg);
    if (receive_message(sock, &response) < 0) {
        printf("ERROR: Failed to receive response from name server\n");
        close(sock);
        return;
    }
    close(sock);
    
    if (response.error_code != ERR_SUCCESS) {
        printf("ERROR: %s\n", response.data);
        return;
    }
    
    char ss_ip[INET_ADDRSTRLEN];
    int ss_port;
    sscanf(response.data, "%s %d", ss_ip, &ss_port);
    
    int ss_sock = connect_to_ss(ss_ip, ss_port);
    if (ss_sock < 0) {
        printf("ERROR: Failed to connect to storage server\n");
        return;
    }
    
    memset(&msg, 0, sizeof(msg));
    msg.msg_type = MSG_WRITE_FILE;
    strncpy(msg.username, username, MAX_USERNAME - 1);
    snprintf(msg.data, MAX_BUFFER, "%s|%d|%s", filename, sent_num, updates);
    
    send_message(ss_sock, &msg);
    if (receive_message(ss_sock, &response) < 0) {
        printf("ERROR: Failed to receive response from storage server\n");
        close(ss_sock);
        return;
    }
    
    if (response.error_code == ERR_SUCCESS) {
        printf("Write Successful!\n");
    } else {
        printf("ERROR: %s\n", response.data);
    }
    
    close(ss_sock);
}

void handle_undo(char *filename) {
    int sock = connect_to_nm();
    if (sock < 0) {
        printf("ERROR: Failed to connect to name server\n");
        return;
    }
    
    Message msg, response;
    memset(&msg, 0, sizeof(msg));
    msg.msg_type = MSG_UNDO;
    strncpy(msg.username, username, MAX_USERNAME - 1);
    strncpy(msg.data, filename, MAX_BUFFER - 1);
    
    send_message(sock, &msg);
    if (receive_message(sock, &response) < 0) {
        printf("ERROR: Failed to receive response from name server\n");
        close(sock);
        return;
    }
    close(sock);
    
    if (response.error_code != ERR_SUCCESS) {
        printf("ERROR: %s\n", response.data);
        return;
    }
    
    char ss_ip[INET_ADDRSTRLEN];
    int ss_port;
    sscanf(response.data, "%s %d", ss_ip, &ss_port);
    
    int ss_sock = connect_to_ss(ss_ip, ss_port);
    if (ss_sock < 0) {
        printf("ERROR: Failed to connect to storage server\n");
        return;
    }
    
    memset(&msg, 0, sizeof(msg));
    msg.msg_type = MSG_UNDO;
    strncpy(msg.username, username, MAX_USERNAME - 1);
    strncpy(msg.data, filename, MAX_BUFFER - 1);
    
    send_message(ss_sock, &msg);
    if (receive_message(ss_sock, &response) < 0) {
        printf("ERROR: Failed to receive response from storage server\n");
        close(ss_sock);
        return;
    }
    
    if (response.error_code == ERR_SUCCESS) {
        printf("Undo Successful!\n");
    } else {
        printf("ERROR: %s\n", response.data);
    }
    
    close(ss_sock);
}

void handle_info(char *filename) {
    int sock = connect_to_nm();
    if (sock < 0) {
        printf("ERROR: Failed to connect to name server\n");
        return;
    }
    
    Message msg, response;
    memset(&msg, 0, sizeof(msg));
    msg.msg_type = MSG_INFO_FILE;
    strncpy(msg.username, username, MAX_USERNAME - 1);
    strncpy(msg.data, filename, MAX_BUFFER - 1);
    
    send_message(sock, &msg);
    if (receive_message(sock, &response) < 0) {
        printf("ERROR: Failed to receive response from name server\n");
        close(sock);
        return;
    }
    
    if (response.error_code == ERR_SUCCESS) {
        printf("%s\n", response.data);
    } else {
        printf("ERROR: %s\n", response.data);
    }
    
    close(sock);
}

void handle_delete(char *filename) {
    int sock = connect_to_nm();
    if (sock < 0) {
        printf("ERROR: Failed to connect to name server\n");
        return;
    }
    
    Message msg, response;
    memset(&msg, 0, sizeof(msg));
    msg.msg_type = MSG_DELETE_FILE;
    strncpy(msg.username, username, MAX_USERNAME - 1);
    strncpy(msg.data, filename, MAX_BUFFER - 1);
    
    send_message(sock, &msg);
    if (receive_message(sock, &response) < 0) {
        printf("ERROR: Failed to receive response from name server\n");
        close(sock);
        return;
    }
    if (response.error_code == ERR_SUCCESS) {
        printf("File '%s' deleted successfully!\n", filename);
    } else {
        printf("ERROR: %s\n", response.data);
    }
    
    close(sock);
}

void handle_stream(char *filename) {
    int sock = connect_to_nm();
    if (sock < 0) {
        printf("ERROR: Failed to connect to name server\n");
        return;
    }
    
    Message msg, response;
    memset(&msg, 0, sizeof(msg));
    msg.msg_type = MSG_STREAM_FILE;
    strncpy(msg.username, username, MAX_USERNAME - 1);
    strncpy(msg.data, filename, MAX_BUFFER - 1);
    
    send_message(sock, &msg);
    if (receive_message(sock, &response) < 0) {
        printf("ERROR: Failed to receive response from name server\n");
        close(sock);
        return;
    }
    close(sock);
    
    if (response.error_code != ERR_SUCCESS) {
        printf("ERROR: %s\n", response.data);
        return;
    }
    
    char ss_ip[INET_ADDRSTRLEN];
    int ss_port;
    sscanf(response.data, "%s %d", ss_ip, &ss_port);
    
    int ss_sock = connect_to_ss(ss_ip, ss_port);
    if (ss_sock < 0) {
        printf("ERROR: Failed to connect to storage server\n");
        return;
    }
    
    memset(&msg, 0, sizeof(msg));
    msg.msg_type = MSG_STREAM_FILE;
    strncpy(msg.username, username, MAX_USERNAME - 1);
    strncpy(msg.data, filename, MAX_BUFFER - 1);
    
    send_message(ss_sock, &msg);
    
    while (1) {
        if (receive_message(ss_sock, &response) < 0) {
            printf("\nERROR: Storage server disconnected\n");
            break;
        }
        
        if (strcmp(response.data, "STOP") == 0) {
            printf("\n");
            break;
        }
        
        printf("%s ", response.data);
        fflush(stdout);
    }
    
    close(ss_sock);
}

void handle_list() {
    int sock = connect_to_nm();
    if (sock < 0) {
        printf("ERROR: Failed to connect to name server\n");
        return;
    }
    
    Message msg, response;
    memset(&msg, 0, sizeof(msg));
    msg.msg_type = MSG_LIST_USERS;
    strncpy(msg.username, username, MAX_USERNAME - 1);
    
    send_message(sock, &msg);
    if (receive_message(sock, &response) < 0) {
        printf("ERROR: Failed to receive response from name server\n");
        close(sock);
        return;
    }
    
    if (response.error_code == ERR_SUCCESS) {
        printf("%s", response.data);
    } else {
        printf("ERROR: %s\n", response.data);
    }
    
    close(sock);
}

void handle_addaccess(char *args) {
    int sock = connect_to_nm();
    if (sock < 0) {
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
    
    if (response.error_code == ERR_SUCCESS) {
        printf("Access granted successfully!\n");
    } else {
        printf("ERROR: %s\n", response.data);
    }
    
    close(sock);
}

void handle_remaccess(char *args) {
    int sock = connect_to_nm();
    if (sock < 0) {
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
    
    if (response.error_code == ERR_SUCCESS) {
        printf("Access removed successfully!\n");
    } else {
        printf("ERROR: %s\n", response.data);
    }
    
    close(sock);
}

void handle_exec(char *filename) {
    int sock = connect_to_nm();
    if (sock < 0) {
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
    if (response.error_code == ERR_SUCCESS) {
        // Output produced by NM execution
        printf("%s", response.data);
    } else {
        printf("ERROR: %s\n", response.data);
    }
    
    close(sock);
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        printf("Usage: %s <nm_ip> <nm_port>\n", argv[0]);
        return 1;
    }
    
    strncpy(nm_ip, argv[1], INET_ADDRSTRLEN - 1);
    nm_port = atoi(argv[2]);
    
    // Set up signal handler for SIGPIPE
    signal(SIGPIPE, SIG_IGN);
    
    printf("Enter username: ");
    if (!fgets(username, sizeof(username), stdin)) {
        printf("ERROR: Failed to read username\n");
        return 1;
    }
    username[strcspn(username, "\n")] = 0;
    
    if (strlen(username) == 0) {
        printf("ERROR: Username cannot be empty\n");
        return 1;
    }
    
    // Register with name server
    int sock = connect_to_nm();
    if (sock < 0) {
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
    
    if (response.error_code != ERR_SUCCESS) {
        printf("ERROR: Failed to register\n");
        return 1;
    }
    
    printf("Welcome %s! Type 'help' for commands.\n\n", username);
    
    char command_history[10][MAX_BUFFER];  // Keep track of last 10 commands
    int history_index = 0;
    int history_count = 0;
    
    char input[MAX_BUFFER];
    while (1) {
        printf("> ");
        if (!fgets(input, sizeof(input), stdin)) break;
        
        input[strcspn(input, "\n")] = 0;
        
        if (strlen(input) == 0) continue;
        
        // Add command to history
        strncpy(command_history[history_index], input, MAX_BUFFER - 1);
        history_index = (history_index + 1) % 10;
        if (history_count < 10) history_count++;
        
        char *cmd = strtok(input, " ");
        if (!cmd) continue;
        
        if (strcmp(cmd, "VIEW") == 0) {
            char *args = strtok(NULL, "");
            handle_view(args);
        } else if (strcmp(cmd, "READ") == 0) {
            char *filename = strtok(NULL, " ");
            if (filename) handle_read(filename);
            else printf("ERROR: Missing filename\n");
        } else if (strcmp(cmd, "CREATE") == 0) {
            char *filename = strtok(NULL, " ");
            if (filename) handle_create(filename);
            else printf("ERROR: Missing filename\n");
        } else if (strcmp(cmd, "WRITE") == 0) {
            char *filename = strtok(NULL, " ");
            char *sent_num = strtok(NULL, " ");
            if (filename && sent_num) handle_write(filename, sent_num);
            else printf("ERROR: Missing arguments\n");
        } else if (strcmp(cmd, "UNDO") == 0) {
            char *filename = strtok(NULL, " ");
            if (filename) handle_undo(filename);
            else printf("ERROR: Missing filename\n");
        } else if (strcmp(cmd, "INFO") == 0) {
            char *filename = strtok(NULL, " ");
            if (filename) handle_info(filename);
            else printf("ERROR: Missing filename\n");
        } else if (strcmp(cmd, "DELETE") == 0) {
            char *filename = strtok(NULL, " ");
            if (filename) handle_delete(filename);
            else printf("ERROR: Missing filename\n");
        } else if (strcmp(cmd, "STREAM") == 0) {
            char *filename = strtok(NULL, " ");
            if (filename) handle_stream(filename);
            else printf("ERROR: Missing filename\n");
        } else if (strcmp(cmd, "LIST") == 0) {
            handle_list();
        } else if (strcmp(cmd, "ADDACCESS") == 0) {
            char *args = strtok(NULL, "");
            if (args) handle_addaccess(args);
            else printf("ERROR: Missing arguments\n");
        } else if (strcmp(cmd, "REMACCESS") == 0) {
            char *args = strtok(NULL, "");
            if (args) handle_remaccess(args);
            else printf("ERROR: Missing arguments\n");
        } else if (strcmp(cmd, "EXEC") == 0) {
            char *filename = strtok(NULL, " ");
            if (filename) handle_exec(filename);
            else printf("ERROR: Missing filename\n");
        } else if (strcmp(cmd, "exit") == 0 || strcmp(cmd, "quit") == 0) {
            break;
        } else if (strcmp(cmd, "help") == 0) {
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
            printf("  exit/quit             - Exit\n");
        } else {
            printf("ERROR: Unknown command. Type 'help' for commands.\n");
        }
    }
    
    return 0;
}