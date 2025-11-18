#ifndef CLIENT_H
#define CLIENT_H

#include "../common.h"

// Global client state
extern char username[MAX_USERNAME];
extern char nm_ip[INET_ADDRSTRLEN];
extern int nm_port;

// Connection helpers
int connect_to_nm(void);
int connect_to_ss(const char *ip, int port);

// Command handlers (implemented in client.c)
void handle_view(char *args);
void handle_read(char *filename);
void handle_create(char *filename);
void handle_write(char *filename, char *sent_num_str);
void handle_undo(char *filename);
void handle_info(char *filename);
void handle_delete(char *filename);
void handle_stream(char *filename);
void handle_list(void);
void handle_addaccess(char *args);
void handle_remaccess(char *args);
void handle_exec(char *filename);

#endif // CLIENT_H
