#include "../common.h"
#include "client.h"
#include <sys/time.h>
#include <netinet/tcp.h>
#include <unistd.h>
#include <signal.h>

int connect_to_ss(const char *ip, int port)
{
    int retry_count = 0;
    const int max_retries = 3;
    int sock;

    while (retry_count < max_retries)
    {
        sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0)
        {
            perror("socket");
            sleep(1);
            retry_count++;
            continue;
        }

        // Set socket options for timeouts
        struct timeval tv;
        tv.tv_sec = 5; // 5 second timeout
        tv.tv_usec = 0;
        if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0 ||
            setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) < 0)
        {
            perror("setsockopt timeout");
            close(sock);
            sleep(1);
            retry_count++;
            continue;
        }

        // Enable TCP keepalive
        int opt = 1;
        if (setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, &opt, sizeof(opt)) < 0)
        {
            perror("setsockopt keepalive");
            close(sock);
            sleep(1);
            retry_count++;
            continue;
        }

        // Set TCP keepalive parameters
        int keepalive_time = 10;  // Start sending keepalive after 10 seconds of idle
        int keepalive_intvl = 5;  // Send keepalive every 5 seconds
        int keepalive_probes = 3; // Drop connection after 3 failed probes

        if (setsockopt(sock, IPPROTO_TCP, TCP_KEEPIDLE, &keepalive_time, sizeof(keepalive_time)) < 0 ||
            setsockopt(sock, IPPROTO_TCP, TCP_KEEPINTVL, &keepalive_intvl, sizeof(keepalive_intvl)) < 0 ||
            setsockopt(sock, IPPROTO_TCP, TCP_KEEPCNT, &keepalive_probes, sizeof(keepalive_probes)) < 0)
        {
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
        if (inet_pton(AF_INET, ip, &addr.sin_addr) <= 0)
        {
            perror("inet_pton");
            close(sock);
            sleep(1);
            retry_count++;
            continue;
        }

        if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0)
        {
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
