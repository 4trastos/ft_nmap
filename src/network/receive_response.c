#include "ft_nmap.h"

int         receive_response(t_thread_context *ctx, int port)
{
    struct sockaddr_in  recv_addr;
    struct timeval      timeout = {4, 0};
    socklen_t           recv_addr_len;
    size_t              recv_bytes;
    int                 recv_sock;

    recv_sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (recv_sock < 0)
    {
        printf("ft_nmap: socket raw ICMP failed: %s\n", strerror(errno));
        return (-1);
    }
    if (getsockopt(recv_sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == -1)
    {
        printf("ft_nmap: setsockopt (SO_RCVTIMEO): %s\n", strerror(errno));
        close(recv_sock);
        return (-1);
    }

    recv_addr_len = sizeof(recv_addr);
    recv_bytes = recvfrom(recv_sock, ctx->recvbuffer, sizeof(ctx->recvbuffer), 0, (struct sockaddr *)&recv_addr, &recv_addr_len);
    if (recv_bytes < 0)
        printf("ft_nmap: recvfrom ( %s )\n", strerror(errno));
    return (0);
}