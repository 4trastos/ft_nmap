#include "ft_nmap.h"

int         receive_response(t_thread_context *ctx, int port)
{
    struct sockaddr_in  recv_addr;
    struct iphdr        *ip_header;
    struct icmphdr      *icmp_reply;
    struct timeval      timeout = {4, 0};
    socklen_t           recv_addr_len = sizeof(recv_addr);
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

    recv_bytes = recvfrom(recv_sock, ctx->recvbuffer, sizeof(ctx->recvbuffer), 0, (struct sockaddr *)&recv_addr, &recv_addr_len);
    if (recv_bytes == -1)
    {
        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
            return (-1);
        printf("ft_nmap: recvfrom error: ( %s )\n", strerror(errno));
        close(recv_sock);
        return (-1);
    }

    ip_header = (struct iphdr *)ctx->recvbuffer;
    icmp_reply = (struct icmphdr *)(ctx->recvbuffer + (ip_header->ihl * 4));

    if (icmp_reply->type == ICMP_ECHOREPLY && icmp_reply->un.echo.id == getpid())
    {
        //verificamos que es el nuestro ¿es necesario???
    }
    else if (icmp_reply->type == ICMP_TIME_EXCEEDED)
    {
        // TTL expirado en algún router intermedio ¿necesario???
    }
    
    return (0);
}