#include "ft_nmap.h"

int    scan_port(t_thread_context *ctx, int port)
{
    (void)port;
    struct sockaddr_in  dest;
    struct sockaddr_in  recv_adr;
    socklen_t           addr_len_recv;
    unsigned char       nuffer[512];
    ssize_t             sent_bytes;
    ssize_t             recv_bytes;
    int                 recv_sock;
    uint16_t            dest_port;

    addr_len_recv = sizeof(recv_adr);

    if (ctx->conf->sockfd == -1 || ctx->conf->hostname != NULL)
        return (-1);
    
    // Socket RAW para recibir ICMP
    recv_sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (recv_sock < 0)
    {
        printf("ft_nmap: socket raw ICMP failed: %s\n", strerror(errno));
        return (-1);
    }

    // timeput de recepción
    struct timeval timeout = {3, 0};

    return (0);
}