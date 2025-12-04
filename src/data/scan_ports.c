#include "ft_nmap.h"

int    scan_port(t_thread_context *ctx, int port)
{
    (void)port;
    struct sockaddr_in  dest;
    struct sockaddr_in  recv_adr;
    socklen_t           addr_len_recv;
    unsigned char       buffer[512];
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
    if (setsockopt(ctx->conf->sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == -1)
    {
        printf("ft_nmap: setsockopt (SO_RCVTIMEO): %s\n", strerror(errno));
        close(ctx->conf->sockfd);
        close(recv_sock);
        return (-1);
    }
    
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_port = htons(port);
    dest.sin_addr = ctx->conf->ip_address;

    struct timeval start;
    struct timeval end;
    gettimeofday(&start, NULL);

    // enviar UDP
    sent_bytes = sendto(ctx->conf->sockfd, "X", 1, 0, (struct sockaddr *)&dest, sizeof(dest));
    if (sent_bytes < 0)
        printf("ft_nmap: sendto ( %s )\n", strerror(errno));
    
    // recibir ICMP
    addr_len_recv = sizeof(recv_adr);
    recv_bytes = recvfrom(recv_sock, buffer, sizeof(buffer), 0, (struct sockaddr *)&recv_adr, &addr_len_recv);
    gettimeofday(&end, NULL);
    if (recv_bytes < 0)
        printf("ft_nmap: recvfrom ( %s )\n", strerror(errno));
    if (analysis_flags(buffer, recv_bytes, ctx->conf->ip_address, dest_port) == -1)
        printf("ft_nmap: scan flags ( %s )\n", buffer);        

    return (0);
}