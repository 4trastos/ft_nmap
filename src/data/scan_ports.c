#include "ft_nmap.h"

int    scan_port(t_thread_context *ctx, int port)
{
    uint16_t            dest_port;
    
    ft_mutex(ctx->send_mutex, LOCK);

    struct timeval start;
    struct timeval end;
    gettimeofday(&start, NULL);

    if (icmp_creation(ctx) != 0)
        return (-1);
    if (send_socket(ctx, port) != 0)
        return (-1);

    ft_mutex(ctx->send_mutex, UNLOCK);
    ft_mutex(ctx->recv_mutex,LOCK);

    // recibir ICMP
    if (receive_response(ctx, port) != 0)
        return (-1);

    if (analysis_flags(buffer, recv_bytes, ctx->conf->ip_address, dest_port) == -1)
        printf("ft_nmap: scan flags ( %s )\n", buffer);        
    gettimeofday(&end, NULL);
    
    ft_mutex(ctx->recv_mutex, UNLOCK);

    return (0);
}