#include "ft_nmap.h"

void set_port_state(t_config *conf, int port, t_port_state state)
{
    for (int i = 0; i < conf->total_ports; i++)
    {
        if (conf->ports[i].number == port)
        {
            conf->ports[i].state = state;
            return;
        }
    }
}

int dispatch_scan(t_thread_context *ctx, int port)
{
    if (ctx->conf->scan_type & SCAN_SYN)
        return (syn_scan(ctx, port));
    if (ctx->conf->scan_type & SCAN_NULL)
        return (null_scan(ctx, port));
    if (ctx->conf->scan_type & SCAN_FIN)
        return (fin_scan(ctx, port));
    if (ctx->conf->scan_type & SCAN_XMAS)
        return (xmas_scan(ctx, port));
    if (ctx->conf->scan_type & SCAN_ACK)
        return (ack_scan(ctx, port));
    if (ctx->conf->scan_type & SCAN_UDP)
        return (udp_scan(ctx, port));

    return (-1);
}

int    scan_port(t_thread_context *ctx, int port)
{ 
    struct timeval start;
    struct timeval end;

    gettimeofday(&start, NULL);
    if (dispatch_scan(ctx, port) == -1)
        return (-1);     
    gettimeofday(&end, NULL);
    ft_mutex(ctx->print_mutex, LOCK);
    show_result(); // hay que crearla
    ft_mutex(ctx->print_mutex, UNLOCK); 

    return (0);
}