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

int    scan_port(t_thread_context *ctx, int port)
{ 
    int idx = 0;

    ft_mutex(ctx->send_mutex, LOCK);

    struct timeval start;
    struct timeval end;
    gettimeofday(&start, NULL);

    idx =  icmp_creation(ctx, port);
    if (send_socket(ctx, port, idx) != 0)
        return (-1);
    
     if (dispatch_scan(ctx, port) == -1)
        return (-1);

    ft_mutex(ctx->send_mutex, UNLOCK);
    ft_mutex(ctx->recv_mutex,LOCK);
    
    if (receive_response(ctx, port) != 0)
        return (-1);

    if (analysis_flags(ctx, port) == -1)
        printf("ft_nmap: scan flags ( %s )\n", ctx->recvbuffer);        
    gettimeofday(&end, NULL);
    
    ft_mutex(ctx->recv_mutex, UNLOCK);

    return (0);
}