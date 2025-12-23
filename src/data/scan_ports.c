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
    struct timeval start;
    struct timeval end;

    gettimeofday(&start, NULL);
    if (init_scan(ctx, port) == -1)
        return (-1);     
    gettimeofday(&end, NULL);

    return (0);
}