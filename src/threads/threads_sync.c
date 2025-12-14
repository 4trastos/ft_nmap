#include "ft_nmap.h"

int         sequential_scan(t_config *conf)
{
    t_thread_context    ctx;
    int                 result;
    int                 idx;
    int                 port;
    //struct timeval      start, end;
    //double              total_time;

    ctx.thread_id = 0;
    ctx.conf = conf;
    ctx.work_mutex = &conf->work_mutex;
    ctx.send_mutex = &conf->send_mutex;
    ctx.print_mutex = &conf->print_mutex;
    ctx.recv_mutex = &conf->recv_mutex;
    ctx.next_port_idx = &conf->next_port_idx;
    
    memset(ctx.sendbuffer, 0, MAX_PACKET_SIZE);
    memset(ctx.recvbuffer, 0, MAX_PACKET_SIZE);

    memset(&ctx.target_addr, 0, sizeof(ctx.target_addr));
    ctx.target_addr.sin_family = AF_INET;
    ctx.target_addr.sin_addr = conf->ip_address;

    conf->next_port_idx = 0;

    while (conf->next_port_idx < conf->total_ports && !g_stop)
    {
        idx = conf->next_port_idx++;
        port = conf->ports[idx].number;

        //gettimeofday(&start, NULL);
        result = scan_port(&ctx, port);
        //gettimeofday(&end, NULL);
        
        //total_time = (double)(end.tv_sec - start.tv_sec) + (double)(end.tv_usec - start.tv_usec) / 1000000.0;
        //printf("[Sequential] Port %d scanned in %.3f seconds\n", port, total_time);

        if (result != 0)
        {
            printf("Error escaneando puerto %d\n", port);
            return (-1);
        }
    }
    
    return (0);
}