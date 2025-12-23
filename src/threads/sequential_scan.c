#include "ft_nmap.h"

int         sequential_scan(t_config *conf)
{
    t_thread_context    ctx;
    int                 result;
    int                 idx;
    int                 port;

    memset(&ctx, 0, sizeof(t_thread_context));

    ctx.thread_id = 0;
    ctx.conf = conf;
    ctx.work_mutex = &conf->work_mutex;
    ctx.send_mutex = &conf->send_mutex;
    ctx.print_mutex = &conf->print_mutex;
    ctx.recv_mutex = &conf->recv_mutex;
    ctx.next_port_idx = &conf->next_port_idx;
    ctx.pcap_handle = conf->pcap_handle;

    conf->next_port_idx = 0;

    while (conf->next_port_idx < conf->total_ports && !g_stop)
    {
        idx = conf->next_port_idx++;
        port = conf->ports[idx].number;

        memset(ctx.sendbuffer, 0, MAX_PACKET_SIZE);
        memset(ctx.recvbuffer, 0, MAX_PACKET_SIZE);

        //printf("[DEBUG Sequential] Scanning port %d from source port %d\n", port, 40000 + ctx.thread_id);

        result = scan_port(&ctx, port);

        if (result != 0)
        {
            printf("Error escaneando puerto %d\n", port);
            return (-1);
        }
        usleep(100000); 
    }
    
    return (0);
}