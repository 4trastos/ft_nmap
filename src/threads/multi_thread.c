#include "ft_nmap.h"

void    notify_threads_stop(void)
{
    ft_mutex(&g_packet_queue.mutex, LOCK);
    g_stop = 1;
    pthread_cond_broadcast(&g_packet_queue.cond);
    ft_mutex(&g_packet_queue.mutex, UNLOCK);
}

void	*thread_routine(void *data)
{
    t_thread_context    *ctx;
    t_config            *conf;
    int                 idx;
    int                 port;
    struct pcap_pkthdr  *header;
    const u_char        *packet;

    ctx = (t_thread_context *)data;
    conf = ctx->conf;

    while (!g_stop)
    {
        ft_mutex(ctx->work_mutex, LOCK);
        if (*(ctx->next_port_idx) >= conf->total_ports)
        {
            ft_mutex(ctx->work_mutex, UNLOCK);
            break;
        }
        idx = (*(ctx->next_port_idx))++;
        ft_mutex(ctx->work_mutex, UNLOCK);

        port = conf->ports[idx].number;

        //printf("[DEBUG Thread %d] Scanning port %d from source port %d\n", ctx->thread_id, port, 40000 + ctx->thread_id);

        if (scan_port(ctx, port) != 0)
            g_stop = 1;

        // ft_mutex(ctx->print_mutex, LOCK);
        // printf("[Thread %d] Puerto %d escaneado\n", ctx->thread_id, conf->ports[idx].number);
        // ft_mutex(ctx->print_mutex, UNLOCK);

        // Procesar paquetes pendientes sin bloquear indefinidamente
        while (get_packet_for_thread(ctx, &packet, &header)  == 1)
            process_tcp_response(ctx, packet, header, port);  // NO liberar packet si es compartido entre hilos
        
    }

    return (NULL);
    
}

void    threads_creation(t_config *conf, t_thread_context *threads)
{

    for (int i = 0; i < conf->speedup && !g_stop; i++)
    {
        memset(&threads[i], 0, sizeof(t_thread_context));
        threads[i].thread_id = i;
        threads[i].conf = conf;
        threads[i].work_mutex = &conf->work_mutex;
        threads[i].send_mutex = &conf->send_mutex;
        threads[i].print_mutex = &conf->print_mutex;
        threads[i].recv_mutex = &conf->recv_mutex;
        threads[i].next_port_idx = &conf->next_port_idx;

        threads[i].pcap_handle = conf->pcap_handle;

        if (pthread_create(&conf->threads[i], NULL, thread_routine, &threads[i]) != 0)
            g_stop = 1;
    }

    return;
}
