#include "ft_nmap.h"

void	*thread_routine(void *data)
{
    t_thread_context    *ctx;
    t_config            *conf;
    int                 idx;
    int                 port;

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

        printf("[DEBUG Thread %d] Scanning port %d from source port %d\n", ctx->thread_id, port, 40000 + ctx->thread_id);

        if (scan_port(ctx, port) != 0)
            g_stop = 1;

        ft_mutex(ctx->print_mutex, LOCK);
        printf("[Thread %d] Puerto %d escaneado\n", ctx->thread_id, conf->ports[idx].number);
        ft_mutex(ctx->print_mutex, UNLOCK);
    }

    return (NULL);
    
}

void    threads_creation(t_config *conf, t_thread_context *ctx_array)
{
    struct bpf_program  fp;
    char                errbuf[PCAP_ERRBUF_SIZE];
    char                filter[100];
    int                 source_port;

    for (int i = 0; i < conf->speedup && !g_stop; i++)
    {
        ctx_array[i].thread_id = i;
        ctx_array[i].conf = conf;
        ctx_array[i].work_mutex = &conf->work_mutex;
        ctx_array[i].send_mutex = &conf->send_mutex;
        ctx_array[i].print_mutex = &conf->print_mutex;
        ctx_array[i].recv_mutex = &conf->recv_mutex;
        ctx_array[i].next_port_idx = &conf->next_port_idx;

        // Cada hilo obtiene su propio handler pcap
        ctx_array[i].pcap_handle = pcap_open_live(conf->interface, BUFSIZ, 1, 100, errbuf);
        if (!ctx_array[i].pcap_handle)
        {
            printf("Error abriendo pcap para hilo %d: %s\n", i, errbuf);
            g_stop = 1;
            continue;
        }

        source_port = 40000 + i;
        snprintf(filter, sizeof(filter), "src host %s and (tcp dst port %d or (icmp and icmp[0] == 3))", inet_ntoa(conf->ip_address), source_port);

        printf("[DEBUG] Thread %d filter: %s\n", i, filter);

         if (pcap_compile(ctx_array[i].pcap_handle, &fp, filter, 0, PCAP_NETMASK_UNKNOWN) == -1 || pcap_setfilter(ctx_array[i].pcap_handle, &fp) == -1)
         {
            printf("Error configurando filtro para hilo %d\n", i);
            g_stop = 1;
        }
        pcap_freecode(&fp);

        if (pthread_create(&conf->threads[i], NULL, thread_routine, &ctx_array[i]) != 0)
            g_stop = 1;
    }

    return;
}
