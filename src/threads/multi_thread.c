#include "ft_nmap.h"

/*
 * Obtiene un paquete para el hilo ctx desde la cola global g_packet_queue.
 * Retorna 1 si se obtiene un paquete, 0 si no hay paquetes (timeout), -1 si se detuvo el escaneo.
 */

int get_packet_for_thread(t_thread_context *ctx, const u_char **packet, struct pcap_pkthdr **header)
{
    t_packet_node   *prev;
    t_packet_node   *current;
    struct iphdr    *ip;
    struct tcphdr   *tcp;
    
    ft_mutex(&g_packet_queue.mutex, LOCK);
    prev = NULL;
    current = g_packet_queue.head;

    while (current && !g_stop)
    {
        ip = (struct iphdr *)(current->packet + offset_calcualte(ctx));

        if (ip->protocol == IPPROTO_TCP)
        {
            tcp = (struct tcphdr *)((u_char *)ip + ip->ihl * 4);
            if (ntohs(tcp->dest) == 40000 + ctx->thread_id)
                break;
        }
        else if (ip->protocol == IPPROTO_ICMP)
            break;
        
        prev = current;
        current = current->next;
    }

    if (!current)
    {
        ft_mutex(&g_packet_queue.mutex, UNLOCK);
        return 0;
    }

    if (prev)
        prev->next = current->next;
    else
        g_packet_queue.head = current->next;

    if (current == g_packet_queue.tail)
        g_packet_queue.tail = prev;

    *packet = current->packet;
    *header = &current->header;
    free(current);

    ft_mutex(&g_packet_queue.mutex, UNLOCK);
    return 1;

}

/*
 * Notifica a todos los hilos que el escaneo terminó.
 */

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

        printf("[DEBUG Thread %d] Scanning port %d from source port %d\n", ctx->thread_id, port, 40000 + ctx->thread_id);

        if (scan_port(ctx, port) != 0)
            g_stop = 1;

        ft_mutex(ctx->print_mutex, LOCK);
        printf("[Thread %d] Puerto %d escaneado\n", ctx->thread_id, conf->ports[idx].number);
        ft_mutex(ctx->print_mutex, UNLOCK);

        // Procesar paquetes pendientes sin bloquear indefinidamente
        while (get_packet_for_thread(ctx, &packet, &header)  == 1)
        {
            process_syn_packet(ctx, packet, header, port);  // NO liberar packet si es compartido entre hilos
        }
        
    }

    return (NULL);
    
}

void    threads_creation(t_config *conf, t_thread_context *ctx_array)
{
    //struct bpf_program  fp;
    //char                errbuf[PCAP_ERRBUF_SIZE];
    //char                filter[100];
    //int                 source_port;

    for (int i = 0; i < conf->speedup && !g_stop; i++)
    {
        ctx_array[i].thread_id = i;
        ctx_array[i].conf = conf;
        ctx_array[i].work_mutex = &conf->work_mutex;
        ctx_array[i].send_mutex = &conf->send_mutex;
        ctx_array[i].print_mutex = &conf->print_mutex;
        ctx_array[i].recv_mutex = &conf->recv_mutex;
        ctx_array[i].next_port_idx = &conf->next_port_idx;

        ctx_array[i].pcap_handle = conf->pcap_handle;

        /* source_port = 40000 + i;
        snprintf(filter, sizeof(filter), "src host %s and (tcp dst port %d or (icmp and icmp[0] == 3))", inet_ntoa(conf->ip_address), source_port);

        printf("[DEBUG] Thread %d filter: %s\n", i, filter);

        if (pcap_compile(ctx_array[i].pcap_handle, &fp, filter, 0, PCAP_NETMASK_UNKNOWN) == -1 || pcap_setfilter(ctx_array[i].pcap_handle, &fp) == -1)
        {
            printf("Error configurando filtro para hilo %d\n", i);
            g_stop = 1;
        }
        pcap_freecode(&fp); */

        if (pthread_create(&conf->threads[i], NULL, thread_routine, &ctx_array[i]) != 0)
            g_stop = 1;
    }

    return;
}
