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
        ctx->probe_id = idx;  
        ft_mutex(ctx->work_mutex, UNLOCK);

        port = conf->ports[idx].number;
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
    for (int i = 0; i < conf->speedup; i++)
    {
        ctx_array[i].thread_id = i;
        ctx_array[i].conf = conf;
        ctx_array[i].work_mutex = &conf->work_mutex;
        ctx_array[i].send_mutex = &conf->send_mutex;
        ctx_array[i].print_mutex = &conf->print_mutex;
        ctx_array[i].recv_mutex = &conf->recv_mutex;
        ctx_array[i].next_port_idx = &conf->next_port_idx;

        if (pthread_create(&conf->threads[i], NULL, thread_routine, &ctx_array[i]) != 0)
            g_stop = 1;
    }

    return;
}
