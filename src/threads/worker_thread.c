#include "ft_nmap.h"

void	*thread_routine(void *data)
{
    // ¿HAGO COSAS???
}

int threads_creation(t_thread_context *threads, t_config *conf)
{
    int i = 0;
    while (i < conf->speedup)
    {
        ft_threads(threads->thread_id++, thread_routine, threads->conf->port_bitmap[i], CREATE);
        i++;
    }
    
    return (0);
}

void    worker_thread(t_thread_context *threads)
{
    int i = 0;
    while (!g_stop && !(threads->thread_id >= threads->conf->total_ports))
    {
        ft_mutex(threads->work_mutex, LOCK);
        threads->thread_id = threads->next_port_idx++;
        ft_mutex(threads->work_mutex, UNLOCK);

        scan_port();
    }
        
    return;
}

