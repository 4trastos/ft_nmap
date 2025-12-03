#include "ft_nmap.h"

void    worker_thread(t_thread_context *threads, t_config *conf)
{
    (void)threads;
    (void)conf;
    return;
}

// while (!g_stop)
// {
//     lock(work_mutex)
//     idx = next_port_idx++
//     unlock(work_mutex)

//     if (idx >= total_ports)
//         break;

//     // escanea ese puerto
// }
