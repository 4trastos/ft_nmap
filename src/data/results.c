#include "ft_nmap.h"

int set_default_ports(t_config *conf, t_thread_context *threads)
{
    if (conf->is_valid == false)
    {
        cleanup(conf, threads);
        return(-1);
    }
    if (conf->ports == 0)
    {

        conf->ports_tokens = 1;
        conf->total_ports = 1024;
    
        conf->ports = malloc(sizeof(t_port) * conf->total_ports);
        if (!conf->ports)
        {
            cleanup(conf, threads);
            return (-1);
        }
        
        for (int i = 0; i < conf->total_ports; i++)
        {
            conf->ports[i].number = i + 1;
            conf->ports[i].start_port = i + 1;
            conf->ports[i].end_port = i + 1;
            conf->ports[i].state = PORT_UNKNOWN;
        }
    }
    
    return (0);
}