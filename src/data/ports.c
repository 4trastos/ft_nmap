#include "ft_nmap.h"

int     port_validator(t_config *conf, char **ports)
{
    int     i = 0;
    
    conf->start_port = atoi(ports[i]);
    conf->ports[i].number = conf->start_port;
    i++;
    if (i < conf->ports_number)
    {
        while (ports[i] != NULL && i < conf->ports_number)
        {
            if ()
        }
    }
    conf->end_port = atoi(ports[i]);
    
    return (0);
}