#include "ft_nmap.h"

void    init_struct(t_config *conf, int argc)
{
    conf->show_help = false;
    conf->use_file = false;
    conf->hostname = NULL;
    conf->file_input = NULL;
    conf->argc = argc;
    conf->scan_type = 0;
    conf->start_port = 0;
    conf->end_port = 0;
    conf->ports_number = 0;
    conf->ports = NULL;
    conf->speedup = 0;
    conf->threads = NULL;
    conf->is_valid = false;
    conf->sockfd = -1;
}

int ft_parser_args(t_config *conf, char **argv)
{
    (void)conf;
    (void)argv;
    return (0);
}