#include "ft_nmap.h"

// ft_nmap --ip 8.8.8.8
// ft_nmap --ip scanme.nmap.org --ports 80
// ft_nmap --ip 10.0.0.1 --ports 1-100 --speedup 5 --scan SYN

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
    int i = 1;
    //int parser_result;

    if (argv[i][0] != '-')
    {
        printf("❌ Error: %s Usage: --ip <address> [--ports <ports>] [--speedup <number>] [--scan <type>] ❌\n", argv[0]);
        return (-1);
    }

    while (i < conf->argc)
    {
        if (argv[i][0] == '-')
        {
            if (strcmp(argv[i], "--help") == 0 && conf->show_help == false)
            {
                conf->show_help = true;
                return (0);
            }
        }
        i++;
    }
    
    return (0);
}