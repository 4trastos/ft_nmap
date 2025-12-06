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
    conf->scan_type = SCAN_SYN;
    conf->ports_tokens = 0;
    conf->total_ports = 0;
    conf->ports = NULL;
    conf->speedup = 1;
    conf->threads = NULL;
    conf->is_valid = false;
    conf->sockfd = -1;
    conf->ttl = 64;
    memset(conf->port_bitmap, 0, sizeof(conf->port_bitmap));
}

int ft_parser_args(t_config *conf, char **argv)
{
    int i = 1;
    int parser_result;

    if (argv[i][0] != '-')
    {
        printf("❌ Error: %s Usage: --ip <IPv4 | hostname> [--ports <ports>] [--speedup <number>] [--scan <type>] ❌\n", argv[0]);
        return (-1);
    }

    while (i < conf->argc)
    {
        if (argv[i][0] == '-')
        {
            if (strcmp(argv[i], "--help") == 0 && conf->show_help == false)
                conf->show_help = true;
            else if (strcmp(argv[i], "--ip") == 0)
            {
                parser_result = parse_ip(conf, argv, i);
                if (parser_result == -1)
                    return (-1);
                if (parser_result == 1)
                    i++;
            }
            else if (strcmp(argv[i], "--ports") == 0)
            {
                parser_result = parse_ports(conf, argv, i);
                if (parser_result == -1)
                    return (-1);
                if (parser_result == 1)
                    i++;
            }
            else if (strcmp(argv[i], "--speedup") == 0)
            {
                parser_result = parse_speedup(conf, argv, i);
                if (parser_result == -1)
                    return (-1);
                if (parser_result == 1)
                    i++;
            }
            else if (strcmp(argv[i], "--scan") == 0)
            {
                parser_result = parse_scantypes(conf, argv, i);
                if (parser_result == -1)
                    return (-1);
                if (parser_result == 1)
                    i++;
            }
            else
            {
                printf("❌ Bad option `%s' (argc %d) \n", argv[i], i);
                printf("Usage: --ip <IPv4 | hostname> [--ports <ports>] [--speedup <number>] [--scan <type>]\n");
                return (-1);
            }
        }
        i++;
    }
    return (0);
}