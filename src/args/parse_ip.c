#include "ft_nmap.h"

int parse_ip(t_config *conf, char **argv, int i)
{
    if (conf->hostname != NULL)
    {
        printf("%s: Error: Only one hostname is allowed\n", argv[0]);
        return (-1);
    }
    if (strcmp(argv[i], "--ip") == 0)
    {
        if ((i + 1 >= conf->argc) || (argv[i+ 1][0] == '-'))
        {
            printf("Option `--ip' (argc %d) requires an argument: `--ip <IPv4 | hostname>'\n", i);
            return (-1);
        }
        conf->hostname = argv[i + 1];
        if (conf->hostname[0] == '-')
            return (-1);
    }
    return (1);
}