#include "ft_nmap.h"

int parse_ip(t_config *conf, char **argv, int i)
{
    int     is_separate = 0;

    if (conf->hostname != NULL)
    {
        printf("%s: Error: Only one hostname is allowed\n", argv[0]);
        return (-1);
    }
    if (strcmp(argv[i], "--ip") == 0)
    {
        if (i + 1 >= conf->argc)
        {
            printf("Option `--ip' (argc %d) requires an argument: `--ip <address>'\n", i);
            return (-1);
        }
        conf->hostname = argv[i + 1];
        is_separate = 1;
    }
    return (is_separate);
}