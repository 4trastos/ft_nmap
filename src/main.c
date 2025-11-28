#include "ft_nmap.h"

volatile sig_atomic_t   g_stop = 0;

void    cleanup(t_config *conf)
{
    free(conf);
}

int main(int argc, char **argv)
{
    t_config   *conf;
    int             exit = 0;

    if (argc == 1)
    {
        printf("%s Usage: --ip <IPv4 | hostname> [--ports <range/list>] [--scan <types>] [--speedup <n>]\n", argv[0]);
        printf("Try --help for more information.\n");
        return (1);
    }

    conf = malloc(sizeof(t_config));
    if (!conf)
        return (1);
    init_signal();
    init_struct(conf, argc);
    if (ft_parser_args(conf, argv) != 0)
        exit = 1;
    if (conf->show_help)
        show_help();
    while (!g_stop && exit == 0 && !conf->show_help)
    {
        printf("ip: ( %s )\n", conf->hostname);
        printf("PARA EL BUCLE `CON Control + C'\n");
        sleep (2);
        if (g_stop == 1)
            printf("SEÑAL RECIBIDA\n");
    }
    
    cleanup(conf);
    return (exit);
}