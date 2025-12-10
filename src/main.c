#include "ft_nmap.h"

volatile sig_atomic_t   g_stop = 0;

void    cleanup(t_config *conf)
{
    if (!conf)
        return;
    if (conf->ports != NULL)
        free(conf->ports);
    if (conf->threads != NULL)
        free(conf->threads);
    free(conf);
}

int main(int argc, char **argv)
{
    t_config            *conf = NULL;
    t_thread_context    *threads = NULL;
    unsigned char       *bytes = 0;
    int                 exit = 0;

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
    {
        show_help(conf);
        return (0);
    }
    else if (dns_resolution(conf) != 0)
        exit = 1;
    else if (socket_creation(conf) != 0)
        exit = 1;
    else
    {
        bytes = (unsigned char *)&conf->ip_address;
        printf("Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-12-03 12:08 CET\n");
        printf("Nmap scan report for %s (%d.%d.%d.%d)\n", conf->hostname, bytes[0], bytes[1], bytes[2], bytes[3]);

        threads = malloc(sizeof(t_thread_context) * conf->speedup);
        if (!threads)
        {
            free(conf);
            return (1);
        }
        conf->threads = malloc(sizeof(pthread_t) * conf->speedup);
        if (!conf->threads)
        {
            cleanup(conf);
            free(threads);
            return (1);
        }

        ft_mutex(&conf->work_mutex, INIT);
        ft_mutex(&conf->print_mutex, INIT);
        ft_mutex(&conf->recv_mutex, INIT);
        ft_mutex(&conf->send_mutex, INIT);

        threads_creation(conf, threads);
        for (int i = 0; i < conf->speedup; i++)
            pthread_join(conf->threads[i], NULL);
        
        ft_mutex(&conf->print_mutex, LOCK);

        printf("[DEBUG TOTAL_PORTS]:  ( %d ) 01\n", conf->total_ports);
        for (int i = 0; i < conf->total_ports; i++)
        {
            printf("[DEBUG]: 02\n");
            if (conf->ports[i].state == PORT_OPEN)
                printf("%d/tcp OPEN\n", conf->ports[i].number);
        }

        ft_mutex(&conf->print_mutex, UNLOCK); 

        ft_mutex(&conf->work_mutex, DESTROY);
        ft_mutex(&conf->print_mutex,DESTROY);
        ft_mutex(&conf->recv_mutex, DESTROY);
        ft_mutex(&conf->send_mutex, DESTROY);
        printf("[DEBUG]: 03\n");
    }
    cleanup(conf);
    if (threads != NULL)
    {
        free(threads);
        threads = NULL;
    }
    return (exit);
}
