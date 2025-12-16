#include "ft_nmap.h"

volatile sig_atomic_t   g_stop = 0;
t_packet_queue g_packet_queue = {0};

void    cleanup(t_config *conf, t_thread_context *threads)
{
    if (!conf || !threads)
        return;
    for (int i = 0; i < conf->speedup; i++)
    {
        if (threads[i].pcap_handle)
        {
            pcap_close(threads[i].pcap_handle);
            threads[i].pcap_handle = NULL;
        }
    }
    
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
    pthread_t           packet_reader;
    struct timeval      start, end;
    time_t              rawtime;
    struct tm           *timeinfo;
    struct servent      *service;
    const char          *service_name;
    char                timebuff[80];
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
    srand(time(NULL));
    if (ft_parser_args(conf, argv) != 0)
        exit = 1;
    if (conf->show_help)
    {
        show_help(conf, threads);
        return (0);
    }
    conf->local_ip = get_local_ip();
    if (set_default_ports(conf, threads) != 0)
        return (1);
    else if (dns_resolution(conf) != 0)
        exit = 1;
    else if (socket_creation(conf) != 0)
        exit = 1;
    else
    {
        gettimeofday(&start, NULL);
        rawtime = start.tv_sec;
        timeinfo = localtime(&rawtime);
        strftime(timebuff, sizeof(timebuff), "%Y-%m-%d %H:%M:%S %Z", timeinfo);

        show_configuration(conf);

        ft_mutex(&conf->work_mutex, INIT);
        ft_mutex(&conf->print_mutex, INIT);
        ft_mutex(&conf->recv_mutex, INIT);
        ft_mutex(&conf->send_mutex, INIT);

        if (pthread_create(&packet_reader, NULL, packet_reader_thread, conf) != 0)
            exit = 1;

        if (conf->speedup == 0)
        {
            if (sequential_scan(conf) != 0)
            {
                cleanup(conf, threads);
                ft_mutex(&conf->work_mutex, DESTROY);
                ft_mutex(&conf->print_mutex,DESTROY);
                ft_mutex(&conf->recv_mutex, DESTROY);
                ft_mutex(&conf->send_mutex, DESTROY);
                return (1);
            }
        }
        else
        {
            threads = malloc(sizeof(t_thread_context) * conf->speedup);
            if (!threads)
            {
                free(conf);
                return (1);
            }
            conf->threads = malloc(sizeof(pthread_t) * conf->speedup);
            if (!conf->threads)
            {
                cleanup(conf, threads);
                free(threads);
                return (1);
            }
    
            threads_creation(conf, threads);
            for (int i = 0; i < conf->speedup; i++)
                pthread_join(conf->threads[i], NULL);

            g_stop = 1;
            pthread_join(packet_reader, NULL);
            free(threads);
            threads = NULL;
        }
        ft_mutex(&conf->work_mutex, DESTROY);
        ft_mutex(&conf->print_mutex,DESTROY);
        ft_mutex(&conf->recv_mutex, DESTROY);
        ft_mutex(&conf->send_mutex, DESTROY);
        
        printf("Port        Service Name (if applicable)       Results                 Conclusion\n");
        printf("-------------------------------------------------------------------------------------------------\n");

        for (int i = 0; i < conf->total_ports; i++)
        {
            service = getservbyport(htons(conf->ports[i].number), "tcp");
            service_name = service ? service->s_name : "unknown";
            if (conf->ports[i].state == PORT_OPEN)
                printf("%d/tcp      %s                              %s(Open)                 Open\n", conf->ports[i].number, service_name, show_scantype(conf));
            else if (conf->ports[i].state == PORT_CLOSED)
                printf("%d/tcp      %s                              %s(Closed)               Closed\n", conf->ports[i].number, service_name, show_scantype(conf));
            else if (conf->ports[i].state == PORT_FILTERED)
                printf("%d/tcp      %s                              %s(Filtered)             Filtered\n", conf->ports[i].number, service_name, show_scantype(conf));
            else if (conf->ports[i].state == PORT_UNFILTERED)
                printf("%d/tcp      %s                              %s(Unfiltered)           Unfiltered\n", conf->ports[i].number, service_name, show_scantype(conf));
            else if (conf->ports[i].state == PORT_OPEN_FILTERED)
                printf("%d/tcp      %s                              %s(Open|Filtered)        Open|Filtered\n", conf->ports[i].number, service_name, show_scantype(conf));
            else
                printf("%d-5d/tcp UNKNOWN\n", conf->ports[i].number);
        }

        gettimeofday(&end, NULL);
        double total_time = (double)(end.tv_sec - start.tv_sec) + (double)(end.tv_usec - start.tv_usec) / 1000000.0;
        printf("\nft_nmap done: 1 IP address (1 host up) scanned in %.2f seconds\n", total_time);
    }

    cleanup(conf, threads);
    return (exit);
}
