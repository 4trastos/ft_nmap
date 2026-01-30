#include "ft_nmap.h"

volatile sig_atomic_t   g_stop = 0;
t_packet_queue g_packet_queue = {0};

static void    run_scan_target(t_config *conf)
{
    t_thread_context    *threads = NULL;
    pthread_t           packet_reader;
    struct timeval      start, end;
    time_t              rawtime;
    struct tm           *timeinfo;
    struct servent      *service;
    const char          *service_name;
    char                timebuff[80];
    
    g_stop = 0;
    if (dns_resolution(conf) != 0 || socket_creation(conf) != 0)
        return;

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
        return;

    if (conf->speedup == 0)
    {
        if (sequential_scan(conf) != 0)
        {
            cleanup(conf, threads);
            ft_mutex(&conf->work_mutex, DESTROY);
            ft_mutex(&conf->print_mutex,DESTROY);
            ft_mutex(&conf->recv_mutex, DESTROY);
            ft_mutex(&conf->send_mutex, DESTROY);
            return;
        }
    }
    else
    {
        threads = malloc(sizeof(t_thread_context) * conf->speedup);
        if (!threads)
        {
            free(conf);
            return;
        }
        conf->threads = malloc(sizeof(pthread_t) * conf->speedup);
        if (!conf->threads)
        {
            cleanup(conf, threads);
            free(threads);
            return;
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
            printf("%d/tcp UNKNOWN\n", conf->ports[i].number);
    }

    gettimeofday(&end, NULL);
    double total_time = (double)(end.tv_sec - start.tv_sec) + (double)(end.tv_usec - start.tv_usec) / 1000000.0;
    printf("\nft_nmap done: 1 IP address (1 host up) scanned in %.2f seconds\n", total_time);

    if (conf->pcap_handle)
    {
        pcap_close(conf->pcap_handle);
        conf->pcap_handle = NULL;
    }
    if (conf->sockfd >= 0)
    {
        close(conf->sockfd);
        conf->sockfd = -1;
    }

    g_stop = 1;
    pthread_join(packet_reader, NULL);
    free_packet_queue();
}

static void    reset_ports_states(t_config *conf)
{
    conf->next_port_idx = 0;
    if (conf->ports)
    {
        for (int i = 0; i < conf->total_ports; i++)
            conf->ports[i].state = PORT_UNKNOWN;
    }
}

void free_packet_queue(void)
{
    t_packet_node   *current, *next;

    ft_mutex(&g_packet_queue.mutex, LOCK);
    current = g_packet_queue.head;
    while (current)
    {
        next = current->next;
        free((void*)current->packet);
        free(current);
        current = next;
    }
    g_packet_queue.head = NULL;
    g_packet_queue.tail = NULL;
    ft_mutex(&g_packet_queue.mutex, UNLOCK);
}


void    cleanup(t_config *conf, t_thread_context *threads)
{
    if (threads)
    {
        for (int i = 0; i < conf->speedup; i++)
            if (threads[i].pcap_handle)
                pcap_close(threads[i].pcap_handle);
        free(threads);
    }
    if (conf)
    {
        free(conf->ports);
        free(conf->threads);
        free(conf);
    }
}

int main(int argc, char **argv)
{
    t_config            *conf = NULL;

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
        return (1);
    if (conf->show_help)
    {
        show_help(conf, NULL);
        return (0);
    }
    if (set_default_ports(conf, NULL) != 0)
        return (1);
    conf->local_ip = get_local_ip();
    if (conf->file_input)
    {
        if (conf->hostname != NULL)
        {
            printf("Error: Multi-format not allowed\n");
            return (1);
        }
        FILE *fd = fopen(conf->file_input, "r");
        char line[256];
        while (fgets(line, sizeof(line), fd))
        {
            line[strcspn(line, "\n")] = 0;
            if (strlen(line) == 0)
                continue;
            conf->hostname = strdup(line);
            run_scan_target(conf);
            reset_ports_states(conf);
            free(conf->hostname);
        }
        fclose(fd);
    }
    else if (conf->hostname)
        run_scan_target(conf);

    cleanup(conf, NULL);
    return (0);
}
