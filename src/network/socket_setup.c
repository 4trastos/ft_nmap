#include "ft_nmap.h"

//    0800 0000 0001 0001 Paquete pequeño
//    0800 = type(8) + code(0)
//    0000 = checksum (temporalmente 0)
//    0001 = id(1)
//    0001 = sequence(1)

int get_packet_for_thread(t_thread_context *ctx, const u_char **packet, struct pcap_pkthdr **header)
{
    pthread_mutex_lock(&g_packet_queue.mutex);
    t_packet_node   *prev = NULL;
    t_packet_node   *current = g_packet_queue.head;
    struct iphdr    *ip;
    struct tcphdr   *tcp;

    while (current && !g_stop)
    {
        ip = (struct iphdr *)(current->packet + offset_calcualte(ctx));
        if (ip->protocol == IPPROTO_TCP)
        {
            tcp = (struct tcphdr *)((u_char *)ip + (ip->ihl * 4));
            if (ntohs(tcp->dest) == 40000 + ctx->thread_id)
            {
                // Lo sacamos de la cola
                if (prev)
                    prev->next = current->next;
                else
                    g_packet_queue.head = current->next;
                if (current == g_packet_queue.tail)
                    g_packet_queue.tail = prev;

                *packet = current->packet;
                *header = &current->header;
                free(current);
                pthread_mutex_unlock(&g_packet_queue.mutex);
                return (1);
            }
        }
        if (ip->protocol == IPPROTO_ICMP)
        {
            if (prev)
                prev->next = current->next;
            else
                g_packet_queue.head = current->next;
            if (current == g_packet_queue.tail)
                    g_packet_queue.tail = prev;
            
            *packet = current->packet;
            *header = &current->header;
            free(current);
            pthread_mutex_unlock(&g_packet_queue.mutex);
            return (1);
        }
        prev = current;
        current = current->next;
    }

    // No hay paquete para este thread
    pthread_cond_wait(&g_packet_queue.cond, &g_packet_queue.mutex);
    pthread_mutex_unlock(&g_packet_queue.mutex);
    return (0);
}

uint16_t    calculate_checksum(void *packet, size_t len)
{
    uint32_t    sum = 0;
    uint16_t    *aux = packet;

    for (size_t i = 0; i < len / 2; i++)
        sum += aux[i];
    if (len % 2)
        sum += ((uint8_t*)packet)[len - 1];
    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);
    return (~sum); 
}

int socket_creation(t_config *conf)
{
    int one = 1;
    int timeout_ms = 10;
    char errorbuf[PCAP_ERRBUF_SIZE];
    char filter_exp[256];
    struct bpf_program fp;
    char ip_str[INET_ADDRSTRLEN];
    const char *dev = "any";

    /* ===== RAW SOCKET (SEND) ===== */
    conf->sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (conf->sockfd == -1)
    {
        perror("ft_nmap: socket");
        return (-1);
    }

    if (setsockopt(conf->sockfd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) == -1)
    {
        perror("ft_nmap: setsockopt IP_HDRINCL");
        close(conf->sockfd);
        return (-1);
    }

    /* ===== PCAP (RECEIVE – ONLY READER THREAD) ===== */
    conf->pcap_handle = pcap_open_live(dev, BUFSIZ, 1, timeout_ms, errorbuf);
    if (!conf->pcap_handle)
    {
        fprintf(stderr, "pcap_open_live: %s\n", errorbuf);
        close(conf->sockfd);
        return (-1);
    }

    conf->pcap_datalink = pcap_datalink(conf->pcap_handle);

    inet_ntop(AF_INET, &conf->ip_address, ip_str, sizeof(ip_str));
    snprintf(filter_exp, sizeof(filter_exp), "(ip proto 6 or ip proto 1) and src host %s", ip_str);

    if (pcap_compile(conf->pcap_handle, &fp, filter_exp, 0,
                     PCAP_NETMASK_UNKNOWN) == -1 ||
        pcap_setfilter(conf->pcap_handle, &fp) == -1)
    {
        fprintf(stderr, "pcap filter error: %s\n",
                pcap_geterr(conf->pcap_handle));
        pcap_freecode(&fp);
        pcap_close(conf->pcap_handle);
        close(conf->sockfd);
        return (-1);
    }

    pcap_freecode(&fp);

    if (pcap_setnonblock(conf->pcap_handle, 1, errorbuf) == -1)
        fprintf(stderr, "pcap_setnonblock: %s\n", errorbuf);

    return (0);
}


/* int     icmp_creation(t_thread_context *ctx, int port)
{
    int idx = port % MAX_PACKET_SIZE;

    memset(&ctx->packets[idx], 0 , sizeof(struct ping_packet));
    ctx->packets[idx].icmp_hdr.type = 8;
    ctx->packets[idx].icmp_hdr.code = 0;
    ctx->packets[idx].icmp_hdr.checksum = 0;
    ctx->packets[idx].icmp_hdr.un.echo.id = getpid();
    ctx->packets[idx].icmp_hdr.un.echo.sequence = ctx->thread_id;
    gettimeofday(&ctx->packets[idx].timestamp, NULL);

    memset(ctx->packets[idx].data, 0, ICMP_PAYLOAD_SIZE);
    ctx->packets[idx].icmp_hdr.checksum = calculate_checksum(&ctx->packets[idx], sizeof(struct ping_packet));
    return (idx);
}


int send_socket(t_thread_context *ctx, int port, int idx)
{
    ssize_t  sent_bytes = 0;

    memset(&ctx->target_addr,0, sizeof(ctx->target_addr));
    ctx->target_addr.sin_family = AF_INET;
    ctx->target_addr.sin_port = htons(port);
    ctx->target_addr.sin_addr = ctx->conf->ip_address;

    sent_bytes = sendto(ctx->conf->sockfd, &ctx->packets[idx], sizeof(struct ping_packet), 0, (struct sockaddr *)&ctx->target_addr, sizeof(ctx->target_addr));
    if (sent_bytes < 0)
    {
        printf("ft_nmap: sendto error: ( %s )\n", strerror(errno));
        close(ctx->conf->sockfd);
        return (-1);
    }

    return (0);
} */
