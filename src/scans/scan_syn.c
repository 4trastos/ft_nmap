#include "ft_nmap.h"

int process_syn_packet(t_thread_context *ctx, const u_char *packet, struct pcap_pkthdr *header, int port)
{
    (void)header;
    struct iphdr    *ip;
    struct tcphdr   *tcp;
    struct icmphdr  *icmp;
    int             link_offset;

    link_offset = offset_calcualte(ctx);
    if (link_offset < 0)
        return (-1);

    ip = (struct iphdr *)(packet + link_offset);

    /* ================= TCP ================= */
    if (ip->protocol == IPPROTO_TCP)
    {
        tcp = (struct tcphdr *)((u_char *)ip + (ip->ihl * 4));

        /* RST → CLOSED */
        if (tcp->rst)
        {
            set_port_state(ctx->conf, port, PORT_CLOSED);
            return (0);
        }
        
        /* SYN + ACK → OPEN */
        if (tcp->syn && tcp->ack)
        {
            set_port_state(ctx->conf, port, PORT_OPEN);
            return (0);
        }
    }

    /* ================= ICMP ================= */
    if (ip->protocol == IPPROTO_ICMP)
    {
        icmp = (struct icmphdr *)((u_char *)ip + (ip->ihl * 4));

        /* Destination unreachable → FILTERED */
        if (icmp->type == ICMP_DEST_UNREACH)
        {
            set_port_state(ctx->conf, port, PORT_FILTERED);
            return (0);
        }
    }

    return (0);  // Paquete no reconocido
}

int offset_calcualte(t_thread_context *ctx)
{
    int offset = -1;

    if (ctx->conf->pcap_datalink == DLT_EN10MB)
        offset = 14;
    else if (ctx->conf->pcap_datalink == DLT_LINUX_SLL)
        offset = 16;
    else
        printf("Unsupported datalink: %d\n", ctx->conf->pcap_datalink);
    return (offset);
}

int syn_scan(t_thread_context *ctx, int port)
{
    if (syn_packet_build(ctx, port) < 0)
        return (-1);
    if (send_syn_packet(ctx, port) < 0)
        return (-1);
    if (receive_syn_response(ctx, port) < 0)
        return (-1);
    return (0);
}


int syn_packet_build(t_thread_context *ctx, int port)
{
    struct iphdr            *ip;
    struct tcphdr           *tcp;
    struct pseudo_header    psh;
    unsigned char           *packet;

    packet = ctx->sendbuffer;
    memset(packet, 0, MAX_PACKET_SIZE);

    ip = (struct iphdr *)packet;
    tcp = (struct tcphdr *)(packet + sizeof(struct iphdr));

    // ================= IP HEADER =================

    ip->ihl         = 5;
    ip->version     = 4;
    ip->tos         = 0;
    ip->tot_len     = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
    ip->id          = htons(rand() % 65535);
    ip->frag_off    = 0;
    ip->ttl         = ctx->conf->ttl;
    ip->protocol    = IPPROTO_TCP;
    ip->check       = 0;
    ip->saddr       = ctx->conf->local_ip;
    ip->daddr       = ctx->conf->ip_address.s_addr;
    ip->check       = calculate_checksum(ip, sizeof(struct iphdr));

    // ================= TCP HEADER =================

    // ¡IMPORTANTE! Usar thread_id, NO probe_id
    int source_port = 40000 + ctx->thread_id;
    tcp->source     = htons(source_port);
    tcp->dest       = htons(port);
    tcp->seq        = htonl(rand());
    tcp->ack_seq    = 0;
    tcp->doff       = sizeof(struct tcphdr) / 4;
    tcp->syn        = 1;
    tcp->window     = htons(1024);
    tcp->check      = 0;
    tcp->urg_ptr    = 0;

    // ================= TCP CHECKSUM =================

    psh.src_addr    = ip->saddr;
    psh.dst_addr    = ip->daddr;
    psh.zero        = 0;
    psh.protocol    = IPPROTO_TCP;
    psh.tcp_length  = htons(sizeof(struct tcphdr));

    unsigned char pseudo_packet[sizeof(psh) + sizeof(struct tcphdr)];
    memcpy(pseudo_packet, &psh, sizeof(psh));
    memcpy(pseudo_packet + sizeof(psh), tcp, sizeof(struct tcphdr));

    tcp->check = calculate_checksum(pseudo_packet, sizeof(psh) + sizeof(struct tcphdr));

    // ¡GUARDAR EL NÚMERO DE SECUENCIA ENVIADO!
    ctx->last_seq_sent = ntohl(tcp->seq);

    return (0);
}

int send_syn_packet(t_thread_context *ctx, int port)
{
    int                 sent_bytes;

    memset(&ctx->target_addr, 0, sizeof(ctx->target_addr));
    ctx->target_addr.sin_family = AF_INET;
    ctx->target_addr.sin_port = htons(port);
    ctx->target_addr.sin_addr = ctx->conf->ip_address;

    ft_mutex(ctx->send_mutex, LOCK);
    sent_bytes = sendto(ctx->conf->sockfd, ctx->sendbuffer, sizeof(struct iphdr) + sizeof(struct tcphdr), 0, (struct sockaddr *)&ctx->target_addr, sizeof(ctx->target_addr));
    ft_mutex(ctx->send_mutex, UNLOCK);

    if (sent_bytes < 0)
    {
        printf("ft_nmap: sendto SYN ( %s )\n", strerror(errno));
        return (-1);
    }

    return (0);
}

int receive_syn_response(t_thread_context *ctx, int port)
{
    struct pcap_pkthdr  *header;
    const u_char        *packet;
    //int                 returned;
    struct timeval      start, now;
    double              time_elapsed;
    
    gettimeofday(&start, NULL);
    
    while (!g_stop)
    {
        gettimeofday(&now, NULL);
        time_elapsed = (double)(now.tv_sec - start.tv_sec) + (double)(now.tv_usec - start.tv_usec) / 1000000.0;
        
        if (time_elapsed >= 2.0)
        {
            printf("[DEBUG Thread %d] TIMEOUT for port %d\n", ctx->thread_id, port);
            set_port_state(ctx->conf, port, PORT_FILTERED);
            return (0);
        }
        
        if (get_packet_for_thread(ctx, &packet, &header))
        {
            process_syn_packet(ctx, packet, header, port);
            free((void*)packet);
            return 0;
        }

        /* ft_mutex(ctx->recv_mutex, LOCK);
        returned = pcap_next_ex(ctx->conf->pcap_handle, &header, &packet);
        ft_mutex(ctx->recv_mutex, UNLOCK);

        if (returned == 1)
        {
            if (packet_is_for_me(ctx, packet, header))
            {
                ft_mutex(ctx->recv_mutex, LOCK);
                process_syn_packet(ctx, packet, header, port);
                ft_mutex(ctx->recv_mutex, UNLOCK);
                return (0);
            }
        }
        else if (returned == 0)  // Timeout
        {
            usleep(10000);
            continue;
        } */

    }
    
    printf("[DEBUG Thread %d] No response for port %d\n", ctx->thread_id, port);
    set_port_state(ctx->conf, port, PORT_FILTERED);
    return (0);
}
