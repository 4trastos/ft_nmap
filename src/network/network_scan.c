#include "ft_nmap.h"

/* - Obtiene un paquete para el hilo ctx desde la cola global g_packet_queue.
   - Retorna 1 si se obtiene un paquete, 0 si no hay paquetes (timeout), -1 si se detuvo el escaneo. */

int get_packet_for_thread(t_thread_context *ctx, const u_char **packet, struct pcap_pkthdr **header)
{
    t_packet_node   *prev;
    t_packet_node   *current;
    struct iphdr    *ip;
    struct tcphdr   *tcp;
    
    ft_mutex(&g_packet_queue.mutex, LOCK);
    prev = NULL;
    current = g_packet_queue.head;

    while (current && !g_stop)
    {
        ip = (struct iphdr *)(current->packet + offset_calculate(ctx));

        if (ip->protocol == IPPROTO_TCP)
        {
            tcp = (struct tcphdr *)((u_char *)ip + ip->ihl * 4);
            if (ntohs(tcp->dest) == 40000 + ctx->thread_id)
                break;
        }
        else if (ip->protocol == IPPROTO_ICMP)
            break;
        
        prev = current;
        current = current->next;
    }

    if (!current)
    {
        ft_mutex(&g_packet_queue.mutex, UNLOCK);
        return 0;
    }

    if (prev)
        prev->next = current->next;
    else
        g_packet_queue.head = current->next;

    if (current == g_packet_queue.tail)
        g_packet_queue.tail = prev;

    *packet = current->packet;
    *header = &current->header;
    free(current);

    ft_mutex(&g_packet_queue.mutex, UNLOCK);
    return 1;

}

int process_tcp_response(t_thread_context *ctx, const u_char *packet, struct pcap_pkthdr *header, int port)
{
    (void)header;
    struct iphdr    *ip;
    struct tcphdr   *tcp;
    struct icmphdr  *icmp;
    int             link_offset;

    link_offset = offset_calculate(ctx);
    if (link_offset < 0)
        return (-1);

    ip = (struct iphdr *)(packet + link_offset);

    /* ================= TCP ================= */
    if (ip->protocol == IPPROTO_TCP)
    {
        tcp = (struct tcphdr *)((u_char *)ip + (ip->ihl * 4));

        /* Validar que la respuesta es para ESTE scan */
        if (ntohs(tcp->dest) != (40000 + ctx->thread_id))
            return 0;

        if (ntohs(tcp->source) != port)
            return 0;

        /* RST → CLOSED */
        if (tcp->rst)
        {
            if (ctx->conf->scan_type & SCAN_ACK)
                set_port_state(ctx->conf, port, PORT_UNFILTERED);       // RST + ACK scan
            else
                set_port_state(ctx->conf, port, PORT_CLOSED);           // RST + SYN scan
            return (0);
        }
        
        /* SYN + ACK → OPEN */
        if ((ctx->conf->scan_type & SCAN_SYN) && tcp->syn && tcp->ack)
        {
            set_port_state(ctx->conf, port, PORT_OPEN);
            return (0);
        }
    }

    /* ================= ICMP ================= */
    if (ip->protocol == IPPROTO_ICMP)
    {
        icmp = (struct icmphdr *)((u_char *)ip + (ip->ihl * 4));

        if (icmp->type == ICMP_DEST_UNREACH && (icmp->code == 1 || icmp->code == 2 || icmp->code == 3 || 
            icmp->code == 9 || icmp->code == 10 || icmp->code == 13))
        {
            // ICMP contiene el IP + TCP ORIGINAL
            struct iphdr  *orig_ip;
            struct tcphdr *orig_tcp;

            orig_ip = (struct iphdr *)((u_char *)icmp + sizeof(struct icmphdr));
            orig_tcp = (struct tcphdr *)((u_char *)orig_ip + orig_ip->ihl * 4);

            // Validar que era NUESTRO SYN
            if (ntohs(orig_tcp->dest) != port)
            return 0;

            if (ntohs(orig_tcp->source) != (40000 + ctx->thread_id))
                return 0;
            set_port_state(ctx->conf, port, PORT_FILTERED);
            return (0);
        }
    }

    return (0);  // Paquete no reconocido
}

/*  
    | Código | Significado                               |
    | ------ | ----------------------------------------- |
    | 1      | Host unreachable                          |
    | 2      | Protocol unreachable                      |
    | 3      | Port unreachable                          |
    | 9      | Network administratively prohibited       |
    | 10     | Host administratively prohibited          |
    | 13     | Communication administratively prohibited | 
*/

int offset_calculate(t_thread_context *ctx)
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

int init_scan(t_thread_context *ctx, int port)
{
    if (packet_build(ctx, port) < 0)
        return (-1);
    if (send_packet(ctx, port) < 0)
        return (-1);
    if (receive_response(ctx, port) < 0)
        return (-1);
    return (0);
}


int packet_build(t_thread_context *ctx, int port)
{
    struct iphdr            *ip;
    struct tcphdr           *tcp;
    struct udphdr           *udp;
    struct pseudo_header    psh;
    unsigned char           *packet;

    packet = ctx->sendbuffer;
    memset(packet, 0, MAX_PACKET_SIZE);

    ip = (struct iphdr *)packet;
    tcp = (struct tcphdr *)(packet + sizeof(struct iphdr));
    udp = (struct udphdr *)(packet + sizeof(struct iphdr));
    int source_port = 40000 + ctx->thread_id;

    // ================= UDP ======================

    if (ctx->conf->scan_type & SCAN_UDP)
    {
        ip->protocol = IPPROTO_UDP;
        ip->tot_len = htons(sizeof(struct iphdr) + sizeof(struct udphdr));

        udp->source = htons(source_port);
        udp->dest = htons(port);
        udp->len = htons(sizeof(struct udphdr));
        udp->check = 0;

        return (0);
    }

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

    tcp->source     = htons(source_port);
    tcp->dest       = htons(port);
    tcp->seq        = htonl(rand());
    tcp->ack_seq    = 0;
    tcp->doff       = sizeof(struct tcphdr) / 4;
    if (ctx->conf->scan_type & SCAN_SYN)
        tcp->syn        = 1;
    if (ctx->conf->scan_type & SCAN_FIN)
        tcp->fin = 1;
    if (ctx->conf->scan_type & SCAN_ACK)
        tcp->ack = 1;
    if (ctx->conf->scan_type & SCAN_XMAS)
        tcp->fin = tcp->psh = tcp->urg = 1;
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

    // ======= GUARDAR EL NÚMERO DE SECUENCIA ENVIADO =====
    ctx->last_seq_sent = ntohl(tcp->seq);

    return (0);
}

int send_packet(t_thread_context *ctx, int port)
{
    int sent_bytes;

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

int receive_response(t_thread_context *ctx, int port)
{
    struct pcap_pkthdr  *header;
    const u_char        *packet;
    struct timeval      start, now;
    double              time_elapsed;
    
    gettimeofday(&start, NULL);
    
    while (!g_stop)
    {
        gettimeofday(&now, NULL);
        time_elapsed = (double)(now.tv_sec - start.tv_sec) + (double)(now.tv_usec - start.tv_usec) / 1000000.0;
        
        if (time_elapsed >= 2.0)
        {
            if (ctx->conf->scan_type & SCAN_UDP)
                set_port_state(ctx->conf, port, PORT_OPEN_FILTERED);
            else if (ctx->conf->scan_type & (SCAN_NULL | SCAN_FIN | SCAN_XMAS))
                set_port_state(ctx->conf, port, PORT_OPEN_FILTERED);
            else if (ctx->conf->scan_type & SCAN_ACK)
                set_port_state(ctx->conf, port, PORT_FILTERED);
            else
                set_port_state(ctx->conf, port, PORT_FILTERED);     // SYN scan
            return (0);
        }
        
        if (get_packet_for_thread(ctx, &packet, &header))
        {
            process_tcp_response(ctx, packet, header, port);
            return 0;
        }
    }
    
    set_port_state(ctx->conf, port, PORT_FILTERED);
    return (0);
}

