#include "ft_nmap.h"

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

    tcp->source     = htons(40000 + ctx->thread_id);
    //tcp->source     = htons(40000 + ctx->probe_id);
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
    struct iphdr        *ip;
    struct tcphdr       *tcp;
    struct icmphdr      *icmp;
    const u_char        *packet;
    int                 returned;
    struct timeval      start, now;
    double              time_elapsed;
    int                 link_offset;

    link_offset = offset_calcualte(ctx);
    if (link_offset < 0)
        return (-1);
    
    // printf("\n[DEBUG] ===== Waiting for response on port %d =====\n", port);
    // printf("[DEBUG] Source port: %d\n", 40000 + ctx->thread_id);
    // printf("[DEBUG] Target IP: %s (0x%08x)\n", inet_ntoa(ctx->conf->ip_address), ctx->conf->ip_address.s_addr);
    
    gettimeofday(&start, NULL);
    
    while (!g_stop)
    {
        gettimeofday(&now, NULL);
        time_elapsed = (double)(now.tv_sec - start.tv_sec) + (double)(now.tv_usec - start.tv_usec) / 1000000.0;
        
        if (time_elapsed >= 1.5)  // Timeout de 1 segundo
        {
            //printf("[DEBUG] TIMEOUT for port %d\n", port);
            set_port_state(ctx->conf, port, PORT_FILTERED);
            return (0);
        }
        
        // Leer paquete
        
        ft_mutex(ctx->recv_mutex, LOCK);
        
        returned = pcap_next_ex(ctx->conf->pcap_handle, &header, &packet);
        
        ft_mutex(ctx->recv_mutex, UNLOCK);
        
        if (returned == 0)
        {
            // No hay paquete
            usleep(10000);  // 10ms
            continue;
        }
        else if (returned == -1)
        {
            //printf("[ERROR] pcap_next_ex: %s\n", pcap_geterr(ctx->conf->pcap_handle));
            break;
        }
        else if (returned == 1)
        {
            //printf("[DEBUG] Received packet: %d bytes\n", header->len);
            
            // Verificar tamaño mínimo
            if (header->len < link_offset + sizeof(struct iphdr))
            {
                printf("[DEBUG] Packet too small, skipping\n");
                continue;
            }
            
            // Saltar header de enlace
            ip = (struct iphdr *)(packet + link_offset);
            
            // Imprimir IP en formato legible
            // struct in_addr src_ip, dst_ip;
            // src_ip.s_addr = ip->saddr;
            // dst_ip.s_addr = ip->daddr;
            
            // printf("[DEBUG] From: %s, To: %s\n", inet_ntoa(src_ip), inet_ntoa(dst_ip));
            // printf("[DEBUG] Expected from: %s\n", inet_ntoa(ctx->conf->ip_address));
            
            // Verificar IP de origen
            if (ip->saddr != ctx->conf->ip_address.s_addr)
            {
                //printf("[DEBUG] Not from target! Skipping...\n");
                continue;
            }
            
            //printf("[DEBUG] ¡CORRECT SOURCE IP! Processing...\n");
            
            // Procesar TCP
            if (ip->protocol == IPPROTO_TCP)
            {
                if (header->len < link_offset + (ip->ihl * 4) + sizeof(struct tcphdr))
                {
                    //printf("[DEBUG] TCP packet too small\n");
                    continue;
                }
                
                tcp = (struct tcphdr *)((u_char *)ip + (ip->ihl * 4));
                
                //int src_port = ntohs(tcp->source);
                int dst_port = ntohs(tcp->dest);
                
                // printf("[DEBUG] TCP ports: %d -> %d\n", src_port, dst_port);
                // printf("[DEBUG] Expected dest port: %d\n", 40000 + ctx->thread_id);
                // printf("[DEBUG] Flags: SYN=%d, ACK=%d, RST=%d\n", tcp->syn, tcp->ack, tcp->rst);
                
                // Verificar que sea para nuestro puerto
                if (dst_port == (40000 + ctx->thread_id))
                {
                    if (tcp->syn && tcp->ack)
                    {
                        //printf("[DEBUG] ¡¡¡PORT %d OPEN!!!\n", port);
                        set_port_state(ctx->conf, port, PORT_OPEN);
                        return (0);
                    }
                    else if (tcp->rst)
                    {
                        //printf("[DEBUG] Port %d CLOSED\n", port);
                        set_port_state(ctx->conf, port, PORT_CLOSED);
                        return (0);
                    }
                }
            }
            // Procesar ICMP
            else if (ip->protocol == IPPROTO_ICMP)
            {
                if (header->len < link_offset + (ip->ihl * 4) + sizeof(struct icmphdr))
                {
                    //printf("[DEBUG] ICMP packet too small\n");
                    continue;
                }
                
                icmp = (struct icmphdr *)((u_char *)ip + (ip->ihl * 4));
                
                //printf("[DEBUG] ICMP type: %d, code: %d\n", icmp->type, icmp->code);
                
                if (icmp->type == ICMP_DEST_UNREACH)
                {
                    //printf("[DEBUG] Port %d FILTERED (ICMP)\n", port);
                    set_port_state(ctx->conf, port, PORT_FILTERED);
                    return (0);
                }
            }
        }
    }
    
    //printf("[DEBUG] No valid response for port %d\n", port);
    set_port_state(ctx->conf, port, PORT_FILTERED);
    return (0);
}