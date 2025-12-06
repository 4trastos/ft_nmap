#include "ft_nmap.h"

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
    struct iphdr        *ip;
    struct tcphdr       *tcp;
    struct pseudo_header psh;
    unsigned char       *packet;

    packet = ctx->sendbuffer;
    memset(packet, 0, MAX_PACKET_SIZE);

    ip = (struct iphdr *)packet;
    tcp = (struct tcphdr *)(packet + sizeof(struct iphdr));

    // ================= IP HEADER =================

    ip->ihl = 5;
    ip->version = 4;
    ip->tos = 0;
    ip->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
    ip->id = htons(rand() % 65535);
    ip->frag_off = 0;
    ip->ttl = ctx->conf->ttl;
    ip->protocol = IPPROTO_TCP;
    ip->check = 0;
    ip->saddr = inet_addr("192.168.1.100");   // luego lo automatizamos
    ip->daddr = ctx->conf->ip_address.s_addr;

    ip->check = calculate_checksum(ip, sizeof(struct iphdr));

    // ================= TCP HEADER =================

    tcp->source = htons(40000 + ctx->thread_id);
    tcp->dest   = htons(port);
    tcp->seq    = htonl(rand());
    tcp->ack_seq = 0;
    tcp->doff   = 5;

    tcp->syn = 1;
    tcp->window = htons(1024);
    tcp->check  = 0;
    tcp->urg_ptr = 0;

    // ================= TCP CHECKSUM =================

    psh.src_addr = ip->saddr;
    psh.dst_addr = ip->daddr;
    psh.zero = 0;
    psh.protocol = IPPROTO_TCP;
    psh.tcp_length = htons(sizeof(struct tcphdr));

    unsigned char pseudo_packet[sizeof(struct pseudo_header) + sizeof(struct tcphdr)];
    memcpy(pseudo_packet, &psh, sizeof(struct pseudo_header));
    memcpy(pseudo_packet + sizeof(struct pseudo_header), tcp, sizeof(struct tcphdr));

    tcp->check = calculate_checksum(pseudo_packet,
        sizeof(struct pseudo_header) + sizeof(struct tcphdr));

    return (0);
}

int send_syn_packet(t_thread_context *ctx, int port)
{
    int sent_bytes;

    memset(&ctx->target_addr, 0, sizeof(ctx->target_addr));
    ctx->target_addr.sin_family = AF_INET;
    ctx->target_addr.sin_port = htons(port);
    ctx->target_addr.sin_addr = ctx->conf->ip_address;

    ft_mutex(ctx->send_mutex, LOCK);

    sent_bytes = sendto(ctx->conf->sockfd, ctx->sendbuffer,
        sizeof(struct iphdr) + sizeof(struct tcphdr), 0, (struct sockaddr *)&ctx->target_addr, sizeof(ctx->target_addr));

    ft_mutex(ctx->send_mutex, UNLOCK);

    if (sent_bytes < 0)
    {
        printf("ft_nmap: sendto SYN ( %s )\n", strerror(errno));
        return (-1);
    }

    return (0);
}
