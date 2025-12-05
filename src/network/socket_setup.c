#include "ft_nmap.h"

uint16_t    calculate_checksum(void *packet, size_t len)
{
    uint32_t    sum;
    uint16_t    *aux = packet;

    for (size_t i = 0; i < len / 2; i++)
        sum += aux[i];
    if (len % 2)
        sum += ((uint8_t*)packet)[len - 1];
    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);
    return (~sum); 
}

int     icmp_creation(t_thread_context *ctx)
{
    struct ping_packet  *packet = NULL;

    if (packet->icmp_hdr.un.echo.sequence >= MAX_PACKET_SIZE)
        return (-1);
    packet = ctx->thread_id;
  
    packet->icmp_hdr.type = 8;
    packet->icmp_hdr.code = 0;
    packet->icmp_hdr.checksum = 0;
    packet->icmp_hdr.un.echo.id = getpid();
    packet->icmp_hdr.un.echo.sequence = ctx->thread_id;
    gettimeofday(&packet->timestamp, NULL);

    memset(packet->data, 0, ICMP_PAYLOAD_SIZE);
    packet->icmp_hdr.checksum = calculate_checksum(packet, sizeof(struct ping_packet));
    ctx->thread_id++;
    return (0);
}


int send_socket(t_thread_context *ctx, int port)
{
    struct ping_packet  *packet;
    size_t              sent_bytes;
    int                 sequencie;

    sequencie = ctx->thread_id - 1;
    packet = &ctx->packets[sequencie];

    memset(&ctx->target_addr,0, sizeof(ctx->target_addr));
    ctx->target_addr.sin_family = AF_INET;
    ctx->target_addr.sin_port = htons(port);
    ctx->target_addr.sin_addr = ctx->conf->ip_address;

    sent_bytes = sendto(ctx->conf->sockfd, packet, 1, ctx->conf->scan_type, (struct sockaddr *)&ctx->target_addr, sizeof(ctx->target_addr));
    if (sent_bytes < 0)
    {
        printf("ft_nmap: sendto ( %s )\n", strerror(errno));
        close(ctx->conf->sockfd);
        return (-1);
    }

    return (0);
}

int socket_creation(t_config *conf)
{
    struct  timeval timeout = {4, 0};
    
    conf->sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (conf->sockfd == -1)
    {
        if (errno == EPERM)
        {
            printf("ft_nmap: socket error ( %s ) - Must be root.\n", strerror(errno));
            return (-1);
        }
        printf("ft_namp: socket error: %s\n", strerror(errno));
        return (-1);
    }
    if (setsockopt(conf->sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == -1)
    {
        printf("ft_nmap: setsockopt (SO_RCVTIMEO): %s\n", strerror(errno));
        close(conf->sockfd);
        return (-1);
    }

    return (0);
}