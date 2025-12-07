#include "ft_nmap.h"

//    0800 0000 0001 0001 Paquete pequeño
//    0800 = type(8) + code(0)
//    0000 = checksum (temporalmente 0)
//    0001 = id(1)
//    0001 = sequence(1)

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

int     icmp_creation(t_thread_context *ctx, int port)
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
    size_t  sent_bytes = 0;

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
}

int socket_creation(t_config *conf)
{
    int             one = 1;
    struct timeval  timeout = {4, 0};
    
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
    if (setsockopt(conf->sockfd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) == -1)
    {
        printf("ft_nmap: setsockopt (IP_HDRINCL): %s\n", strerror(errno));
        close(conf->sockfd);
        return (-1);
    }

    return (0);
}