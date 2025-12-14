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
}

int socket_creation(t_config *conf)
{
    int                 one = 1;
    int                 timeout_ms = 1000;
    char                errorbuf[PCAP_ERRBUF_SIZE];
    char                filter_exp[256];
    struct bpf_program  fp;
    char                ip_str[INET_ADDRSTRLEN];
    struct in_addr      target_ip = conf->ip_address;
    const char          *dev = "any";  // Siempre usar "any"
    
    /* Socket para ENVIAR paquetes IP completos */
    conf->sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
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
    
    if (setsockopt(conf->sockfd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) == -1)
    {
        printf("ft_nmap: setsockopt (IP_HDRINCL): %s\n", strerror(errno));
        close(conf->sockfd);
        return (-1);
    }

    /* ========== PCAP PARA RECIBIR ========== */
    
    //printf("[DEBUG] Using network device: %s\n", dev);
    
    // Abrir dispositivo para captura
    conf->pcap_handle = pcap_open_live(dev, BUFSIZ, 1, timeout_ms, errorbuf);
    if (conf->pcap_handle == NULL)
    {
        //printf("ft_nmap: pcap_open_live error: ( %s )\n", errorbuf);
        close(conf->sockfd);
        return (-1);
    }

    conf->pcap_datalink = pcap_datalink(conf->pcap_handle);

    // Convertir IP a string para el filtro
    inet_ntop(AF_INET, &target_ip, ip_str, INET_ADDRSTRLEN);

    // Construir el filtro BPF - VERIFICAR FORMATO
    snprintf(filter_exp, sizeof(filter_exp), "(ip proto 6 or ip proto 1) and src host %s", ip_str);
    
    //printf("[DEBUG] PCAP filter: %s\n", filter_exp);
    //printf("[DEBUG] Target IP: %s (hex: 0x%08x)\n", ip_str, (unsigned int)target_ip.s_addr);

    // Compilar filtro
    if (pcap_compile(conf->pcap_handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1)
    {
        fprintf(stderr, "ft_nmap: pcap_compile error: %s\n", pcap_geterr(conf->pcap_handle));
        fprintf(stderr, "Filter expression was: %s\n", filter_exp);
        pcap_close(conf->pcap_handle);
        close(conf->sockfd);
        return (-1);
    }

    // Aplicar filtro
    if (pcap_setfilter(conf->pcap_handle, &fp) == -1)
    {
        fprintf(stderr, "ft_nmap: pcap_setfilter error: %s\n", pcap_geterr(conf->pcap_handle));
        pcap_freecode(&fp);
        pcap_close(conf->pcap_handle);
        close(conf->sockfd);
        return (-1);
    }

    pcap_freecode(&fp);

    // ***** Configurar como NO BLOQUEANTE *****
    if (pcap_setnonblock(conf->pcap_handle, 1, errorbuf) == -1)
    {
        printf("[WARNING] pcap_setnonblock failed: %s\n", errorbuf);
        // Continúa, pero será bloqueante
    }
    // else
    // {
    //     printf("[DEBUG] PCAP set to non-blocking mode\n");
    // }
    
    //printf("[DEBUG] Filter applied successfully\n");
    
    return (0);
}