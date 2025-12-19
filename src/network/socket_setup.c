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

    if (pcap_compile(conf->pcap_handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1 ||
        pcap_setfilter(conf->pcap_handle, &fp) == -1)
    {
        fprintf(stderr, "pcap filter error: %s\n", pcap_geterr(conf->pcap_handle));
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