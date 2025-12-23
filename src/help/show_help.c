#include "ft_nmap.h"

void    show_help(t_config *conf, t_thread_context *threads)
{
    cleanup(conf, threads);
    
    printf("ft_nmap - Help\nUsage:\n");
    printf("  ft_nmap [OPTIONS] --ip <address>\n");
    printf("\nOptions:\n");
    printf(" --help                     Show this help message and exit\n");
    printf(" --ip <address>             Target IPv4 address or hostname (FQDN allowed)\n");
    printf(" --ports <range/list>       Ports to scan (max 1024 total):\n");
    printf("                               - Examples: 1-10, 80, 22,80,443, 1,5-15\n");
    printf("                               - Default: 1-1024\n");
    printf(" --scan <types>             Scan types: SYN, NULL, FIN, XMAS, ACK, UDP\n");
    printf("                               - Example: --scan SYN,FIN,XMAS\n");
    printf("                               - Default: all scans\n");
    printf(" --speedup <n>              Number of threads (0 to 250)\n");
    printf("                               0 = sequential scan (no threads)\n");
    printf("                               Default: 0\n");
    return; 
}

void        show_configuration(t_config *conf)
{
    unsigned char   *bytes = 0;
    char            scan_str[256] = {0};
    int             first = 1;

    bytes = (unsigned char *)&conf->ip_address;
    printf("\nScan Configurations\n");
    printf("Target IP-Address : %d.%d.%d.%d \n", bytes[0], bytes[1], bytes[2], bytes[3]);
    printf("No of Ports to scan : %d\n", conf->total_ports);
    if (conf->scan_type & SCAN_SYN)
    {
        if (!first) strcat(scan_str, ", ");
        strcat(scan_str, "SYN");
        first = 0;
    }
    if (conf->scan_type & SCAN_NULL)
    {
        if (!first) strcat(scan_str, ", ");
        strcat(scan_str, "NULL");
        first = 0;
    }
    if (conf->scan_type & SCAN_FIN)
    {
        if (!first) strcat(scan_str, ", ");
        strcat(scan_str, "FIN");
        first = 0;
    }
    if (conf->scan_type & SCAN_XMAS)
    {
        if (!first) strcat(scan_str, ", ");
        strcat(scan_str, "XMAS");
        first = 0;
    }
    if (conf->scan_type & SCAN_ACK)
    {
        if (!first) strcat(scan_str, ", ");
        strcat(scan_str, "ACK");
        first = 0;
    }
    if (conf->scan_type & SCAN_UDP)
    {
        if (!first) strcat(scan_str, ", ");
        strcat(scan_str, "UDP");
        first = 0;
    }
    if (scan_str[0] == '\0')
        strcpy(scan_str, "NONE");
    
    printf("Scans to be performed : %s\n", scan_str);
    printf("No of threads : %d\n", conf->speedup);
    printf("Scanning..\n\n");
}

char    *show_scantype(t_config *conf)
{
    char            scan_str[64];
    int             first = 1;
    char            *aux = NULL;

    memset(scan_str, 0, sizeof(scan_str));

    if (conf->scan_type & SCAN_SYN)
    {
        if (!first) strcat(scan_str, ", ");
        strcat(scan_str, "SYN");
        first = 0;
    }
    if (conf->scan_type & SCAN_NULL)
    {
        if (!first) strcat(scan_str, ", ");
        strcat(scan_str, "NULL");
        first = 0;
    }
    if (conf->scan_type & SCAN_FIN)
    {
        if (!first) strcat(scan_str, ", ");
        strcat(scan_str, "FIN");
        first = 0;
    }
    if (conf->scan_type & SCAN_XMAS)
    {
        if (!first) strcat(scan_str, ", ");
        strcat(scan_str, "XMAS");
        first = 0;
    }
    if (conf->scan_type & SCAN_ACK)
    {
        if (!first) strcat(scan_str, ", ");
        strcat(scan_str, "ACK");
        first = 0;
    }
    if (conf->scan_type & SCAN_UDP)
    {
        if (!first) strcat(scan_str, ", ");
        strcat(scan_str, "UDP");
        first = 0;
    }
    if (scan_str[0] == '\0')
        strcpy(scan_str, "NONE");
    aux = scan_str;
    return (aux);
}