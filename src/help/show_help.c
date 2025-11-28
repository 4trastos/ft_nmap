#include "ft_nmap.h"

void    show_help(void)
{
    printf("ft_nmap - Help\nUsage:\n");
    printf("  ft_nmap [OPTIONS] --ip <address>\n");
    printf("\nOptions:\n");
    printf(" --help                     Show this help message and exit\n");
    printf(" --ip <address>             Target IPv4 address or hostname (FQDN allowed)\n");
    printf(" --ports <range/list>       Ports to scan:\n");
    printf("                               - Examples: 1-10, 80, 22,80,443, 1,5-15\n");
    printf("                               - Default: 1-1024\n");
    printf(" --scan <types>             Scan types: SYN, NULL, FIN, XMAS, ACK, UDP\n");
    printf("                               - Example: --scan SYN,FIN,XMAS\n");
    printf("                               - Default: all scans\n");
    printf(" --speedup <n>              Number of threads (0 to 250)\n");
    return; 
}