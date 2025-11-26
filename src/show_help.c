#include "ft_nmap.h"

void    show_help(void)
{
    printf("Help Screen\n");
    printf("ft_nmap [OPTIONS]\n");
    printf(" --help    Print this help screen\n");
    printf(" --ports   ports to scan (eg: 1-10 or 1,2,3 or 1,5-15)\n");
    printf(" --ip      ip addresses to scan in dot format\n");
    printf(" --file    File name containing IP addresses to scan,\n");
    printf(" --speedup [250 max] number of parallel threads to use\n");
    printf(" --scan    SYN/NULL/FIN/XMAS/ACK/UDP  \n");
    return; 
}