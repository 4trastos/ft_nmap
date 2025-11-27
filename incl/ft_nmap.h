#ifndef FT_NMAP_H
# define FT_NMAP_H

# include <pcap/pcap.h> 

# include <sys/types.h>
# include <sys/socket.h>
# include <sys/time.h>
# include <sys/un.h>
# include <netdb.h>
# include <netinet/in.h>
# include <netinet/ip.h>
# include <netinet/ip_icmp.h>
# include <netinet/udp.h>

# include <string.h>
# include <stdlib.h>
# include <unistd.h>
# include <stdio.h>
# include <stdbool.h>
# include <errno.h>
# include <signal.h>
# include <pthread.h>

struct config
{
    bool    show_help;
    bool    is_valid;
    char    **argv;
    int     argc;
};

//*** Init Functions ***/

int     main(int argc, char **argv);

//*** Parser ***/

void    init_struct(struct config *conf);
int     ft_parser(struct config *conf, char **argv);

//*** Show Printouts***/

void    show_help(void);

#endif