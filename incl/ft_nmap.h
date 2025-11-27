#ifndef FT_NMAP_H
# define FT_NMAP_H

# include <string.h>
# include <stdlib.h>
# include <unistd.h>
# include <stdio.h>
# include <stdbool.h>
# include <errno.h>
# include <signal.h>
# include <pthread.h>
# include <sys/types.h>
# include <sys/socket.h>
# include <sys/time.h>
# include <sys/un.h>
# include <netdb.h>
# include <netinet/in.h>
# include <netinet/ip.h>
# include <netinet/ip_icmp.h>
# include <netinet/udp.h>
# include <pcap/pcap.h> 

extern volatile sig_atomic_t   g_stop;

typedef enum e_sacan_flags
{
    SCAN_SYN    = 1 << 0,
    SCAN_NULL   = 1 << 1,
    SCAN_FIN    = 1 << 2,
    SCAN_XMAS   = 1 << 3,
    SCAN_ACK    = 1 << 4,
    SCAN_UDP    = 1 << 5
}   t_scan_flags;

typedef enum e_port_state
{
    PORT_UNKNOWN,
    PORT_OPEN,
    PORT_CLOSED,
    PORT_FILTERED,
    PORT_UNFILTERED,
    PORT_OPEN_FILTERED
}   t_port_state;

typedef struct s_port
{
    int                     number;
    t_port_state            state;
}   t_port;

typedef struct s_config
{
    /* User Options */
    bool                    show_help;
    bool                    use_file;
    char                    *hostname;
    char                    *file_input;
    int                     argc;
    struct  in_addr         ip_address;

    /* Scan Options */
    int                     scan_type;

    /* Ports */
    int                     start_port;
    int                     end_port;
    int                     ports_number;
    t_port                  *ports;

    /* Threading */
    int                     speedup;
    pthread_t               *threads;

    /* Runtime */
    bool                    is_valid;
    int                     sockfd;
}   t_config;

//*** Init Functions ***/

int     main(int argc, char **argv);

//*** Parser ***/

void    init_struct(t_config *conf, int argc);
int     ft_parser_args(t_config *conf, char **argv);

//*** Show Printouts***/

void    show_help(void);

//** Signals **/

void    init_signal(void);
void    handler_singint(int signum);

#endif