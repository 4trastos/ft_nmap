#ifndef FT_NMAP_H
# define FT_NMAP_H

# include <string.h>
# include <stdlib.h>
# include <unistd.h>
# include <stdio.h>
# include <stdbool.h>
# include <ctype.h>
# include <errno.h>
# include <signal.h>
# include <pthread.h>
# include <limits.h>
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

# define    MAX_PACKET_SIZE 1500

extern volatile sig_atomic_t   g_stop;

typedef pthread_mutex_t t_mutex;

typedef enum e_opcode
{
    LOCK,
    UNLOCK,
    INIT,
	DESTROY,
	CREATE,
	JOIN,
	DETACH
}   t_opcode;

typedef enum e_scan_flags
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
    int                     start_port;
    int                     end_port;
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
    int                     ttl;
    struct  in_addr         ip_address;

    /* Scan Options */
    int                     scan_type;

    /* Ports */
    int                     ports_tokens;
    int                     port_bitmap[65536];
    int                     total_ports;
    t_port                  *ports;

    /* Threading */
    long                    nprocs;
    int                     speedup;
    pthread_t               *threads;
    int                     next_port_idx; 

    /* Mutexes */
    t_mutex                 work_mutex;         // Para tomar puertos
    t_mutex                 print_mutex;        // Para imprimir
    t_mutex                 send_mutex;         // Para sendto() en raw socket
    t_mutex                 recv_mutex;         // Para recvfrom() en raw socket

    /* Runtime */
    bool                    is_valid;
    int                     sockfd;
}   t_config;

typedef struct s_thread_context
{
    int                 thread_id;
    int                 *next_port_idx;     // Índice global del puerto
    t_mutex             *work_mutex;        // Proteger next_port_idx
    t_mutex             *print_mutex;       // Imprimir limpio

    /* Socket RAW compartido */
    t_mutex             *send_mutex;        // Proteger sendto()
    t_mutex             *recv_mutex;        // Proteger recvfrom()

    /* Buffers propios por hilo */
    unsigned char       sendbuffer[MAX_PACKET_SIZE];
    unsigned char       recvbuffer[MAX_PACKET_SIZE];

    /* Destino */
    struct sockaddr_in  target_addr;

    t_config           *conf;
}   t_thread_context;

//*** Init Functions ***/

int     main(int argc, char **argv);
void    cleanup(t_config *conf);

//*** Parser ***/

void    init_struct(t_config *conf, int argc);
int     ft_parser_args(t_config *conf, char **argv);
int     parse_ip(t_config *conf, char **argv, int i);
int     parse_ports(t_config *conf, char **argv, int i);
int     port_validator(t_config *conf, char **token);
int     validate_range(const char *token, int *start, int *end);
int     parse_speedup(t_config *conf, char **argv, int i);
int     parse_scantypes(t_config *conf, char **argv, int i);
char    **split_scan(char *str, char c);

/*** Socket & DNS ***/

int     dns_resolution(t_config *conf);
int     socket_creation(t_config *conf);

//*** Show Printouts***/

void    show_help(t_config *conf);

//** Signals **/

void    init_signal(void);
void    handler_singint(int signum);

/*** Utils Functions ***/

char    **split_tokens(char *str, t_config *conf);
int     count_tokens(char *str);
char    *ft_strndup(char *str, int num);
void    double_free(char **ports);
int     find_dash(char *str);
char	*ft_substr(char *str, int start, int len);
int     ft_strlen(char *str);
int     ft_atoi_dav(char *str, int *limit);

/*** Threads ***/

void     threads_creation(t_config *conf, t_thread_context *ctx_array);
void	*thread_routine(void *data);
void    ft_mutex(t_mutex *mutex, t_opcode opcode);
void    ft_threads(t_thread_context *thread, void *(*foo)(void *), void *data, t_opcode opcode);

/*** Scan Ports ***/

int    scan_port(t_thread_context *ctx, int port);

#endif